/**
 * İki aşamalı lead discovery → qualify → teaser pipeline.
 *
 * Aşama 1 — Ön-eleme (preScreenPendingCandidates):
 *   Sadece ucuz kontroller (domain eleme + liveness). Tier3 → Tier2.
 *   Sık schedule edilebilir, yüksek batch limiti.
 *
 * Aşama 2 — Derin kalifikasyon (qualifyPendingCandidates):
 *   Tam OSINT zinciri. Yalnızca Tier2 domainlere uygulanır. Tier2 → Tier1/Tier2.
 */
import { db } from "@workspace/db";
import { leadCandidatesTable, domainScansTable, customerTechStackTable } from "@workspace/db";
import { eq, and, asc, desc, sql, inArray } from "drizzle-orm";
import { logger } from "../lib/logger";
import { scanCRTSH } from "./crtshScanner";
import { scanShodanFree, SHODAN_FREE_QUERIES } from "./shodanDiscovery";
import * as apolloService from "./apolloService";
import * as hunterService from "./hunterService";
import { whoisLookup } from "./whoisService";
import { scrapeContactEmail } from "./webContactScraper";
import { generateLeadTeaserEmail } from "./leadTeaserEmail";
import { shouldExcludeFromPipeline, computeCVEBreakdown } from "./leadScoringService";
import { checkLiveness } from "./leadDiscovery/webContentEnrichment";

function sleep(ms: number): Promise<void> {
  return new Promise((res) => setTimeout(res, ms));
}

function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((res) => setTimeout(() => res(fallback), ms)),
  ]);
}

function getSalesSignal(vendorName: string): string | null {
  const n = vendorName.toLowerCase();
  if (n.includes("cloudflare")) return "cdn_user";
  if (n.includes("wordpress")) return "cms_wordpress";
  if (n.includes("fortinet") || n.includes("fortigate")) return "fortinet_customer";
  if (n.includes("microsoft") || n.includes("office 365") || n.includes("exchange")) return "microsoft_shop";
  return null;
}

function getISOWeek(date: Date): number {
  const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  return Math.ceil((((d.valueOf() - yearStart.valueOf()) / 86400000) + 1) / 7);
}

function isConnErr(e: unknown): boolean {
  const msg = e instanceof Error ? e.message : String(e);
  return msg.includes("Connection terminated") || msg.includes("ECONNRESET") || msg.includes("connection timeout");
}

async function retryConnErr<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (!isConnErr(e)) throw e;
    await sleep(500);
    return fn();
  }
}

async function runDomainScanInternal(domain: string): Promise<{
  id: number;
  overallScore: number;
  findings: Array<{ severity: string; title: string }>;
  cveSummary: Array<{ cvssScore: number; cveId?: string }>;
} | null> {
  try {
    const { performDomainScan } = await import("../routes/domain-scan/index");
    const result = await performDomainScan(domain);
    if (!result) return null;
    return {
      id: result.id ?? 0,
      overallScore: result.overallScore ?? 0,
      findings: result.findings ?? [],
      cveSummary: (result.cveSummary as Array<{ cvssScore: number; cveId?: string }>) ?? [],
    };
  } catch (err) {
    logger.warn({ err, domain }, "Discovery pipeline: direct domain scan failed");
    return null;
  }
}

export interface PipelineConfig {
  useCrtsh?: boolean;
  useShodan?: boolean;
  crtshQueries?: string[];
  shodanQueryIndexes?: number[];
  autoQualify?: boolean;
  maxDomains?: number;
  qualifyLimit?: number;
}

export async function runFullDiscoveryAndQualify(config: PipelineConfig = {}): Promise<void> {
  const {
    useCrtsh = true,
    useShodan = true,
    crtshQueries = ["%.com.tr", "%.net.tr"],
    shodanQueryIndexes = [0, 2, 4],
    autoQualify = true,
    maxDomains = 200,
    qualifyLimit = 20,
  } = config;

  logger.info("=== Lead Discovery Pipeline Başladı ===");

  if (useCrtsh) {
    for (const query of crtshQueries) {
      logger.info({ query }, "crt.sh taraması başlıyor");
      try {
        await scanCRTSH(query, { daysBack: 30, minCorporateScore: 60, limit: Math.floor(maxDomains / crtshQueries.length) });
      } catch (e) {
        logger.error({ query, err: String(e) }, "crt.sh taraması başarısız");
      }
      await sleep(2000);
    }
  }

  if (useShodan && process.env["SHODAN_API_KEY"]) {
    for (const idx of shodanQueryIndexes) {
      logger.info({ idx, label: SHODAN_FREE_QUERIES[idx]?.label }, "Shodan taraması başlıyor");
      try {
        await scanShodanFree(idx, 100);
      } catch (e) {
        logger.error({ idx, err: String(e) }, "Shodan taraması başarısız");
      }
      await sleep(3000);
    }
  }

  if (!autoQualify) {
    logger.info("Kalifikasyon atlandı (autoQualify=false)");
    return;
  }

  await qualifyPendingCandidates(qualifyLimit);
  logger.info("=== Pipeline Tamamlandı ===");
}

// ─── FAZ 1: Ön-eleme (Tier 3 → Tier 2) ──────────────────────────────────────

/**
 * Sadece ucuz kontroller: domain eleme + liveness check.
 * Tier3 domainleri hızlıca eleme veya Tier2'ye terfi ettirir.
 * Tam OSINT zinciri çalıştırmaz.
 */
export async function preScreenPendingCandidates(limit: number = 500): Promise<{ processed: number; promoted: number; eliminated: number }> {
  // Atomik claim: scan_status'u 'prescreening' yaparak eş zamanlı instance'ların aynı adayı seçmesini engelle.
  // FOR UPDATE SKIP LOCKED → çakışan satırlar atlanır, her instance kendi batch'ini alır.
  const claimResult = await db.execute<{
    id: number;
    domain: string;
    source_data: unknown;
    has_fortigate: boolean;
  }>(sql`
    UPDATE lead_candidates
    SET scan_status = 'prescreening', updated_at = now()
    WHERE id IN (
      SELECT id FROM lead_candidates
      WHERE scan_status = 'pending' AND tier = 'tier3'
      ORDER BY has_fortigate DESC,
               (source_data->>'corporateScore')::int DESC NULLS LAST,
               created_at ASC
      LIMIT ${limit}
      FOR UPDATE SKIP LOCKED
    )
    RETURNING id, domain, source_data, has_fortigate
  `);
  const pending = claimResult.rows as Array<{ id: number; domain: string; source_data: unknown; has_fortigate: boolean }>;

  logger.info({ count: pending.length }, "Ön-eleme başlıyor (Tier3 → Tier2)");

  const MAX_RUNTIME_MS = 8 * 60 * 1000;
  const batchStart = Date.now();
  let processedCount = 0;
  let promotedCount = 0;
  let eliminatedCount = 0;
  const processedIds = new Set<number>();

  for (const candidate of pending) {
    if (Date.now() - batchStart > MAX_RUNTIME_MS) {
      logger.warn({ processed: processedCount, promoted: promotedCount }, "Ön-eleme: max süre (8 dk) aşıldı, batch sonlandırılıyor");
      break;
    }

    try {
      // source_data: raw SQL snake_case döndürür
      const sourceOrg = (candidate.source_data as Record<string, unknown> | null)?.["org"] as string | null ?? null;
      const exclusion = shouldExcludeFromPipeline(candidate.domain, sourceOrg);
      if (exclusion.exclude) {
        logger.info({ domain: candidate.domain, reason: exclusion.reason }, "Ön-eleme: domain eleme listesinde, atlanıyor");
        await db.update(leadCandidatesTable).set({
          scanStatus: "failed",
          updatedAt: new Date(),
        }).where(eq(leadCandidatesTable.id, candidate.id));
        processedIds.add(candidate.id);
        processedCount++;
        eliminatedCount++;
        await sleep(100);
        continue;
      }

      const liveness = await checkLiveness(candidate.domain);
      if (!liveness.isAlive) {
        logger.info(
          { domain: candidate.domain, httpStatus: liveness.httpStatus },
          "Ön-eleme: site erişilemiyor, elendi",
        );
        await db.update(leadCandidatesTable).set({
          scanStatus: "failed",
          isAlive: false,
          httpStatus: liveness.httpStatus,
          responseTimeMs: liveness.responseTimeMs,
          updatedAt: new Date(),
        }).where(eq(leadCandidatesTable.id, candidate.id));
        processedIds.add(candidate.id);
        processedCount++;
        eliminatedCount++;
        await sleep(100);
        continue;
      }

      await db.update(leadCandidatesTable).set({
        scanStatus: "pending",
        isAlive: true,
        httpStatus: liveness.httpStatus,
        responseTimeMs: liveness.responseTimeMs,
        tier: "tier2",
        updatedAt: new Date(),
      }).where(eq(leadCandidatesTable.id, candidate.id));

      processedIds.add(candidate.id);
      processedCount++;
      promotedCount++;
    } catch (e) {
      logger.warn({ domain: candidate.domain, err: String(e) }, "Ön-eleme hatası");
      // Hata durumunda da işlenmiş sayılır — 'pending'e bırakılmaz, bir sonraki batch'te tekrar alınmaz
      processedIds.add(candidate.id);
      processedCount++;
    }

    await sleep(200);
  }

  // MAX_RUNTIME nedeniyle işlenemeyen claimed ('prescreening') adayları 'pending'e döndür
  const unprocessedIds = pending.filter((c) => !processedIds.has(c.id)).map((c) => c.id);
  if (unprocessedIds.length > 0) {
    await db.update(leadCandidatesTable)
      .set({ scanStatus: "pending", updatedAt: new Date() })
      .where(inArray(leadCandidatesTable.id, unprocessedIds));
    logger.info({ count: unprocessedIds.length }, "Ön-eleme: işlenemeyen adaylar 'pending'e döndürüldü");
  }

  logger.info({ processed: processedCount, promoted: promotedCount, eliminated: eliminatedCount }, "Ön-eleme batch tamamlandı");
  return { processed: processedCount, promoted: promotedCount, eliminated: eliminatedCount };
}

// ─── FAZ 2: Derin kalifikasyon (Tier 2 → Tier 1 / reject) ───────────────────

// Aynı anda yalnızca bir kalifikasyon run'ı çalışsın.
// Cron her 15 dk'da tetiklenir ama her run ~20-50 dk sürebilir;
// üst üste gelen run'lar DB bağlantı havuzunu tüketiyor.
let isQualifying = false;
let isQualifyingSetAt = 0;

/**
 * Tam OSINT zinciri — yalnızca Tier2 domainlere uygulanır.
 * Geçen domainler Tier1'e terfi eder; geçemeyenler Tier2'de kalır (scanned+rejected).
 */
export async function qualifyPendingCandidates(limit: number = 200): Promise<{ processed: number; qualified: number }> {
  const LOCK_TIMEOUT_MS = 15 * 60 * 1000;
  if (isQualifying) {
    if (Date.now() - isQualifyingSetAt > LOCK_TIMEOUT_MS) {
      logger.warn("isQualifying kilidi 15 dk timeout — zorla temizleniyor");
      isQualifying = false;
    } else {
      logger.warn("Kalifikasyon zaten çalışıyor, bu tetikleyici atlanıyor");
      return { processed: 0, qualified: 0 };
    }
  }
  isQualifying = true;
  isQualifyingSetAt = Date.now();
  try {
  const pending = await db.select().from(leadCandidatesTable)
    .where(and(
      eq(leadCandidatesTable.scanStatus, "pending"),
      eq(leadCandidatesTable.tier, "tier2"),
    ))
    .orderBy(
      desc(leadCandidatesTable.hasFortigate),
      desc(sql`(source_data->>'corporateScore')::int`),
      asc(leadCandidatesTable.createdAt),
    )
    .limit(limit);

  // Concurrency: her batch'te kaç domain paralel taransın.
  // isRunning kilidi sayesinde üst üste run yoktur; pool max=25 ile concurrency=5
  // güvenli (5 scan × ~3 DB yazımı = 15 connection, havuz limitinin altında).
  const CONCURRENCY = 5;
  logger.info({ count: pending.length, concurrency: CONCURRENCY }, "Derin kalifikasyon başlıyor (Tier2)");

  const MAX_RUNTIME_MS = 13 * 60 * 1000;
  const SCAN_TIMEOUT_MS = 20_000;
  const batchStart = Date.now();
  let processedCount = 0;
  let qualifiedCount = 0;

  const disableApolloHunter = process.env["DISABLE_APOLLO_HUNTER"] === "true";

  // Tek bir adayı işler; döndürdüğü sayıları batch toplar
  async function processOne(candidate: (typeof pending)[number]): Promise<{ processed: number; qualified: number }> {
    try {
      // ── Liveness gate: tier2'ye doğrudan eklenen domain'ler preScreen'den geçmez.
      // Gerçek timeout/bağlantı hatası (httpStatus=0) → kalifikasyona sokmadan fail et.
      // 4xx yanıtları (415, 403, 404…) sunucunun canlı olduğunu gösterir — geçer.
      // 18s outer timeout: checkLiveness 2 URL dener, her biri 8s AbortController'a sahip.
      // Önceki 9s hatalıydı: HTTPS 8s zaman aşımına girince HTTP fallback için yalnızca
      // 1s kalıyordu → canlı domainler yanlışlıkla "ölü" işaretleniyordu.
      const liveness = await withTimeout(checkLiveness(candidate.domain), 18_000, { httpStatus: 0, isAlive: false, responseTimeMs: 0 });
      if (!liveness.isAlive && liveness.httpStatus === 0) {
        logger.info({ domain: candidate.domain }, "Kalifikasyon: domain gerçekten erişilemiyor (http_status=0), eleniyor");
        await retryConnErr(() => db.update(leadCandidatesTable).set({
          scanStatus: "failed",
          isAlive: false,
          httpStatus: 0,
          updatedAt: new Date(),
        }).where(eq(leadCandidatesTable.id, candidate.id)));
        return { processed: 1, qualified: 0 };
      }

      await retryConnErr(() => db.update(leadCandidatesTable).set({
        scanStatus: "scanning",
        isAlive: liveness.isAlive,
        httpStatus: liveness.httpStatus,
        responseTimeMs: liveness.responseTimeMs,
        updatedAt: new Date(),
      }).where(eq(leadCandidatesTable.id, candidate.id)));

      const scanResult = await withTimeout(runDomainScanInternal(candidate.domain), SCAN_TIMEOUT_MS, null);

      if (!scanResult) {
        await retryConnErr(() => db.update(leadCandidatesTable).set({
          scanStatus: "failed",
          updatedAt: new Date(),
        }).where(eq(leadCandidatesTable.id, candidate.id)));
        return { processed: 1, qualified: 0 };
      }

      const criticals = scanResult.findings.filter((f) => f.severity === "critical");
      const isQualified = scanResult.overallScore < 60;

      const cveBreakdown = computeCVEBreakdown(scanResult.cveSummary);
      const existingSourceData = (candidate.sourceData as Record<string, unknown> | null) ?? {};
      const updatedSourceData = { ...existingSourceData, cveBreakdown };

      await retryConnErr(() => db.update(leadCandidatesTable).set({
        scanStatus: "scanned",
        scanId: scanResult.id,
        riskScore: scanResult.overallScore,
        criticalFindings: criticals.length,
        findingHighlights: criticals.slice(0, 3).map((f) => f.title),
        isQualified,
        tier: isQualified ? "tier1" : "tier2",
        lastScannedAt: new Date(),
        scanDepth: "full",
        sourceData: updatedSourceData,
        updatedAt: new Date(),
      }).where(eq(leadCandidatesTable.id, candidate.id)));

      // Shadow IT + Shodan ağ cihazı → customer_tech_stack aktarımı
      try {
        const scanRow = await db
          .select({
            shadowItServices: domainScansTable.shadowItServices,
            shodanOpenPorts: domainScansTable.shodanOpenPorts,
          })
          .from(domainScansTable)
          .where(eq(domainScansTable.id, scanResult.id))
          .then((r) => r[0]);

        // ── Shadow IT servisleri ─────────────────────────────────────────────
        const services = (scanRow?.shadowItServices ?? []) as Array<{
          name: string; category: string; risk: string; description: string; version?: string;
        }>;

        if (services.length > 0) {
          await db.delete(customerTechStackTable).where(
            and(
              eq(customerTechStackTable.leadCandidateId, candidate.id),
              eq(customerTechStackTable.detectedVia, "shadow_it_scan"),
            ),
          );

          for (const svc of services) {
            await db.insert(customerTechStackTable).values({
              domain: candidate.domain,
              leadCandidateId: candidate.id,
              category: svc.category,
              vendor: svc.name,
              version: svc.version ?? null,
              securityRisk: (svc.risk as "critical" | "high" | "medium" | "low" | "none") ?? null,
              securityNote: svc.description,
              salesSignal: getSalesSignal(svc.name),
              detectedVia: "shadow_it_scan",
              confidence: 80,
            }).onConflictDoNothing();
          }

          logger.info({ domain: candidate.domain, count: services.length }, "Shadow IT → customer_tech_stack aktarıldı");
        }

        // ── Shodan: ağ cihazı / güvenlik duvarı tespiti ──────────────────────
        const shodanPorts = (scanRow?.shodanOpenPorts ?? []) as Array<{
          port: number; protocol: string; service: string; product: string; version: string;
        }>;

        if (shodanPorts.length > 0) {
          const networkProducts = [
            { pattern: /fortinet|fortigate|fortiweb/i, vendor: "fortinet",   product: "FortiGate",   salesSignal: "has_fortinet"      },
            { pattern: /palo alto|pan-os/i,            vendor: "paloalto",   product: "Palo Alto",   salesSignal: "has_network_device" },
            { pattern: /cisco/i,                       vendor: "cisco",      product: "Cisco",       salesSignal: "has_network_device" },
            { pattern: /juniper|junos/i,               vendor: "juniper",    product: "Juniper",     salesSignal: "has_network_device" },
            { pattern: /checkpoint|check point/i,      vendor: "checkpoint", product: "Check Point", salesSignal: "has_network_device" },
            { pattern: /sophos/i,                      vendor: "sophos",     product: "Sophos",      salesSignal: "has_network_device" },
            { pattern: /mikrotik|routeros/i,           vendor: "mikrotik",   product: "MikroTik",    salesSignal: "has_network_device" },
          ];

          const detectedDevices = new Map<string, { vendor: string; product: string; salesSignal: string; version: string }>();
          for (const port of shodanPorts) {
            const haystack = `${port.product} ${port.service}`.toLowerCase();
            for (const np of networkProducts) {
              if (np.pattern.test(haystack) && !detectedDevices.has(np.vendor)) {
                detectedDevices.set(np.vendor, { ...np, version: port.version ?? "" });
              }
            }
          }

          if (detectedDevices.size > 0) {
            await db.delete(customerTechStackTable).where(
              and(
                eq(customerTechStackTable.leadCandidateId, candidate.id),
                eq(customerTechStackTable.detectedVia, "shodan"),
                eq(customerTechStackTable.category, "firewall"),
              ),
            );

            for (const [, dev] of detectedDevices) {
              await db.insert(customerTechStackTable).values({
                domain: candidate.domain,
                leadCandidateId: candidate.id,
                category: "firewall",
                vendor: dev.vendor,
                product: dev.product,
                version: dev.version || null,
                salesSignal: dev.salesSignal,
                detectedVia: "shodan",
                confidence: 90,
              }).onConflictDoNothing();
            }

            logger.info({ domain: candidate.domain, devices: [...detectedDevices.keys()] }, "Shodan ağ cihazı → customer_tech_stack aktarıldı");
          }
        }
      } catch (e) {
        logger.warn({ domain: candidate.domain, err: String(e) }, "Shadow IT / Shodan tech_stack aktarımı başarısız");
      }

      if (!isQualified) {
        logger.info({ domain: candidate.domain, score: scanResult.overallScore }, "Kalifikasyon reddedildi");
        return { processed: 1, qualified: 0 };
      }

      // ── Qualified: iletişim bul (Apollo/Hunter → WHOIS → Web scraping) ──────
      if (!candidate.contactEmail) {
        try {
          let contactEmail: string | null = null;
          let contactName: string | null = null;
          let contactTitle: string | null = null;
          let contactSource = "unknown";

          if (!disableApolloHunter) {
            // 1. Apollo
            const apolloContacts = await apolloService.findDecisionMakers(candidate.domain);
            if (apolloContacts.length > 0) {
              const c = apolloContacts[0] as { email?: string; name?: string; title?: string };
              contactEmail = c.email ?? null;
              contactName = c.name ?? null;
              contactTitle = c.title ?? null;
              contactSource = "apollo";
            }

            // 2. Hunter fallback
            if (!contactEmail) {
              const hunterResult = await hunterService.domainSearch(candidate.domain);
              const top = hunterResult.emails[0] as { value?: string; first_name?: string; last_name?: string; position?: string } | undefined;
              if (top) {
                contactEmail = top.value ?? null;
                contactName = [top.first_name, top.last_name].filter(Boolean).join(" ") || null;
                contactTitle = top.position ?? null;
                contactSource = "hunter";
              }
            }
          } else {
            logger.info({ domain: candidate.domain }, "Apollo/Hunter devre dışı (DISABLE_APOLLO_HUNTER=true), WHOIS'e geçiliyor");
          }

          // 3. WHOIS
          if (!contactEmail) {
            const whoisEmail = await whoisLookup(candidate.domain);
            if (whoisEmail) {
              contactEmail = whoisEmail;
              contactSource = "whois";
            }
          }

          // 4. Web scraping (birincil yöntem TR için)
          if (!contactEmail) {
            const webContact = await scrapeContactEmail(candidate.domain);
            if (webContact) {
              contactEmail = webContact.email;
              contactSource = `web${webContact.sourcePath}`;
            }
          }

          if (contactEmail) {
            await db.update(leadCandidatesTable).set({
              contactEmail,
              contactName,
              contactTitle,
              contactSource,
              needsManualContact: false,
              updatedAt: new Date(),
            }).where(eq(leadCandidatesTable.id, candidate.id));
            logger.info({ domain: candidate.domain, source: contactSource }, "Kontak bulundu");
          } else {
            await db.update(leadCandidatesTable).set({
              needsManualContact: true,
              updatedAt: new Date(),
            }).where(eq(leadCandidatesTable.id, candidate.id));
            logger.info({ domain: candidate.domain }, "Kontak bulunamadı — manuel araştırma işaretlendi");
          }
        } catch (e) {
          logger.warn({ domain: candidate.domain, err: String(e) }, "İletişim bulma başarısız");
          await db.update(leadCandidatesTable).set({
            needsManualContact: true,
            updatedAt: new Date(),
          }).where(eq(leadCandidatesTable.id, candidate.id));
        }
      }

      // Teaser üret — fire-and-forget
      setImmediate(async () => {
        try {
          await generateLeadTeaserEmail(candidate.id, scanResult);
          logger.info({ domain: candidate.domain }, "Teaser email otomatik üretildi");
        } catch (e) {
          logger.warn({ err: String(e), domain: candidate.domain }, "Teaser email üretimi başarısız");
        }
      });

      logger.info({ domain: candidate.domain, criticals: criticals.length, score: scanResult.overallScore }, "Kalifikasyon geçti → Tier1");
      return { processed: 1, qualified: 1 };
    } catch (e) {
      logger.error({ domain: (candidate as { domain?: string }).domain, err: String(e) }, "Kalifikasyon hatası");
      // Catch içindeki DB update da başarısız olursa Promise.all'u çökertmemeli.
      try {
        await retryConnErr(() => db.update(leadCandidatesTable).set({
          scanStatus: "failed",
          updatedAt: new Date(),
        }).where(eq(leadCandidatesTable.id, candidate.id)));
      } catch (dbErr) {
        logger.warn({ domain: (candidate as { domain?: string }).domain, err: String(dbErr) }, "Kalifikasyon: failed güncelleme de başarısız, domain pending'de kalıyor");
      }
      return { processed: 1, qualified: 0 };
    }
  }

  // CONCURRENCY adet domain'i aynı anda işle
  for (let i = 0; i < pending.length; i += CONCURRENCY) {
    if (Date.now() - batchStart > MAX_RUNTIME_MS) {
      logger.warn({ processed: processedCount, qualified: qualifiedCount }, "Kalifikasyon: max süre (13 dk) aşıldı, batch sonlandırılıyor");
      break;
    }

    const chunk = pending.slice(i, i + CONCURRENCY);
    const results = await Promise.all(chunk.map((c) => processOne(c)));
    for (const r of results) {
      processedCount += r.processed;
      qualifiedCount += r.qualified;
    }

    // Rate limiter'lara nezaket: batch'ler arasında kısa duraklama
    if (i + CONCURRENCY < pending.length) await sleep(100);
  }

  logger.info({ processed: processedCount, qualified: qualifiedCount }, "Kalifikasyon batch tamamlandı");
  return { processed: processedCount, qualified: qualifiedCount };
  } finally {
    isQualifying = false;
  }
}

export { getISOWeek };
