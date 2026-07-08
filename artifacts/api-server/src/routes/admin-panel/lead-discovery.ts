import { Router } from "express";
import type { Request, Response } from "express";
import { randomUUID } from "crypto";
import { db } from "@workspace/db";
import {
  leadCandidatesTable,
  discoveryRunsTable,
  customerTechStackTable,
  ispPartnersTable,
  domainScansTable,
  isrCustomersTable,
  isrDealsTable,
  cveTrackerTable,
  cveDomainMatchesTable,
} from "@workspace/db";
import {
  eq, desc, sql, and, count, isNull, isNotNull, asc, ilike, or, inArray, gte,
} from "drizzle-orm";
import { requireAdmin } from "./middleware";
import { scanCRTSH } from "../../services/crtshScanner";
import { scanShodanFree, SHODAN_FREE_QUERIES } from "../../services/shodanDiscovery";
import { runFullDiscoveryAndQualify, qualifyPendingCandidates, preScreenPendingCandidates } from "../../services/discoveryPipeline";
import { generateLeadTeaserEmail } from "../../services/leadTeaserEmail";
import { whoisLookup } from "../../services/whoisService";
import { scrapeContactEmail } from "../../services/webContactScraper";
import { logger } from "../../lib/logger";
import { enrichLeadFromTrSources } from "../../services/leadDiscovery/trSourcesEnrichment";
import { enrichLeadFromWeb } from "../../services/leadDiscovery/webContentEnrichment";
import { sendMail } from "../../services/email";
import { buildTeaserEmailHtml, buildDealNotificationHtml } from "../../lib/email-templates/isrEmails";
import { getIsrEmail, getIsrBaseUrl } from "../../lib/isr/teamConfig";

function requireTenantId(req: Request, res: Response): number | null {
  const tid = (req.session as unknown as Record<string, unknown>)["tenantId"] as number | undefined;
  if (!tid) { res.status(403).json({ error: "Workspace seçilmedi", code: "NO_TENANT" }); return null; }
  return tid;
}

const router = Router();

// ─── ISP tabloları oluştur / migrate et (startup'ta çağrılır) ────────────────
export async function ensureIspTables() {
  await db.execute(sql`ALTER TABLE lead_candidates ADD COLUMN IF NOT EXISTS isp_organization TEXT`);
  await db.execute(sql`CREATE INDEX IF NOT EXISTS idx_lead_candidates_isp ON lead_candidates(isp_organization)`);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS isp_partners (
      id SERIAL PRIMARY KEY,
      organization_name_pattern TEXT NOT NULL,
      partner_name VARCHAR(255) NOT NULL,
      partner_contact VARCHAR(255),
      is_active_partnership BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`CREATE INDEX IF NOT EXISTS idx_isp_partners_pattern ON isp_partners(organization_name_pattern)`);
  await db.execute(sql`CREATE INDEX IF NOT EXISTS idx_isp_partners_name ON isp_partners(partner_name)`);

  // Seed yalnızca tablo boşsa
  const { rows } = await db.execute<{ c: string }>(sql`SELECT COUNT(*) AS c FROM isp_partners`);
  if (parseInt(rows[0]?.c ?? "0") === 0) {
    const seeds: [string, string][] = [
      ["%Turk Telekomunikasyon%", "Türk Telekom"],
      ["%TTNet%", "Türk Telekom"],
      ["%TT Teknoloji%", "Türk Telekom"],
      ["%Turk Telecom%", "Türk Telekom"],
      ["%Superonline Iletisim%", "Turkcell Superonline"],
      ["%Superonline%", "Turkcell Superonline"],
      ["%Turkcell Superonline%", "Turkcell Superonline"],
      ["%Vodafone Net%", "Vodafone"],
      ["%Vodafone Telekomunikasyon%", "Vodafone"],
      ["%Vodafone TR%", "Vodafone"],
      ["%TURKNET%", "TurkNet"],
      ["%Turknet Iletisim%", "TurkNet"],
      ["%Turk Net%", "TurkNet"],
      ["%Fibernet%", "Fibernet"],
      ["%Millenicom%", "Millenicom"],
      ["%Radore%", "Radore Hosting"],
      ["%Natro%", "Natro"],
      ["%Doruk%", "Doruk Net"],
      ["%Fatihnet%", "Fatihnet"],
      ["%Bursanet%", "Bursanet"],
      ["%Metronet%", "Metronet"],
      ["%Hetzner%", "Hetzner Online"],
      ["%OVH%", "OVH"],
      ["%DigitalOcean%", "DigitalOcean"],
      ["%Amazon%", "AWS"],
      ["%AMAZON%", "AWS"],
      ["%Microsoft Corporation%", "Azure"],
      ["%Google LLC%", "Google Cloud"],
      ["%Cloudflare%", "Cloudflare"],
      ["%Akamai%", "Akamai"],
    ];
    for (const [pattern, name] of seeds) {
      await db.execute(sql`INSERT INTO isp_partners(organization_name_pattern, partner_name) VALUES(${pattern}, ${name}) ON CONFLICT DO NOTHING`);
    }
  }

  // Backfill mevcut lead'ler
  await db.execute(sql`
    UPDATE lead_candidates
    SET isp_organization = source_data->>'org'
    WHERE isp_organization IS NULL AND source_data->>'org' IS NOT NULL AND source_data->>'org' <> ''
  `);
}

// ─── GET /api/admin-panel/lead-discovery/stats ───────────────────────────────
router.get("/admin-panel/lead-discovery/stats", requireAdmin, async (_req: Request, res: Response) => {
  res.set("Cache-Control", "no-store");
  const [total] = await db.select({ count: count() }).from(leadCandidatesTable);
  const [scanned] = await db.select({ count: count() }).from(leadCandidatesTable)
    .where(eq(leadCandidatesTable.scanStatus, "scanned"));
  const [qualified] = await db.select({ count: count() }).from(leadCandidatesTable)
    .where(eq(leadCandidatesTable.isQualified, true));
  const [withContact] = await db.select({ count: count() }).from(leadCandidatesTable)
    .where(and(eq(leadCandidatesTable.isQualified, true), isNotNull(leadCandidatesTable.contactEmail)));
  const [teaserReady] = await db.select({ count: count() }).from(leadCandidatesTable)
    .where(and(isNotNull(leadCandidatesTable.teaserSubject), isNull(leadCandidatesTable.teaserSentAt)));
  const [teaserSent] = await db.select({ count: count() }).from(leadCandidatesTable)
    .where(isNotNull(leadCandidatesTable.teaserSentAt));
  // pending = tier2 (nitelendirme bekleyen, stabil sayı) + tier3 (ön-eleme bekleyen)
  const [pendingTier2] = await db.select({ count: count() }).from(leadCandidatesTable)
    .where(and(eq(leadCandidatesTable.scanStatus, "pending"), eq(leadCandidatesTable.tier, "tier2")));
  const [pendingTier3] = await db.select({ count: count() }).from(leadCandidatesTable)
    .where(and(eq(leadCandidatesTable.scanStatus, "pending"), eq(leadCandidatesTable.tier, "tier3")));
  const [prescreening] = await db.select({ count: count() }).from(leadCandidatesTable)
    .where(eq(leadCandidatesTable.scanStatus, "prescreening"));
  const [scanning] = await db.select({ count: count() }).from(leadCandidatesTable)
    .where(eq(leadCandidatesTable.scanStatus, "scanning"));

  // Source breakdown
  const bySource = await db.select({
    source: leadCandidatesTable.source,
    count: count(),
  }).from(leadCandidatesTable).groupBy(leadCandidatesTable.source);

  res.json({
    total: total?.count ?? 0,
    pending: (pendingTier2?.count ?? 0) + (pendingTier3?.count ?? 0),
    pendingTier2: pendingTier2?.count ?? 0,
    pendingTier3: pendingTier3?.count ?? 0,
    prescreening: prescreening?.count ?? 0,
    scanning: scanning?.count ?? 0,
    scanned: scanned?.count ?? 0,
    qualified: qualified?.count ?? 0,
    withContact: withContact?.count ?? 0,
    teaserReady: teaserReady?.count ?? 0,
    teaserSent: teaserSent?.count ?? 0,
    bySource,
  });
});

// ─── GET /api/admin-panel/lead-discovery/certstream/status ──────────────────
// GitHub Actions Certstream bridge istatistikleri — discovery_runs tablosundan
router.get("/admin-panel/lead-discovery/certstream/status", requireAdmin, async (_req: Request, res: Response) => {
  res.set("Cache-Control", "no-store");
  // "ct_discovery" artık crt.sh scanner'ı tarafından kullanılıyor (certstream-bridge.yml → "certstream-bridge" kaynağına geçildi)
  // Bu listeye dahil edilmez; yalnızca gerçek certstream bridge ve BGP bridge kaynakları sayılır.
  const BRIDGE_SOURCES = ["certstream-bridge", "certstream", "bgptools-bridge", "bgp_tools", "bgptools"];

  const recentRuns = await db.select({
    id: discoveryRunsTable.id,
    source: discoveryRunsTable.source,
    status: discoveryRunsTable.status,
    totalFound: discoveryRunsTable.totalFound,
    totalAdded: discoveryRunsTable.totalAdded,
    startedAt: discoveryRunsTable.startedAt,
    completedAt: discoveryRunsTable.completedAt,
  }).from(discoveryRunsTable)
    .where(inArray(discoveryRunsTable.source, BRIDGE_SOURCES))
    .orderBy(desc(discoveryRunsTable.startedAt))
    .limit(20);

  const [ctTotal] = await db.select({ count: count() }).from(leadCandidatesTable)
    .where(inArray(leadCandidatesTable.source, BRIDGE_SOURCES));

  const lastRun = recentRuns[0] ?? null;
  const last24h = recentRuns.filter(r => r.startedAt && (Date.now() - new Date(r.startedAt).getTime()) < 86_400_000);
  const totalAdded24h = last24h.reduce((s, r) => s + r.totalAdded, 0);
  const totalFound24h = last24h.reduce((s, r) => s + r.totalFound, 0);
  const totalAddedAll = recentRuns.reduce((s, r) => s + r.totalAdded, 0);

  res.json({
    bridgeActive: lastRun != null && lastRun.startedAt != null &&
      (Date.now() - new Date(lastRun.startedAt).getTime()) < 2 * 60 * 60 * 1000,
    lastRunAt: lastRun?.startedAt ?? null,
    lastRunSource: lastRun?.source ?? null,
    lastRunAdded: lastRun?.totalAdded ?? 0,
    lastRunFound: lastRun?.totalFound ?? 0,
    totalLeads: ctTotal?.count ?? 0,
    totalAdded24h,
    totalFound24h,
    runs24h: last24h.length,
    recentRuns: recentRuns.slice(0, 10),
  });
});

// ─── POST /api/admin-panel/lead-discovery/certstream/dispatch ────────────────
router.post("/admin-panel/lead-discovery/certstream/dispatch", requireAdmin, async (_req: Request, res: Response) => {
  const pat = process.env["GITHUB_PAT"];
  if (!pat) { res.status(503).json({ error: "GITHUB_PAT eksik — dispatch yapılamıyor" }); return; }

  const replitDomains = (process.env["REPLIT_DOMAINS"] ?? "").split(",").map(d => d.trim()).filter(Boolean);
  const primaryDomain = replitDomains[0] ?? "cyberstep.io";
  const ingestUrl = `https://${primaryDomain}/api/internal/cert-ingest`;

  const { dispatchWorkflow, watchRunInBackground } = await import("../../services/githubActionsHelper");
  const repo = "serkangrdl-cyberstep/CyberStep";
  const workflowId = "certstream-bridge.yml";
  const dispatchedAt = new Date();
  const correlationId = randomUUID();

  const result = await dispatchWorkflow({
    pat,
    repo,
    workflowId,
    inputs: { ingest_url: ingestUrl, correlation_id: correlationId },
  });

  if (!result.dispatched) {
    logger.warn({ status: result.httpStatus }, "Certstream dispatch başarısız");
    res.status(502).json({ ok: false, error: `GitHub API ${result.httpStatus} döndürdü` });
    return;
  }

  logger.info({ trigger: "manual", correlationId }, "Certstream dispatch manual tetiklendi — run izleniyor");
  watchRunInBackground({ pat, repo, workflowId, dispatchedAt, correlationId, logContext: { trigger: "manual" } });

  res.json({ ok: true, message: "GitHub Actions dispatch tetiklendi — run sonucu sunucu loglarına yazılacak" });
});

// ─── GET /api/admin-panel/lead-discovery/runs ────────────────────────────────
router.get("/admin-panel/lead-discovery/runs", requireAdmin, async (req: Request, res: Response) => {
  const limit = parseInt(req.query["limit"] as string ?? "20");
  const runs = await db.select().from(discoveryRunsTable)
    .orderBy(desc(discoveryRunsTable.startedAt))
    .limit(limit);
  res.json(runs);
});

// ─── POST /api/admin-panel/lead-discovery/crtsh ──────────────────────────────
router.post("/admin-panel/lead-discovery/crtsh", requireAdmin, async (req: Request, res: Response) => {
  const { query = "%.com.tr", daysBack = 30, minCorporateScore = 10, limit = 300 } =
    req.body as { query?: string; daysBack?: number; minCorporateScore?: number; limit?: number };

  res.json({ message: "crt.sh taraması başlatıldı", query });

  setImmediate(async () => {
    try {
      const result = await scanCRTSH(query, { daysBack, minCorporateScore, limit });
      logger.info(result, "crt.sh taraması tamamlandı");
    } catch (e) {
      logger.error({ err: String(e) }, "crt.sh taraması başarısız");
    }
  });
});

// ─── GET /api/admin-panel/lead-discovery/shodan/queries ──────────────────────
router.get("/admin-panel/lead-discovery/shodan/queries", requireAdmin, (_req: Request, res: Response) => {
  res.json(SHODAN_FREE_QUERIES.map((q, i) => ({ index: i, ...q })));
});

// ─── POST /api/admin-panel/lead-discovery/shodan ─────────────────────────────
router.post("/admin-panel/lead-discovery/shodan", requireAdmin, async (req: Request, res: Response) => {
  const { queryIndex = 0, maxResults = 100 } =
    req.body as { queryIndex?: number; maxResults?: number };

  if (!process.env["SHODAN_API_KEY"]) {
    res.status(400).json({ error: "SHODAN_API_KEY bulunamadı. Replit Secrets'e ekleyin." });
    return;
  }

  const q = SHODAN_FREE_QUERIES[queryIndex];
  res.json({ message: "Shodan taraması başlatıldı", label: q?.label });

  setImmediate(async () => {
    try {
      const result = await scanShodanFree(queryIndex, maxResults);
      logger.info(result, "Shodan taraması tamamlandı");
    } catch (e) {
      logger.error({ err: String(e) }, "Shodan taraması başarısız");
    }
  });
});

// ─── POST /api/admin-panel/lead-discovery/ripe-dns ───────────────────────────
router.post("/admin-panel/lead-discovery/ripe-dns", requireAdmin, async (req: Request, res: Response) => {
  const { maxPrefixes = 60 } = (req.body ?? {}) as { maxPrefixes?: number };
  res.json({ message: "RIPE DNS keşfi başlatıldı", maxPrefixes });
  setImmediate(async () => {
    try {
      const { runRipeDiscovery } = await import("../../services/ripeDiscovery");
      const result = await runRipeDiscovery({ maxPrefixes });
      logger.info(result, "RIPE DNS keşfi tamamlandı");
    } catch (e) {
      logger.error({ err: String(e) }, "RIPE DNS keşfi başarısız");
    }
  });
});

// ─── POST /api/admin-panel/lead-discovery/full ───────────────────────────────
router.post("/admin-panel/lead-discovery/full", requireAdmin, async (req: Request, res: Response) => {
  const {
    useCrtsh = true,
    useShodan = true,
    autoQualify = true,
    maxDomains = 200,
    qualifyLimit = 20,
    crtshQueries,
    shodanQueryIndexes,
  } = req.body as {
    useCrtsh?: boolean;
    useShodan?: boolean;
    autoQualify?: boolean;
    maxDomains?: number;
    qualifyLimit?: number;
    crtshQueries?: string[];
    shodanQueryIndexes?: number[];
  };

  res.json({ message: "Tam pipeline başlatıldı. Bu işlem 2-3 saat sürebilir." });

  setImmediate(async () => {
    try {
      await runFullDiscoveryAndQualify({
        useCrtsh, useShodan, autoQualify, maxDomains, qualifyLimit,
        crtshQueries, shodanQueryIndexes,
      });
    } catch (e) {
      logger.error({ err: String(e) }, "Pipeline başarısız");
    }
  });
});

// ─── POST /api/admin-panel/lead-discovery/prescreen ─────────────────────────
router.post("/admin-panel/lead-discovery/prescreen", requireAdmin, async (req: Request, res: Response) => {
  const { limit = 500 } = (req.body ?? {}) as { limit?: number };
  res.json({ message: `${limit} aday ön-eleme başlatıldı.` });
  setImmediate(async () => {
    try {
      const result = await preScreenPendingCandidates(limit);
      logger.info({ result }, "Manuel ön-eleme tamamlandı");
    } catch (e) {
      logger.error({ err: String(e) }, "Ön-eleme başarısız");
    }
  });
});

// ─── POST /api/admin-panel/lead-discovery/qualify ────────────────────────────
router.post("/admin-panel/lead-discovery/qualify", requireAdmin, async (req: Request, res: Response) => {
  const { limit = 20 } = (req.body ?? {}) as { limit?: number };
  res.json({ message: `${limit} aday kalifikasyonu başlatıldı.` });
  setImmediate(async () => {
    try {
      await qualifyPendingCandidates(limit);
    } catch (e) {
      logger.error({ err: String(e) }, "Kalifikasyon başarısız");
    }
  });
});

// ─── POST /api/admin-panel/lead-discovery/reset-stale-qualified ───────────────
// 48 saatten önce qualify edilmiş leadleri (WAF/CDN kontrolü öncesi false pozitifler)
// pending+tier2+is_qualified=false olarak sıfırla; bir sonraki qualify batch'i onları tekrar değerlendirir.
router.post("/admin-panel/lead-discovery/reset-stale-qualified", requireAdmin, async (req: Request, res: Response) => {
  const { hoursAgo = 48 } = (req.body ?? {}) as { hoursAgo?: number };
  const cutoff = new Date(Date.now() - hoursAgo * 60 * 60 * 1000);

  const result = await db.execute(sql`
    UPDATE lead_candidates
    SET
      scan_status   = 'pending',
      tier          = 'tier2',
      is_qualified  = false,
      scan_id       = NULL,
      risk_score    = NULL,
      critical_findings = 0,
      finding_highlights = NULL,
      last_scanned_at = NULL,
      updated_at    = NOW()
    WHERE
      is_qualified = true
      AND scan_status = 'scanned'
      AND (last_scanned_at < ${cutoff} OR last_scanned_at IS NULL)
  `);

  const resetCount = result.rowCount ?? 0;
  req.log.info({ resetCount, hoursAgo }, "Eski qualified leadler yeniden kalifikasyona sokuldu");
  res.json({ reset: resetCount, message: `${resetCount} lead sıfırlandı — şimdi Kalifikasyonu Çalıştır butonuyla batch batch işleyin.` });
});

// ─── POST /api/admin-panel/lead-discovery/requalify-all-scanned ──────────────
// Hem qualified hem de non-qualified tüm "scanned" leadleri pending+tier2'ye döndürür.
// Yeni kalifikasyon mantığı (WAF skoru, DKIM güncellemesi vb.) tüm mevcut adaylara uygulanır.
router.post("/admin-panel/lead-discovery/requalify-all-scanned", requireAdmin, async (req: Request, res: Response) => {
  const result = await db.execute(sql`
    UPDATE lead_candidates
    SET
      scan_status       = 'pending',
      tier              = 'tier2',
      is_qualified      = false,
      scan_id           = NULL,
      risk_score        = NULL,
      critical_findings = 0,
      finding_highlights = NULL,
      last_scanned_at   = NULL,
      updated_at        = NOW()
    WHERE scan_status = 'scanned'
  `);

  const resetCount = result.rowCount ?? 0;
  req.log.info({ resetCount }, "Tüm scanned leadler yeniden kalifikasyona sokuldu");
  res.json({
    reset: resetCount,
    message: `${resetCount} lead sıfırlandı — admin panelinden "Kalifikasyonu Çalıştır" (limit: 50-100) ile batch batch işleyin.`,
  });
});

// ─── GET /api/admin-panel/lead-discovery/qualified ───────────────────────────
router.get("/admin-panel/lead-discovery/qualified", requireAdmin, async (req: Request, res: Response) => {
  const minScore    = parseInt(req.query["minScore"] as string ?? "0");
  const hasContact  = req.query["hasContact"]  === "true";
  const noContact   = req.query["noContact"]   === "true";
  const notSent     = req.query["notSent"]     === "true";
  const hasTeaser   = req.query["hasTeaser"]   === "true";
  const teaserSent  = req.query["teaserSent"]  === "true";
  const criticalPort = req.query["criticalPort"] === "true";
  const tier        = req.query["tier"] as string | undefined;
  const source      = req.query["source"] as string | undefined;
  const search      = (req.query["search"] as string ?? "").trim().toLowerCase();
  const sortBy      = (req.query["sortBy"] as string) || "risk_desc";
  const municipality = req.query["municipality"] as string | undefined; // "only" | "exclude" | undefined
  const page        = Math.max(1, parseInt(req.query["page"] as string ?? "1"));
  const pageSize    = Math.min(100, Math.max(10, parseInt(req.query["pageSize"] as string ?? "50")));
  const sectorEmpty = req.query["sectorEmpty"] === "true";
  const sectorSearch = (req.query["sector"] as string ?? "").trim();
  const cityEmpty   = req.query["cityEmpty"] === "true";
  const citySearch  = (req.query["city"] as string ?? "").trim();

  const conditions: ReturnType<typeof sql | typeof eq | typeof isNotNull | typeof isNull>[] = [
    eq(leadCandidatesTable.isQualified, true),
  ];
  if (minScore > 0)   conditions.push(sql`${leadCandidatesTable.riskScore} >= ${minScore}`);
  if (hasContact)     conditions.push(isNotNull(leadCandidatesTable.contactEmail));
  if (noContact)      conditions.push(isNull(leadCandidatesTable.contactEmail));
  if (notSent)        conditions.push(isNull(leadCandidatesTable.teaserSentAt));
  if (teaserSent)     conditions.push(isNotNull(leadCandidatesTable.teaserSentAt));
  if (hasTeaser)      conditions.push(isNotNull(leadCandidatesTable.teaserSubject));
  if (tier)           conditions.push(eq(leadCandidatesTable.tier, tier));
  if (source)         conditions.push(eq(leadCandidatesTable.source, source));
  if (search)         conditions.push(sql`${leadCandidatesTable.domain} ILIKE ${"%" + search + "%"}`);
  if (criticalPort)   conditions.push(sql`${leadCandidatesTable.domain} IN (
    SELECT domain FROM customer_tech_stack
    WHERE category = 'open_port' AND security_risk = 'critical' AND is_active = true
  )`);
  if (municipality === "only")    conditions.push(sql`(${leadCandidatesTable.isMunicipality} = true OR ${leadCandidatesTable.domain} LIKE '%.bel.tr')`);
  if (municipality === "exclude") conditions.push(sql`(${leadCandidatesTable.isMunicipality} = false AND ${leadCandidatesTable.domain} NOT LIKE '%.bel.tr')`);
  if (sectorEmpty)    conditions.push(sql`(${leadCandidatesTable.sector} IS NULL OR ${leadCandidatesTable.sector} = '')`);
  else if (sectorSearch) conditions.push(sql`${leadCandidatesTable.sector} ILIKE ${"%" + sectorSearch + "%"}`);
  if (cityEmpty)      conditions.push(sql`(${leadCandidatesTable.city} IS NULL OR ${leadCandidatesTable.city} = '')`);
  else if (citySearch) conditions.push(sql`${leadCandidatesTable.city} ILIKE ${"%" + citySearch + "%"}`);

  const bistOnly  = req.query["bistOnly"]  === "true";
  const bistIndex = (req.query["bistIndex"] as string ?? "").trim();
  if (bistOnly)                 conditions.push(eq(leadCandidatesTable.isPublicCompany, true));
  if (bistIndex === "bist30")   conditions.push(eq(leadCandidatesTable.isBist30, true));
  else if (bistIndex === "bist100") conditions.push(eq(leadCandidatesTable.isBist100, true));
  else if (bistIndex === "bist500") conditions.push(eq(leadCandidatesTable.isBist500, true));

  const orderClause =
    sortBy === "risk_asc"   ? leadCandidatesTable.riskScore :
    sortBy === "domain_asc" ? leadCandidatesTable.domain :
    sortBy === "added_desc" ? desc(leadCandidatesTable.createdAt) :
    sortBy === "added_asc"  ? leadCandidatesTable.createdAt :
    /* risk_desc default */   desc(leadCandidatesTable.riskScore);

  const [rows, [{ total }]] = await Promise.all([
    db.select().from(leadCandidatesTable)
      .where(and(...conditions))
      .orderBy(orderClause)
      .limit(pageSize)
      .offset((page - 1) * pageSize),
    db.select({ total: count() }).from(leadCandidatesTable)
      .where(and(...conditions)),
  ]);

  res.json({ rows, total, page, pageSize });
});

// ─── GET /api/admin-panel/lead-discovery/candidates ──────────────────────────
router.get("/admin-panel/lead-discovery/candidates", requireAdmin, async (req: Request, res: Response) => {
  const status       = req.query["status"] as string | undefined;
  const tier         = req.query["tier"] as string | undefined;
  const hasContact   = req.query["hasContact"] === "true";
  const notSent      = req.query["notSent"]    === "true";
  const municipality = req.query["municipality"] as string | undefined; // "only" | "exclude" | undefined
  const search       = (req.query["search"] as string ?? "").trim();
  const page         = parseInt(req.query["page"] as string ?? "1");
  const pageSize     = parseInt(req.query["pageSize"] as string ?? "50");
  const sectorEmpty  = req.query["sectorEmpty"] === "true";
  const sectorSearch = (req.query["sector"] as string ?? "").trim();
  const cityEmpty    = req.query["cityEmpty"] === "true";
  const citySearch   = (req.query["city"] as string ?? "").trim();

  const conditions: ReturnType<typeof sql | typeof eq | typeof isNotNull | typeof isNull>[] = [];
  if (status) conditions.push(eq(leadCandidatesTable.scanStatus, status));
  if (tier) conditions.push(eq(leadCandidatesTable.tier, tier));
  if (hasContact) conditions.push(isNotNull(leadCandidatesTable.contactEmail));
  if (notSent)    conditions.push(isNull(leadCandidatesTable.teaserSentAt));
  if (search)     conditions.push(sql`${leadCandidatesTable.domain} ILIKE ${"%" + search + "%"}`);
  if (municipality === "only")    conditions.push(sql`(${leadCandidatesTable.isMunicipality} = true OR ${leadCandidatesTable.domain} LIKE '%.bel.tr')`);
  if (municipality === "exclude") conditions.push(sql`(${leadCandidatesTable.isMunicipality} = false AND ${leadCandidatesTable.domain} NOT LIKE '%.bel.tr')`);
  if (sectorEmpty)    conditions.push(sql`(${leadCandidatesTable.sector} IS NULL OR ${leadCandidatesTable.sector} = '')`);
  else if (sectorSearch) conditions.push(sql`${leadCandidatesTable.sector} ILIKE ${"%" + sectorSearch + "%"}`);
  if (cityEmpty)      conditions.push(sql`(${leadCandidatesTable.city} IS NULL OR ${leadCandidatesTable.city} = '')`);
  else if (citySearch) conditions.push(sql`${leadCandidatesTable.city} ILIKE ${"%" + citySearch + "%"}`);

  const bistOnly  = req.query["bistOnly"]  === "true";
  const bistIndex = (req.query["bistIndex"] as string ?? "").trim();
  if (bistOnly)                 conditions.push(eq(leadCandidatesTable.isPublicCompany, true));
  if (bistIndex === "bist30")   conditions.push(eq(leadCandidatesTable.isBist30, true));
  else if (bistIndex === "bist100") conditions.push(eq(leadCandidatesTable.isBist100, true));
  else if (bistIndex === "bist500") conditions.push(eq(leadCandidatesTable.isBist500, true));

  const sourceFilter  = (req.query["source"]  as string ?? "").trim();
  const scanStatusFilter = (req.query["scanStatus"] as string ?? "").trim();
  const isAliveFilter = req.query["isAlive"] as string | undefined; // "true" | "false"
  const hasFortigateFilter = req.query["hasFortigate"] === "true";
  if (sourceFilter)     conditions.push(eq(leadCandidatesTable.source, sourceFilter));
  if (scanStatusFilter) conditions.push(eq(leadCandidatesTable.scanStatus, scanStatusFilter));
  if (isAliveFilter === "true")  conditions.push(eq(leadCandidatesTable.isAlive, true));
  if (isAliveFilter === "false") conditions.push(sql`(${leadCandidatesTable.isAlive} = false OR ${leadCandidatesTable.isAlive} IS NULL)`);
  if (hasFortigateFilter) conditions.push(eq(leadCandidatesTable.hasFortigate, true));

  const rows = await db.select().from(leadCandidatesTable)
    .where(conditions.length ? and(...conditions) : undefined)
    .orderBy(desc(leadCandidatesTable.createdAt))
    .limit(pageSize)
    .offset((page - 1) * pageSize);

  const [{ total }] = await db.select({ total: count() }).from(leadCandidatesTable)
    .where(conditions.length ? and(...conditions) : undefined);

  // WAF + reputation için domain_scans'tan batch yükle
  const scanIds = rows.map((r) => r.scanId).filter((id): id is number => id !== null);
  const wafMap = new Map<number, {
    wafDetected: boolean | null;
    confidenceScore: number | null;
    blacklistScore: number | null;
    sslDaysRemaining: number | null;
    mailReputationScore: number | null;
  }>();
  if (scanIds.length > 0) {
    const wafRows = await db.select({
      id:                  domainScansTable.id,
      wafDetected:         domainScansTable.wafDetected,
      confidenceScore:     domainScansTable.confidenceScore,
      blacklistScore:      domainScansTable.blacklistScore,
      sslDaysRemaining:    domainScansTable.sslDaysRemaining,
      mailReputationScore: domainScansTable.mailReputationScore,
    }).from(domainScansTable).where(inArray(domainScansTable.id, scanIds));
    for (const r of wafRows) wafMap.set(r.id, {
      wafDetected:         r.wafDetected,
      confidenceScore:     r.confidenceScore,
      blacklistScore:      r.blacklistScore,
      sslDaysRemaining:    r.sslDaysRemaining,
      mailReputationScore: r.mailReputationScore,
    });
  }
  const enrichedRows = rows.map((r) => ({
    ...r,
    wafDetected:         r.scanId ? (wafMap.get(r.scanId)?.wafDetected         ?? null) : null,
    confidenceScore:     r.scanId ? (wafMap.get(r.scanId)?.confidenceScore     ?? null) : null,
    blacklistScore:      r.scanId ? (wafMap.get(r.scanId)?.blacklistScore      ?? null) : null,
    sslDaysRemaining:    r.scanId ? (wafMap.get(r.scanId)?.sslDaysRemaining    ?? null) : null,
    mailReputationScore: r.scanId ? (wafMap.get(r.scanId)?.mailReputationScore ?? null) : null,
  }));

  res.json({ rows: enrichedRows, total, page, pageSize });
});

// ─── GET /api/admin-panel/lead-discovery/export ───────────────────────────────
// Mevcut filtreleri dikkate alarak tüm lead_candidates listesini Excel olarak indir.
router.get("/admin-panel/lead-discovery/export", requireAdmin, async (req: Request, res: Response) => {
  try {
    const ExcelJS = (await import("exceljs")).default;

    const tier         = req.query["tier"] as string | undefined;
    const hasContact   = req.query["hasContact"] === "true";
    const notSent      = req.query["notSent"]    === "true";
    const municipality = req.query["municipality"] as string | undefined;
    const search       = (req.query["search"] as string ?? "").trim();

    const conditions: ReturnType<typeof sql | typeof eq | typeof isNotNull | typeof isNull>[] = [];
    if (tier)         conditions.push(eq(leadCandidatesTable.tier, tier));
    if (hasContact)   conditions.push(isNotNull(leadCandidatesTable.contactEmail));
    if (notSent)      conditions.push(isNull(leadCandidatesTable.teaserSentAt));
    if (search)       conditions.push(sql`${leadCandidatesTable.domain} ILIKE ${"%" + search + "%"}`);
    if (municipality === "only")    conditions.push(sql`(${leadCandidatesTable.isMunicipality} = true OR ${leadCandidatesTable.domain} LIKE '%.bel.tr')`);
    if (municipality === "exclude") conditions.push(sql`(${leadCandidatesTable.isMunicipality} = false AND ${leadCandidatesTable.domain} NOT LIKE '%.bel.tr')`);

    const where = conditions.length ? and(...conditions) : undefined;

    const [{ total }] = await db.select({ total: count() }).from(leadCandidatesTable).where(where);
    const totalNum = Number(total);

    if (totalNum === 0) {
      res.status(404).json({ error: "Export edilecek kayıt bulunamadı." });
      return;
    }

    const wb = new ExcelJS.Workbook();
    wb.creator = "CyberStep.io";
    wb.created = new Date();
    const ws = wb.addWorksheet("Domains");

    ws.columns = [
      { header: "Domain",          key: "domain",          width: 32 },
      { header: "IP Adresi",       key: "ip",              width: 16 },
      { header: "Risk Skoru",      key: "riskScore",       width: 12 },
      { header: "Risk Seviyesi",   key: "riskLevel",       width: 14 },
      { header: "Durum",           key: "status",          width: 14 },
      { header: "Kayıt Tarihi",    key: "createdAt",       width: 20 },
      { header: "Son Tarama",      key: "lastScanned",     width: 20 },
      { header: "Ülke",            key: "country",         width: 8  },
      { header: "Şehir",           key: "city",            width: 16 },
      { header: "Sektör",          key: "sector",          width: 18 },
      { header: "Şirket Adı",      key: "companyName",     width: 26 },
      { header: "Açık Port Sayısı",key: "portCount",       width: 16 },
      { header: "CVE Sayısı",      key: "cveCount",        width: 12 },
      { header: "WAF Tespit",      key: "waf",             width: 12 },
      { header: "Kaynak",          key: "source",          width: 18 },
      { header: "Halka Açık",      key: "isPublicCompany", width: 12 },
      { header: "BIST Ticker",     key: "ticker",          width: 12 },
      { header: "BIST Endeks",     key: "bistIndexes",     width: 28 },
      { header: "BIST Pazar",      key: "bistMarket",      width: 16 },
    ];

    // Header satırı stili
    const headerRow = ws.getRow(1);
    headerRow.eachCell((cell) => {
      cell.fill   = { type: "pattern", pattern: "solid", fgColor: { argb: "FF0E1A2E" } };
      cell.font   = { bold: true, color: { argb: "FF00C8FF" } };
      cell.border = { bottom: { style: "thin", color: { argb: "FF00C8FF" } } };
    });
    headerRow.height = 20;
    ws.views = [{ state: "frozen", xSplit: 0, ySplit: 1 }];

    const RISK_COLORS: Record<string, string> = {
      critical: "FFFF4444",
      high:     "FFFF8C00",
      medium:   "FFF5A623",
      low:      "FF00C8FF",
    };

    function getRiskLevel(score: number | null): string {
      if (score === null || score === undefined) return "";
      if (score < 30) return "critical";
      if (score < 60) return "high";
      if (score < 80) return "medium";
      return "low";
    }

    function fmtDate(d: Date | string | null | undefined): string {
      if (!d) return "";
      const dt = d instanceof Date ? d : new Date(d as string);
      if (isNaN(dt.getTime())) return "";
      const dd   = String(dt.getDate()).padStart(2, "0");
      const mm   = String(dt.getMonth() + 1).padStart(2, "0");
      const yyyy = dt.getFullYear();
      const hh   = String(dt.getHours()).padStart(2, "0");
      const min  = String(dt.getMinutes()).padStart(2, "0");
      return `${dd}.${mm}.${yyyy} ${hh}:${min}`;
    }

    const BATCH = 1000;
    const batches = Math.ceil(totalNum / BATCH);

    for (let b = 0; b < batches; b++) {
      const rows = await db.select({
        domain:          leadCandidatesTable.domain,
        companyName:     leadCandidatesTable.companyName,
        sector:          leadCandidatesTable.sector,
        city:            leadCandidatesTable.city,
        source:          leadCandidatesTable.source,
        scanStatus:      leadCandidatesTable.scanStatus,
        scanId:          leadCandidatesTable.scanId,
        riskScore:       leadCandidatesTable.riskScore,
        wafDetected:     leadCandidatesTable.wafDetected,
        createdAt:       leadCandidatesTable.createdAt,
        lastScannedAt:   leadCandidatesTable.lastScannedAt,
        isPublicCompany: leadCandidatesTable.isPublicCompany,
        ticker:          leadCandidatesTable.ticker,
        bistIndexes:     leadCandidatesTable.bistIndexes,
        bistMarket:      leadCandidatesTable.bistMarket,
      }).from(leadCandidatesTable)
        .where(where)
        .orderBy(asc(leadCandidatesTable.id))
        .limit(BATCH)
        .offset(b * BATCH);

      // Batch'teki scan_id'ler için domain_scans verisi
      const scanIds = rows.map(r => r.scanId).filter((id): id is number => id !== null);
      const scanMap = new Map<number, {
        originIp: string | null;
        openPortsCount: number | null;
        criticalCveCount: number | null;
        highCveCount: number | null;
        country: string | null;
      }>();
      if (scanIds.length > 0) {
        const scans = await db.select({
          id:              domainScansTable.id,
          originIp:        domainScansTable.originIp,
          openPortsCount:  domainScansTable.openPortsCount,
          criticalCveCount:domainScansTable.criticalCveCount,
          highCveCount:    domainScansTable.highCveCount,
          country:         domainScansTable.abuseIpdbCountry,
        }).from(domainScansTable).where(inArray(domainScansTable.id, scanIds));
        for (const s of scans) scanMap.set(s.id, s);
      }

      for (const row of rows) {
        const scan      = row.scanId ? (scanMap.get(row.scanId) ?? null) : null;
        const riskLevel = getRiskLevel(row.riskScore);
        const cveCount  = scan ? ((scan.criticalCveCount ?? 0) + (scan.highCveCount ?? 0)) : null;

        const excelRow = ws.addRow({
          domain:          row.domain,
          ip:              scan?.originIp ?? "",
          riskScore:       row.riskScore  ?? "",
          riskLevel:       riskLevel === "critical" ? "Kritik" : riskLevel === "high" ? "Yüksek" : riskLevel === "medium" ? "Orta" : riskLevel === "low" ? "Düşük" : "",
          status:          row.scanStatus ?? "",
          createdAt:       fmtDate(row.createdAt),
          lastScanned:     fmtDate(row.lastScannedAt),
          country:         scan?.country ?? "",
          city:            row.city        ?? "",
          sector:          row.sector      ?? "",
          companyName:     row.companyName ?? "",
          portCount:       scan?.openPortsCount ?? "",
          cveCount:        cveCount !== null ? cveCount : "",
          waf:             row.wafDetected === true ? "Evet" : row.wafDetected === false ? "Hayır" : "",
          source:          row.source ?? "",
          isPublicCompany: row.isPublicCompany ? "Evet" : "",
          ticker:          row.ticker      ?? "",
          bistIndexes:     row.bistIndexes ?? "",
          bistMarket:      row.bistMarket  ?? "",
        });
        excelRow.height = 18;

        // Risk seviyesi hücresini renklendir
        if (riskLevel && RISK_COLORS[riskLevel]) {
          const cell = excelRow.getCell("riskLevel");
          cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: RISK_COLORS[riskLevel]! } };
          cell.font = { bold: true, color: { argb: "FF0E1A2E" } };
        }
      }
    }

    const today  = new Date().toISOString().slice(0, 10);
    const buffer = await wb.xlsx.writeBuffer();
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", `attachment; filename="cyberstep_domains_${today}.xlsx"`);
    res.setHeader("X-Total-Count", String(totalNum));
    res.send(Buffer.from(buffer));
    logger.info({ totalNum, tier, search, municipality }, "Domain Excel export tamamlandı");
  } catch (err) {
    logger.error({ err }, "Domain Excel export hatası");
    res.status(500).json({ error: "Export sırasında hata oluştu." });
  }
});

// ─── GET /api/admin-panel/lead-discovery/export-qualified ────────────────────
router.get("/admin-panel/lead-discovery/export-qualified", requireAdmin, async (req: Request, res: Response) => {
  try {
    const ExcelJS = (await import("exceljs")).default;

    const minScore     = parseInt(req.query["minScore"] as string ?? "0");
    const hasContact   = req.query["hasContact"]   === "true";
    const noContact    = req.query["noContact"]    === "true";
    const notSent      = req.query["notSent"]      === "true";
    const hasTeaser    = req.query["hasTeaser"]    === "true";
    const teaserSent   = req.query["teaserSent"]   === "true";
    const criticalPort = req.query["criticalPort"] === "true";
    const tier         = req.query["tier"] as string | undefined;
    const search       = (req.query["search"] as string ?? "").trim();
    const municipality = req.query["municipality"] as string | undefined;
    const sectorEmpty  = req.query["sectorEmpty"]  === "true";
    const sectorSearch = (req.query["sector"] as string ?? "").trim();
    const cityEmpty    = req.query["cityEmpty"]    === "true";
    const citySearch   = (req.query["city"] as string ?? "").trim();

    const conditions: ReturnType<typeof sql | typeof eq | typeof isNotNull | typeof isNull>[] = [
      eq(leadCandidatesTable.isQualified, true),
    ];
    if (minScore > 0)   conditions.push(sql`${leadCandidatesTable.riskScore} >= ${minScore}`);
    if (hasContact)     conditions.push(isNotNull(leadCandidatesTable.contactEmail));
    if (noContact)      conditions.push(isNull(leadCandidatesTable.contactEmail));
    if (notSent)        conditions.push(isNull(leadCandidatesTable.teaserSentAt));
    if (teaserSent)     conditions.push(isNotNull(leadCandidatesTable.teaserSentAt));
    if (hasTeaser)      conditions.push(isNotNull(leadCandidatesTable.teaserSubject));
    if (tier)           conditions.push(eq(leadCandidatesTable.tier, tier));
    if (search)         conditions.push(sql`${leadCandidatesTable.domain} ILIKE ${"%" + search + "%"}`);
    if (criticalPort)   conditions.push(sql`${leadCandidatesTable.domain} IN (
      SELECT domain FROM customer_tech_stack
      WHERE category = 'open_port' AND security_risk = 'critical' AND is_active = true
    )`);
    if (municipality === "only")    conditions.push(sql`(${leadCandidatesTable.isMunicipality} = true OR ${leadCandidatesTable.domain} LIKE '%.bel.tr')`);
    if (municipality === "exclude") conditions.push(sql`(${leadCandidatesTable.isMunicipality} = false AND ${leadCandidatesTable.domain} NOT LIKE '%.bel.tr')`);
    if (sectorEmpty)    conditions.push(sql`(${leadCandidatesTable.sector} IS NULL OR ${leadCandidatesTable.sector} = '')`);
    else if (sectorSearch) conditions.push(sql`${leadCandidatesTable.sector} ILIKE ${"%" + sectorSearch + "%"}`);
    if (cityEmpty)      conditions.push(sql`(${leadCandidatesTable.city} IS NULL OR ${leadCandidatesTable.city} = '')`);
    else if (citySearch) conditions.push(sql`${leadCandidatesTable.city} ILIKE ${"%" + citySearch + "%"}`);

    const where = and(...conditions);

    const [{ total }] = await db.select({ total: count() }).from(leadCandidatesTable).where(where);
    const totalNum = Number(total);

    if (totalNum === 0) {
      res.status(404).json({ error: "Export edilecek kayıt bulunamadı." });
      return;
    }

    const wb = new ExcelJS.Workbook();
    wb.creator = "CyberStep.io";
    wb.created = new Date();
    const ws = wb.addWorksheet("Qualified Leads");

    ws.columns = [
      { header: "Domain",          key: "domain",       width: 32 },
      { header: "Şirket Adı",      key: "companyName",  width: 28 },
      { header: "Yetkili Adı",     key: "officerName",  width: 22 },
      { header: "Yetkili Unvanı",  key: "officerTitle", width: 20 },
      { header: "Email",           key: "email",        width: 30 },
      { header: "Risk Skoru",      key: "riskScore",    width: 12 },
      { header: "Risk Seviyesi",   key: "riskLevel",    width: 14 },
      { header: "Tier",            key: "tier",         width: 10 },
      { header: "Sektör",          key: "sector",       width: 18 },
      { header: "Şehir",           key: "city",         width: 16 },
      { header: "Teaser Durumu",   key: "teaserStatus", width: 16 },
      { header: "Contact Kaynağı", key: "contactSrc",   width: 18 },
      { header: "LinkedIn",        key: "linkedin",     width: 50 },
      { header: "Kayıt Tarihi",    key: "createdAt",    width: 20 },
    ];

    const headerRow = ws.getRow(1);
    headerRow.eachCell((cell) => {
      cell.fill   = { type: "pattern", pattern: "solid", fgColor: { argb: "FF0E1A2E" } };
      cell.font   = { bold: true, color: { argb: "FF00C8FF" } };
      cell.border = { bottom: { style: "thin", color: { argb: "FF00C8FF" } } };
    });
    headerRow.height = 20;
    ws.views = [{ state: "frozen", xSplit: 0, ySplit: 1 }];

    const RISK_COLORS: Record<string, string> = {
      critical: "FFFF4444",
      high:     "FFFF8C00",
      medium:   "FFF5A623",
      low:      "FF00C8FF",
    };

    function getRiskLevel(score: number | null): string {
      if (score === null || score === undefined) return "";
      if (score < 30) return "critical";
      if (score < 60) return "high";
      if (score < 80) return "medium";
      return "low";
    }

    function fmtDate(d: Date | string | null | undefined): string {
      if (!d) return "";
      const dt = d instanceof Date ? d : new Date(d as string);
      if (isNaN(dt.getTime())) return "";
      return `${String(dt.getDate()).padStart(2, "0")}.${String(dt.getMonth() + 1).padStart(2, "0")}.${dt.getFullYear()} ${String(dt.getHours()).padStart(2, "0")}:${String(dt.getMinutes()).padStart(2, "0")}`;
    }

    function buildLinkedIn(domain: string, companyName: string | null, officerName: string | null): string {
      const slug = domain.split(".")[0] ?? "";
      const company = companyName ?? (slug.charAt(0).toUpperCase() + slug.slice(1).toLowerCase());
      if (officerName) {
        return `https://www.linkedin.com/search/results/people/?keywords=${encodeURIComponent(`${officerName} ${company}`)}`;
      }
      return `https://www.linkedin.com/search/results/people/?keywords=${encodeURIComponent(company)}&titleKeyword=${encodeURIComponent("IT OR CTO OR CISO OR Genel Mudur")}`;
    }

    const BATCH = 1000;
    const batches = Math.ceil(totalNum / BATCH);

    for (let b = 0; b < batches; b++) {
      const rows = await db.select({
        domain:       leadCandidatesTable.domain,
        companyName:  leadCandidatesTable.companyName,
        officerName:  leadCandidatesTable.officerName,
        officerTitle: leadCandidatesTable.officerTitle,
        contactEmail: leadCandidatesTable.contactEmail,
        contactSource:leadCandidatesTable.contactSource,
        riskScore:    leadCandidatesTable.riskScore,
        tier:         leadCandidatesTable.tier,
        sector:       leadCandidatesTable.sector,
        city:         leadCandidatesTable.city,
        teaserSentAt: leadCandidatesTable.teaserSentAt,
        teaserSubject:leadCandidatesTable.teaserSubject,
        createdAt:    leadCandidatesTable.createdAt,
      }).from(leadCandidatesTable)
        .where(where)
        .orderBy(desc(leadCandidatesTable.riskScore))
        .limit(BATCH)
        .offset(b * BATCH);

      for (const row of rows) {
        const riskLevel = getRiskLevel(row.riskScore);
        const teaserStatus = row.teaserSentAt ? "Gönderildi" : row.teaserSubject ? "Hazır" : "Yok";

        const excelRow = ws.addRow({
          domain:       row.domain,
          companyName:  row.companyName  ?? "",
          officerName:  row.officerName  ?? "",
          officerTitle: row.officerTitle ?? "",
          email:        row.contactEmail ?? "",
          riskScore:    row.riskScore    ?? "",
          riskLevel:    riskLevel === "critical" ? "Kritik" : riskLevel === "high" ? "Yüksek" : riskLevel === "medium" ? "Orta" : riskLevel === "low" ? "Düşük" : "",
          tier:         row.tier         ?? "",
          sector:       row.sector       ?? "",
          city:         row.city         ?? "",
          teaserStatus,
          contactSrc:   row.contactSource ?? "",
          linkedin:     buildLinkedIn(row.domain, row.companyName ?? null, row.officerName ?? null),
          createdAt:    fmtDate(row.createdAt),
        });
        excelRow.height = 18;

        if (riskLevel && RISK_COLORS[riskLevel]) {
          const cell = excelRow.getCell("riskLevel");
          cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: RISK_COLORS[riskLevel]! } };
          cell.font = { bold: true, color: { argb: "FF0E1A2E" } };
        }

        const emailCell = excelRow.getCell("email");
        if (row.contactEmail) {
          emailCell.value = { text: row.contactEmail, hyperlink: `mailto:${row.contactEmail}` };
          emailCell.font  = { color: { argb: "FF00C8FF" }, underline: true };
        }

        const linkedinCell = excelRow.getCell("linkedin");
        const linkedinUrl = buildLinkedIn(row.domain, row.companyName ?? null, row.officerName ?? null);
        linkedinCell.value = { text: "LinkedIn Ara", hyperlink: linkedinUrl };
        linkedinCell.font  = { color: { argb: "FF7CB9F4" }, underline: true };
      }
    }

    const today  = new Date().toISOString().slice(0, 10);
    const buffer = await wb.xlsx.writeBuffer();
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", `attachment; filename="cyberstep_qualified_${today}.xlsx"`);
    res.setHeader("X-Total-Count", String(totalNum));
    res.send(Buffer.from(buffer));
    logger.info({ totalNum, tier, search, municipality }, "Qualified Excel export tamamlandı");
  } catch (err) {
    logger.error({ err }, "Qualified Excel export hatası");
    res.status(500).json({ error: "Export sırasında hata oluştu." });
  }
});

// ─── PATCH /api/admin-panel/lead-discovery/candidates/:id/contact ────────────
// ─── PATCH /api/admin-panel/lead-discovery/candidates/:id ────────────────────
router.patch("/admin-panel/lead-discovery/candidates/:id", requireAdmin, async (req: Request, res: Response) => {
  const id = parseInt(String(req.params["id"] ?? "0"));
  if (!id) { res.status(400).json({ error: "Geçersiz ID" }); return; }
  const body = req.body as {
    companyName?: string; sector?: string; subSector?: string; city?: string;
    ticker?: string; bistIndexes?: string; bistMarket?: string;
    isPublicCompany?: boolean; sourceList?: string; tier?: string; notes?: string;
  };
  const clean = (v: string | undefined | null) => (typeof v === "string" ? v.trim() || null : undefined);
  const bi = body.bistIndexes !== undefined ? (body.bistIndexes.trim() || null) : undefined;
  const updateObj: Record<string, unknown> = { updatedAt: new Date() };
  if (body.companyName  !== undefined) updateObj["companyName"]  = clean(body.companyName);
  if (body.sector       !== undefined) updateObj["sector"]       = clean(body.sector);
  if (body.subSector    !== undefined) updateObj["subSector"]    = clean(body.subSector);
  if (body.city         !== undefined) updateObj["city"]         = clean(body.city);
  if (body.ticker       !== undefined) updateObj["ticker"]       = clean(body.ticker);
  if (bi !== undefined) {
    updateObj["bistIndexes"] = bi;
    updateObj["isBist30"]  = !!(bi?.includes("BIST 30"));
    updateObj["isBist100"] = !!(bi?.includes("BIST 100"));
    updateObj["isBist500"] = !!(bi?.includes("BIST 500"));
  }
  if (body.bistMarket   !== undefined) updateObj["bistMarket"]   = clean(body.bistMarket);
  if (body.isPublicCompany !== undefined) updateObj["isPublicCompany"] = !!body.isPublicCompany;
  if (body.sourceList   !== undefined) updateObj["sourceList"]   = clean(body.sourceList);
  if (body.tier         !== undefined) updateObj["tier"]         = clean(body.tier);
  if (body.notes        !== undefined) updateObj["notes"]        = clean(body.notes);
  await db.update(leadCandidatesTable).set(updateObj).where(eq(leadCandidatesTable.id, id));
  const [updated] = await db.select().from(leadCandidatesTable).where(eq(leadCandidatesTable.id, id));
  res.json({ ok: true, candidate: updated });
});

router.patch("/admin-panel/lead-discovery/candidates/:id/contact", requireAdmin, async (req: Request, res: Response) => {
  const id = parseInt(String(req.params["id"] ?? "0"));
  const { contactEmail, contactName, contactTitle } = req.body as {
    contactEmail?: string; contactName?: string; contactTitle?: string;
  };
  if (!contactEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactEmail)) {
    res.status(400).json({ error: "Geçerli bir e-posta adresi gerekli." }); return;
  }
  const [candidate] = await db.select().from(leadCandidatesTable).where(eq(leadCandidatesTable.id, id));
  if (!candidate) { res.status(404).json({ error: "Aday bulunamadı" }); return; }

  await db.update(leadCandidatesTable).set({
    contactEmail: contactEmail.trim(),
    contactName: contactName?.trim() || null,
    contactTitle: contactTitle?.trim() || null,
    contactSource: "manual",
    updatedAt: new Date(),
  }).where(eq(leadCandidatesTable.id, id));

  res.json({ message: "Kontak bilgisi güncellendi." });
});

// ─── POST /api/admin-panel/lead-discovery/candidates/:id/promote-to-isr ──────
router.post("/admin-panel/lead-discovery/candidates/:id/promote-to-isr", requireAdmin, async (req: Request, res: Response) => {
  const tenantId = requireTenantId(req, res); if (!tenantId) return;
  const id = parseInt(String(req.params["id"] ?? "0"));
  const [candidate] = await db.select().from(leadCandidatesTable).where(eq(leadCandidatesTable.id, id));
  if (!candidate) { res.status(404).json({ error: "Aday bulunamadı" }); return; }
  if (candidate.isrPromotedAt) {
    res.json({ ok: true, isrCustomerId: candidate.isrCustomerId, alreadyPromoted: true });
    return;
  }

  const companyName = candidate.scrapedCompanyName ?? candidate.companyName ?? candidate.domain;
  const [isrCustomer] = await db.insert(isrCustomersTable).values({
    tenantId,
    companyName,
    contactName: candidate.contactName ?? candidate.officerName ?? null,
    email: candidate.contactEmail ?? null,
    phone: candidate.scrapedPhone ?? null,
    sector: candidate.sector ?? null,
    notes: [
      candidate.isrNotes,
      candidate.riskScore != null ? `Risk skoru: ${candidate.riskScore}` : null,
      candidate.criticalFindings > 0 ? `Kritik bulgu: ${candidate.criticalFindings}` : null,
      candidate.findingHighlights?.length ? `Bulgular: ${candidate.findingHighlights.slice(0, 3).join("; ")}` : null,
    ].filter(Boolean).join("\n") || null,
  }).returning({ id: isrCustomersTable.id });

  await db.update(leadCandidatesTable).set({
    isrPromotedAt: new Date(),
    isrCustomerId: isrCustomer?.id ?? null,
    updatedAt: new Date(),
  }).where(eq(leadCandidatesTable.id, id));

  // Otomatik deal oluştur + ISR ekibine bildirim (fire-and-forget)
  setImmediate(async () => {
    try {
      const baseUrl = getIsrBaseUrl();
      const [newDeal] = await db.insert(isrDealsTable).values({
        tenantId,
        customerId: isrCustomer?.id ?? null,
        customerName: companyName,
        customerEmail: candidate.contactEmail ?? "",
        customerCompany: companyName,
        customerPhone: candidate.scrapedPhone ?? null,
        status: "new",
        intakeChannel: "lead_discovery",
        priority: (candidate.riskScore ?? 0) >= 70 ? "high" : "normal",
        notes: [
          `Lead skoru: ${candidate.riskScore ?? "N/A"}`,
          candidate.criticalFindings > 0 ? `Kritik bulgu: ${candidate.criticalFindings}` : null,
          "Otomatik oluşturuldu — Lead Discovery",
        ].filter(Boolean).join("\n"),
      }).returning({ id: isrDealsTable.id });

      const dealUrl = `${baseUrl}/panel/isr/deal/${newDeal?.id}`;
      const isrEmail = getIsrEmail("isr-team");
      await sendMail({
        to: isrEmail,
        subject: `Yeni Deal: ${companyName}`,
        html: buildDealNotificationHtml({
          companyName,
          domain: candidate.domain,
          contactName: candidate.contactName ?? null,
          contactEmail: candidate.contactEmail ?? null,
          riskScore: candidate.riskScore ?? null,
          criticalFindings: candidate.criticalFindings ?? 0,
          dealId: newDeal?.id ?? 0,
          dealUrl,
        }),
      });
      logger.info({ id, domain: candidate.domain, dealId: newDeal?.id }, "ISR deal oluşturuldu ve bildirim gönderildi");
    } catch (err) {
      logger.error({ err, id }, "ISR deal oluşturma/bildirim hatası");
    }
  });

  logger.info({ id, domain: candidate.domain, isrCustomerId: isrCustomer?.id }, "Lead ISR müşteri listesine eklendi");
  res.json({ ok: true, isrCustomerId: isrCustomer?.id });
});

// ─── PATCH /api/admin-panel/lead-discovery/candidates/:id/isr-notes ──────────
router.patch("/admin-panel/lead-discovery/candidates/:id/isr-notes", requireAdmin, async (req: Request, res: Response) => {
  const id = parseInt(String(req.params["id"] ?? "0"));
  const { isrNotes } = req.body as { isrNotes?: string };
  const [candidate] = await db.select().from(leadCandidatesTable).where(eq(leadCandidatesTable.id, id));
  if (!candidate) { res.status(404).json({ error: "Aday bulunamadı" }); return; }
  await db.update(leadCandidatesTable).set({
    isrNotes: typeof isrNotes === "string" ? isrNotes.trim() || null : null,
    updatedAt: new Date(),
  }).where(eq(leadCandidatesTable.id, id));
  res.json({ message: "ISR notları güncellendi." });
});

// ─── POST /api/admin-panel/lead-discovery/web-enrich (batch) ─────────────────
router.post("/admin-panel/lead-discovery/web-enrich", requireAdmin, async (req: Request, res: Response) => {
  const { limit = 30 } = (req.body ?? {}) as { limit?: number };
  const leads = await db.select({ id: leadCandidatesTable.id, domain: leadCandidatesTable.domain })
    .from(leadCandidatesTable)
    .where(eq(leadCandidatesTable.isQualified, true))
    .limit(limit);

  res.json({ message: `${leads.length} lead için web enrichment başlatıldı.`, count: leads.length });

  setImmediate(async () => {
    for (const lead of leads) {
      try {
        await enrichLeadFromWeb(lead.id, lead.domain);
        await new Promise((r) => setTimeout(r, 1500));
      } catch (e) {
        logger.warn({ id: lead.id, domain: lead.domain, err: String(e) }, "Batch web enrich hata");
      }
    }
    logger.info({ count: leads.length }, "Batch web enrich tamamlandı");
  });
});

// ─── POST /api/admin-panel/lead-discovery/candidates/:id/web-enrich ──────────
router.post("/admin-panel/lead-discovery/candidates/:id/web-enrich", requireAdmin, async (req: Request, res: Response) => {
  const id = parseInt(String(req.params["id"] ?? "0"));
  const [candidate] = await db.select().from(leadCandidatesTable).where(eq(leadCandidatesTable.id, id));
  if (!candidate) { res.status(404).json({ error: "Aday bulunamadı" }); return; }

  res.json({ message: "Web enrichment başlatıldı." });

  setImmediate(async () => {
    try {
      await enrichLeadFromWeb(id, candidate.domain);
      logger.info({ id, domain: candidate.domain }, "Tek lead web enrich tamamlandı");
    } catch (e) {
      logger.error({ id, err: String(e) }, "Tek lead web enrich başarısız");
    }
  });
});

// ─── POST /api/admin-panel/lead-discovery/candidates/:id/re-enrich ────────────
router.post("/admin-panel/lead-discovery/candidates/:id/re-enrich", requireAdmin, async (req: Request, res: Response) => {
  const id = parseInt(String(req.params["id"] ?? "0"));
  const [candidate] = await db.select().from(leadCandidatesTable).where(eq(leadCandidatesTable.id, id));
  if (!candidate) { res.status(404).json({ error: "Aday bulunamadı" }); return; }

  res.json({ message: "Kontak arama başlatıldı (WHOIS + Web scraping)." });

  setImmediate(async () => {
    try {
      let contactEmail: string | null = null;
      let contactSource = "";

      // WHOIS
      const whoisEmail = await whoisLookup(candidate.domain);
      if (whoisEmail) { contactEmail = whoisEmail; contactSource = "whois"; }

      // Web scraping fallback
      if (!contactEmail) {
        const webContact = await scrapeContactEmail(candidate.domain);
        if (webContact) { contactEmail = webContact.email; contactSource = `web${webContact.sourcePath}`; }
      }

      if (contactEmail) {
        await db.update(leadCandidatesTable).set({
          contactEmail,
          contactSource,
          updatedAt: new Date(),
        }).where(eq(leadCandidatesTable.id, id));
        logger.info({ id, domain: candidate.domain, source: contactSource, email: contactEmail }, "Re-enrich kontak bulundu");
      } else {
        logger.info({ id, domain: candidate.domain }, "Re-enrich: kontak bulunamadı");
      }

      // MERSIS/KAP TR kaynaklarından yetkili adı/unvanını bul (her durumda çalışır)
      try {
        await enrichLeadFromTrSources(id, candidate.domain);
      } catch (trErr) {
        logger.debug({ id, err: String(trErr) }, "TR enrich non-fatal hata");
      }
    } catch (e) {
      logger.error({ id, err: String(e) }, "Re-enrich başarısız");
    }
  });
});

// ─── POST /api/admin-panel/lead-discovery/candidates/:id/teaser ──────────────
router.post("/admin-panel/lead-discovery/candidates/:id/teaser", requireAdmin, async (req: Request, res: Response) => {
  const id = parseInt(String(req.params["id"] ?? "0"));
  const [candidate] = await db.select().from(leadCandidatesTable).where(eq(leadCandidatesTable.id, id));
  if (!candidate) { res.status(404).json({ error: "Aday bulunamadı" }); return; }

  res.json({ message: "Teaser üretimi başlatıldı." });
  setImmediate(async () => {
    try {
      await generateLeadTeaserEmail(id, {
        overallScore: candidate.riskScore ?? 0,
        findings: (candidate.findingHighlights ?? []).map((t, i) => ({ severity: (i < 3 ? "critical" : "high") as "critical" | "high", title: t })),
      });
    } catch (e) {
      logger.error({ id, err: String(e) }, "Manuel teaser üretimi başarısız");
    }
  });
});

// ─── POST /api/admin-panel/lead-discovery/candidates/:id/send-teaser ─────────
router.post("/admin-panel/lead-discovery/candidates/:id/send-teaser", requireAdmin, async (req: Request, res: Response) => {
  const id = parseInt(String(req.params["id"] ?? "0"));
  const [candidate] = await db.select().from(leadCandidatesTable).where(eq(leadCandidatesTable.id, id));
  if (!candidate) { res.status(404).json({ error: "Aday bulunamadı" }); return; }
  if (!candidate.teaserSubject || !candidate.teaserBody) {
    res.status(400).json({ error: "Önce teaser üretilmeli." }); return;
  }
  if (!candidate.contactEmail) {
    res.status(400).json({ error: "İletişim e-postası bulunamadı." }); return;
  }

  const html = buildTeaserEmailHtml({
    companyName: candidate.scrapedCompanyName ?? candidate.companyName ?? candidate.domain,
    contactName: candidate.contactName ?? null,
    domain: candidate.domain,
    teaserBody: candidate.teaserBody,
    riskScore: candidate.riskScore ?? null,
    criticalFindings: candidate.criticalFindings ?? 0,
  });

  setImmediate(async () => {
    try {
      await sendMail({ to: candidate.contactEmail!, subject: candidate.teaserSubject!, html });
      logger.info({ id, to: candidate.contactEmail }, "Teaser e-posta gönderildi");
    } catch (err) {
      logger.error({ err, id }, "Teaser e-posta gönderimi başarısız");
    }
  });

  await db.update(leadCandidatesTable).set({ teaserSentAt: new Date(), updatedAt: new Date() })
    .where(eq(leadCandidatesTable.id, id));

  res.json({ message: `Teaser ${candidate.contactEmail} adresine gönderiliyor.`, sentTo: candidate.contactEmail });
});

// ─── DELETE /api/admin-panel/lead-discovery/candidates/:id ───────────────────
router.delete("/admin-panel/lead-discovery/candidates/:id", requireAdmin, async (req: Request, res: Response) => {
  const id = parseInt(String(req.params["id"] ?? "0"));
  await db.delete(leadCandidatesTable).where(eq(leadCandidatesTable.id, id));
  res.json({ message: "Aday silindi." });
});

// ─── GET /api/admin-panel/lead-discovery/candidates/:id/tech-stack ───────────
router.get("/admin-panel/lead-discovery/candidates/:id/tech-stack", requireAdmin, async (req: Request, res: Response) => {
  const id = parseInt(String(req.params["id"] ?? "0"));
  // Fingerprintler domain bazlı kaydediliyor (leadCandidateId=null olabilir)
  // Önce candidate'in domain'ini bul, sonra domain'e göre sorgula
  const [candidate] = await db
    .select({ domain: leadCandidatesTable.domain })
    .from(leadCandidatesTable)
    .where(eq(leadCandidatesTable.id, id))
    .limit(1);
  if (!candidate) { res.json([]); return; }

  const stack = await db
    .select({
      vendor: customerTechStackTable.vendor,
      product: customerTechStackTable.product,
      category: customerTechStackTable.category,
      salesSignal: customerTechStackTable.salesSignal,
      securityRisk: customerTechStackTable.securityRisk,
      securityNote: customerTechStackTable.securityNote,
      evidence: customerTechStackTable.evidence,
    })
    .from(customerTechStackTable)
    .where(and(
      eq(customerTechStackTable.domain, candidate.domain),
      eq(customerTechStackTable.isActive, true),
    ))
    .orderBy(asc(customerTechStackTable.category));
  res.json(stack);
});

// ─── GET /api/admin-panel/lead-discovery/domain/:domain ──────────────────────
// Tek bir domain için tam görünüm: lead_candidates satırı + aktif tech-stack kayıtları.
// Var olan /candidates/:id/tech-stack rotasının domain bazlı, tek noktadan bakış eşdeğeri.
router.get("/admin-panel/lead-discovery/domain/:domain", requireAdmin, async (req: Request, res: Response) => {
  const domain = String(req.params["domain"] ?? "").trim().toLowerCase();
  if (!domain) { res.status(400).json({ error: "domain parametresi gerekli" }); return; }

  const [candidate] = await db.select().from(leadCandidatesTable)
    .where(eq(leadCandidatesTable.domain, domain))
    .limit(1);
  if (!candidate) { res.status(404).json({ error: "Domain bulunamadı", domain }); return; }

  const [techStack, scan] = await Promise.all([
    db.select({
      vendor: customerTechStackTable.vendor,
      product: customerTechStackTable.product,
      category: customerTechStackTable.category,
      version: customerTechStackTable.version,
      confidence: customerTechStackTable.confidence,
      salesSignal: customerTechStackTable.salesSignal,
      securityRisk: customerTechStackTable.securityRisk,
      securityNote: customerTechStackTable.securityNote,
      evidence: customerTechStackTable.evidence,
      lastVerifiedAt: customerTechStackTable.lastVerifiedAt,
    }).from(customerTechStackTable)
      .where(and(
        eq(customerTechStackTable.domain, domain),
        eq(customerTechStackTable.isActive, true),
      ))
      .orderBy(asc(customerTechStackTable.category)),
    candidate.scanId
      ? db.select().from(domainScansTable).where(eq(domainScansTable.id, candidate.scanId)).limit(1)
      : Promise.resolve([]),
  ]);

  res.json({ candidate, techStack, scan: scan[0] ?? null });
});

// ─── GET /api/admin-panel/lead-discovery/sources ─────────────────────────────
// discovery_runs tablosundan kaynak bazlı özet: son senkronizasyon, toplam bulunan/eklenen,
// ve o kaynaktan gelen lead_candidates sayısı — CyberStep Discovery Engine spek'indeki
// GET /sources'a karşılık gelen agregasyon.
router.get("/admin-panel/lead-discovery/sources", requireAdmin, async (_req: Request, res: Response) => {
  res.set("Cache-Control", "no-store");

  const runStats = await db.select({
    source: discoveryRunsTable.source,
    runCount: count(),
    totalFound: sql<number>`COALESCE(SUM(${discoveryRunsTable.totalFound}), 0)`,
    totalAdded: sql<number>`COALESCE(SUM(${discoveryRunsTable.totalAdded}), 0)`,
    lastRunAt: sql<string | null>`MAX(${discoveryRunsTable.startedAt})`,
    lastStatus: sql<string | null>`(ARRAY_AGG(${discoveryRunsTable.status} ORDER BY ${discoveryRunsTable.startedAt} DESC))[1]`,
  }).from(discoveryRunsTable)
    .groupBy(discoveryRunsTable.source)
    .orderBy(discoveryRunsTable.source);

  const candidateCounts = await db.select({
    source: leadCandidatesTable.source,
    count: count(),
  }).from(leadCandidatesTable)
    .groupBy(leadCandidatesTable.source);

  const candidateCountMap = new Map(candidateCounts.map((c) => [c.source, c.count]));
  const allSources = new Set([...runStats.map((r) => r.source), ...candidateCounts.map((c) => c.source)]);

  const sources = [...allSources].sort().map((source) => {
    const run = runStats.find((r) => r.source === source);
    return {
      source,
      runCount: run?.runCount ?? 0,
      totalFound: run ? Number(run.totalFound) : 0,
      totalAdded: run ? Number(run.totalAdded) : 0,
      lastRunAt: run?.lastRunAt ?? null,
      lastStatus: run?.lastStatus ?? null,
      totalCandidates: candidateCountMap.get(source) ?? 0,
    };
  });

  res.json({ sources });
});

// ─── GET /api/admin-panel/lead-discovery/isp-groups ──────────────────────────
// Kalifikasyonu geçmiş lead'leri normalize edilmiş ISP adına göre gruplar
router.get("/admin-panel/lead-discovery/isp-groups", requireAdmin, async (_req: Request, res: Response) => {
  // Tüm isp_partners pattern'lerini çek
  const partners = await db.select().from(ispPartnersTable).orderBy(asc(ispPartnersTable.partnerName));

  // Qualify'lı lead'leri isp_organization ile çek
  const leads = await db.select({
    id: leadCandidatesTable.id,
    domain: leadCandidatesTable.domain,
    companyName: leadCandidatesTable.companyName,
    riskScore: leadCandidatesTable.riskScore,
    criticalFindings: leadCandidatesTable.criticalFindings,
    ispOrganization: leadCandidatesTable.ispOrganization,
    contactEmail: leadCandidatesTable.contactEmail,
    teaserSentAt: leadCandidatesTable.teaserSentAt,
    lastScannedAt: leadCandidatesTable.lastScannedAt,
    tier: leadCandidatesTable.tier,
  }).from(leadCandidatesTable)
    .where(and(
      eq(leadCandidatesTable.isQualified, true),
      isNotNull(leadCandidatesTable.ispOrganization),
    ))
    .orderBy(desc(leadCandidatesTable.riskScore));

  // Lead'i normalize edilmiş partner adına eşle
  function resolvePartnerName(rawOrg: string): { normalizedName: string; isActivePartnership: boolean; partnerContact: string | null } {
    for (const p of partners) {
      // ILIKE pattern: % wildcard → JS regex
      const regex = new RegExp(p.organizationNamePattern.replace(/%/g, ".*"), "i");
      if (regex.test(rawOrg)) {
        return { normalizedName: p.partnerName, isActivePartnership: p.isActivePartnership, partnerContact: p.partnerContact };
      }
    }
    return { normalizedName: rawOrg, isActivePartnership: false, partnerContact: null };
  }

  // Gruplama
  const groups: Record<string, {
    normalizedName: string;
    isActivePartnership: boolean;
    partnerContact: string | null;
    count: number;
    avgRiskScore: number;
    criticalFindingsTotal: number;
    lastScannedAt: Date | null;
    leads: typeof leads;
  }> = {};

  for (const lead of leads) {
    const raw = lead.ispOrganization ?? "Bilinmiyor";
    const { normalizedName, isActivePartnership, partnerContact } = resolvePartnerName(raw);
    if (!groups[normalizedName]) {
      groups[normalizedName] = {
        normalizedName,
        isActivePartnership,
        partnerContact,
        count: 0,
        avgRiskScore: 0,
        criticalFindingsTotal: 0,
        lastScannedAt: null,
        leads: [],
      };
    }
    const g = groups[normalizedName]!;
    g.count++;
    g.criticalFindingsTotal += lead.criticalFindings ?? 0;
    g.leads.push(lead);
    if (lead.lastScannedAt && (!g.lastScannedAt || lead.lastScannedAt > g.lastScannedAt)) {
      g.lastScannedAt = lead.lastScannedAt;
    }
  }

  // avgRiskScore hesapla
  for (const g of Object.values(groups)) {
    const scores = g.leads.map(l => l.riskScore ?? 0).filter(s => s > 0);
    g.avgRiskScore = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
  }

  // Büyükten küçüğe lead sayısına göre sırala
  const sorted = Object.values(groups).sort((a, b) => b.count - a.count);
  res.json(sorted);
});

// ─── GET /api/admin-panel/lead-discovery/isp-partners ────────────────────────
router.get("/admin-panel/lead-discovery/isp-partners", requireAdmin, async (_req: Request, res: Response) => {
  const rows = await db.select().from(ispPartnersTable).orderBy(asc(ispPartnersTable.partnerName));
  res.json(rows);
});

// ─── POST /api/admin-panel/lead-discovery/isp-partners ───────────────────────
router.post("/admin-panel/lead-discovery/isp-partners", requireAdmin, async (req: Request, res: Response) => {
  const { organizationNamePattern, partnerName, partnerContact } = req.body as {
    organizationNamePattern: string;
    partnerName: string;
    partnerContact?: string;
  };
  if (!organizationNamePattern || !partnerName) {
    res.status(400).json({ error: "organizationNamePattern ve partnerName zorunlu." }); return;
  }
  const [row] = await db.insert(ispPartnersTable).values({
    organizationNamePattern,
    partnerName,
    partnerContact: partnerContact ?? null,
    isActivePartnership: false,
  }).returning();
  res.json(row);
});

// ─── PATCH /api/admin-panel/lead-discovery/isp-partners/:id ──────────────────
router.patch("/admin-panel/lead-discovery/isp-partners/:id", requireAdmin, async (req: Request, res: Response) => {
  const id = parseInt(String(req.params["id"] ?? "0"));
  const { isActivePartnership, partnerContact, partnerName } = req.body as {
    isActivePartnership?: boolean;
    partnerContact?: string;
    partnerName?: string;
  };
  const updates: Partial<{ isActivePartnership: boolean; partnerContact: string; partnerName: string; updatedAt: Date }> = { updatedAt: new Date() };
  if (isActivePartnership !== undefined) updates.isActivePartnership = isActivePartnership;
  if (partnerContact !== undefined) updates.partnerContact = partnerContact;
  if (partnerName !== undefined) updates.partnerName = partnerName;
  const [row] = await db.update(ispPartnersTable).set(updates).where(eq(ispPartnersTable.id, id)).returning();
  if (!row) { res.status(404).json({ error: "Bulunamadı" }); return; }
  res.json(row);
});

// ─── POST /api/admin-panel/lead-discovery/isp-backfill ───────────────────────
// Manuel tetikle: source_data->>'org' alanını isp_organization'a kopyala
router.post("/admin-panel/lead-discovery/isp-backfill", requireAdmin, async (_req: Request, res: Response) => {
  const result = await db.execute(
    sql`UPDATE lead_candidates SET isp_organization = source_data->>'org'
        WHERE isp_organization IS NULL AND source_data->>'org' IS NOT NULL AND source_data->>'org' <> ''`
  );
  res.json({ updated: result.rowCount });
});

// ─── POST /api/admin-panel/lead-discovery/bulk-import-pdf ────────────────────
// PDF listesinden toplu domain import — body: { domains: [...] }
// ON CONFLICT (domain) DO NOTHING — idempotent, tekrar çalıştırılabilir
router.post("/admin-panel/lead-discovery/bulk-import-pdf", requireAdmin, async (req: Request, res: Response) => {
  const { domains } = req.body as {
    domains: Array<{ domain: string; industry: string; revenueUsd: number; employeeRange: string }>;
  };
  if (!Array.isArray(domains) || domains.length === 0) {
    res.status(400).json({ error: "domains array gerekli" });
    return;
  }

  let inserted = 0;
  let skipped = 0;
  const CHUNK = 50;

  for (let i = 0; i < domains.length; i += CHUNK) {
    const chunk = domains.slice(i, i + CHUNK);
    const e = (s: string) => s.replace(/'/g, "''");
    const result = await db.execute(sql`
      INSERT INTO lead_candidates (domain, sector, source, scan_status, tier, is_municipality, source_data, has_kev_match, waf_enrichment_attempts)
      SELECT * FROM unnest(
        ${sql.raw(`ARRAY[${chunk.map(r => `'${e(r.domain)}'`).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(r => `'${e(r.industry)}'`).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(() => `'pdf_import'`).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(() => `'pending'`).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(() => `'tier2'`).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(r => r.domain.endsWith(".bel.tr") ? "true" : "false").join(",")}]`)}::bool[],
        ${sql.raw(`ARRAY[${chunk.map(r => `'${e(JSON.stringify({ industry: r.industry, revenue_usd: r.revenueUsd, employee_range: r.employeeRange }))}'`).join(",")}]`)}::jsonb[],
        ${sql.raw(`ARRAY[${chunk.map(() => "false").join(",")}]`)}::bool[],
        ${sql.raw(`ARRAY[${chunk.map(() => "0").join(",")}]`)}::int[]
      ) AS t(domain, sector, source, scan_status, tier, is_municipality, source_data, has_kev_match, waf_enrichment_attempts)
      ON CONFLICT (domain) DO NOTHING
    `);
    inserted += result.rowCount ?? 0;
    skipped += chunk.length - (result.rowCount ?? 0);
  }

  logger.info({ inserted, skipped, total: domains.length }, "PDF bulk import tamamlandı");
  res.json({ inserted, skipped, total: domains.length });
});

// ─── POST /api/admin-panel/lead-discovery/domain-add ─────────────────────────
// Domain(lar) ekle veya zenginleştir.
// Yeni format: { rows: [{domain, companyName?, sector?, subSector?, sourceList?, listRank?, city?}], source? }
// Eski format (geriye dönük): { domains: string[], source?, sector?, label? }
// ON CONFLICT (domain) DO UPDATE SET ... COALESCE — mevcut veri silinmez, eksik alanlar doldurulur.
router.post("/admin-panel/lead-discovery/domain-add", requireAdmin, async (req: Request, res: Response) => {
  const body = req.body as {
    rows?: Array<{
      domain: string;
      companyName?: string;
      sector?: string;
      subSector?: string;
      sourceList?: string;
      listRank?: string;
      city?: string;
      ticker?: string;
      companyEmail?: string;
      bistIndexes?: string;
      bistMarket?: string;
      address?: string;
    }>;
    domains?: string[];
    source?: string;
    sector?: string;
    label?: string;
  };

  const normalize = (d: string) =>
    d.replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/.*$/, "").trim().toLowerCase();
  const clean = (v: string | null | undefined): string | null =>
    (v?.trim() || null);

  // Normalize input — destekle hem yeni (rows) hem eski (domains) format
  type InputRow = {
    domain: string;
    companyName: string | null;
    sector: string | null;
    subSector: string | null;
    sourceList: string | null;
    listRank: string | null;
    city: string | null;
    ticker: string | null;
    companyEmail: string | null;
    bistIndexes: string | null;
    bistMarket: string | null;
    address: string | null;
    isPublicCompany: boolean;
    isBist30: boolean;
    isBist100: boolean;
    isBist500: boolean;
  };

  let inputRows: InputRow[];
  if (Array.isArray(body.rows) && body.rows.length > 0) {
    inputRows = body.rows.map(r => {
      const tk = clean(r.ticker);
      const bi = clean(r.bistIndexes);
      return {
        domain: normalize(r.domain),
        companyName: clean(r.companyName),
        sector: clean(r.sector),
        subSector: clean(r.subSector),
        sourceList: clean(r.sourceList),
        listRank: clean(r.listRank),
        city: clean(r.city),
        ticker: tk,
        companyEmail: clean(r.companyEmail),
        bistIndexes: bi,
        bistMarket: clean(r.bistMarket),
        address: clean(r.address),
        isPublicCompany: tk != null,
        isBist30:  !!(bi?.includes("BIST 30")),
        isBist100: !!(bi?.includes("BIST 100")),
        isBist500: !!(bi?.includes("BIST 500")),
      };
    }).filter(r => r.domain.length > 0);
  } else if (Array.isArray(body.domains) && body.domains.length > 0) {
    const sec = clean(body.sector);
    inputRows = body.domains.map(d => ({
      domain: normalize(d),
      companyName: null,
      sector: sec,
      subSector: null,
      sourceList: clean(body.label ?? null),
      listRank: null,
      city: null,
      ticker: null,
      companyEmail: null,
      bistIndexes: null,
      bistMarket: null,
      address: null,
      isPublicCompany: false,
      isBist30: false,
      isBist100: false,
      isBist500: false,
    })).filter(r => r.domain.length > 0);
  } else {
    res.status(400).json({ error: "rows veya domains array gerekli" });
    return;
  }

  // Deduplicate by domain
  const seen = new Set<string>();
  inputRows = inputRows.filter(r => { if (seen.has(r.domain)) return false; seen.add(r.domain); return true; });
  if (inputRows.length === 0) {
    res.status(400).json({ error: "Geçerli domain bulunamadı" });
    return;
  }

  const src = clean(body.source) ?? "manual_import";
  const allDomains = inputRows.map(r => r.domain);

  // Mevcut olanları bul
  const existing = await db
    .select({ domain: leadCandidatesTable.domain })
    .from(leadCandidatesTable)
    .where(inArray(leadCandidatesTable.domain, allDomains));
  const existingSet = new Set(existing.map(r => r.domain));

  // Enriched = mevcut domain + en az bir zenginleştirme alanı dolu
  const hasEnrichment = (r: InputRow) =>
    !!(r.companyName || r.sector || r.subSector || r.sourceList || r.listRank || r.city
      || r.ticker || r.companyEmail || r.bistIndexes || r.bistMarket || r.address);

  let inserted = 0;
  let enriched = 0;
  let unchanged = 0;
  const CHUNK = 50;

  const e = (s: string) => s.replace(/'/g, "''");
  const nt = (v: string | null) => v !== null ? `'${e(v)}'` : "NULL";

  for (let i = 0; i < inputRows.length; i += CHUNK) {
    const chunk = inputRows.slice(i, i + CHUNK);
    const meta = JSON.stringify({ label: body.label ?? src });

    const result = await db.execute(sql`
      INSERT INTO lead_candidates
        (domain, company_name, sector, sub_sector, source_list, list_rank, city,
         ticker, company_email, bist_indexes, bist_market, scraped_address,
         source, scan_status, tier, is_municipality, source_data, has_kev_match,
         waf_enrichment_attempts, is_public_company, is_bist30, is_bist100, is_bist500)
      SELECT * FROM unnest(
        ${sql.raw(`ARRAY[${chunk.map(r => `'${e(r.domain)}'`).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(r => nt(r.companyName)).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(r => nt(r.sector)).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(r => nt(r.subSector)).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(r => nt(r.sourceList)).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(r => nt(r.listRank)).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(r => nt(r.city)).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(r => nt(r.ticker)).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(r => nt(r.companyEmail)).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(r => nt(r.bistIndexes)).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(r => nt(r.bistMarket)).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(r => nt(r.address)).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(() => `'${e(src)}'`).join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(() => "'pending'").join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(() => "'tier2'").join(",")}]`)}::text[],
        ${sql.raw(`ARRAY[${chunk.map(r => r.domain.endsWith(".bel.tr") || r.domain.includes(".gov.tr") ? "true" : "false").join(",")}]`)}::bool[],
        ${sql.raw(`ARRAY[${chunk.map(() => `'${e(meta)}'`).join(",")}]`)}::jsonb[],
        ${sql.raw(`ARRAY[${chunk.map(() => "false").join(",")}]`)}::bool[],
        ${sql.raw(`ARRAY[${chunk.map(() => "0").join(",")}]`)}::int[],
        ${sql.raw(`ARRAY[${chunk.map(r => r.isPublicCompany ? "true" : "false").join(",")}]`)}::bool[],
        ${sql.raw(`ARRAY[${chunk.map(r => r.isBist30  ? "true" : "false").join(",")}]`)}::bool[],
        ${sql.raw(`ARRAY[${chunk.map(r => r.isBist100 ? "true" : "false").join(",")}]`)}::bool[],
        ${sql.raw(`ARRAY[${chunk.map(r => r.isBist500 ? "true" : "false").join(",")}]`)}::bool[]
      ) AS t(domain, company_name, sector, sub_sector, source_list, list_rank, city,
             ticker, company_email, bist_indexes, bist_market, scraped_address,
             source, scan_status, tier, is_municipality, source_data, has_kev_match,
             waf_enrichment_attempts, is_public_company, is_bist30, is_bist100, is_bist500)
      ON CONFLICT (domain) DO UPDATE SET
        company_name   = COALESCE(EXCLUDED.company_name,   lead_candidates.company_name),
        sector         = COALESCE(EXCLUDED.sector,         lead_candidates.sector),
        sub_sector     = COALESCE(EXCLUDED.sub_sector,     lead_candidates.sub_sector),
        source_list    = COALESCE(EXCLUDED.source_list,    lead_candidates.source_list),
        list_rank      = COALESCE(EXCLUDED.list_rank,      lead_candidates.list_rank),
        city           = COALESCE(EXCLUDED.city,           lead_candidates.city),
        ticker         = COALESCE(EXCLUDED.ticker,         lead_candidates.ticker),
        company_email  = COALESCE(EXCLUDED.company_email,  lead_candidates.company_email),
        bist_indexes   = COALESCE(EXCLUDED.bist_indexes,   lead_candidates.bist_indexes),
        bist_market    = COALESCE(EXCLUDED.bist_market,    lead_candidates.bist_market),
        scraped_address = COALESCE(EXCLUDED.scraped_address, lead_candidates.scraped_address),
        is_public_company = lead_candidates.is_public_company OR EXCLUDED.is_public_company,
        is_bist30  = lead_candidates.is_bist30  OR EXCLUDED.is_bist30,
        is_bist100 = lead_candidates.is_bist100 OR EXCLUDED.is_bist100,
        is_bist500 = lead_candidates.is_bist500 OR EXCLUDED.is_bist500,
        updated_at = now()
    `);
    inserted += result.rowCount ?? 0;

    // Enriched/unchanged sayacı güncelle
    for (const r of chunk) {
      if (existingSet.has(r.domain)) {
        if (hasEnrichment(r)) enriched++;
        else unchanged++;
      }
    }
  }

  const results = inputRows.map(r => ({
    domain: r.domain,
    status: existingSet.has(r.domain)
      ? (hasEnrichment(r) ? ("enriched" as const) : ("unchanged" as const))
      : ("inserted" as const),
  }));

  logger.info({ inserted, enriched, unchanged, total: inputRows.length, src }, "domain-add tamamlandı");
  res.json({ inserted, enriched, unchanged, skipped: enriched + unchanged, total: inputRows.length, results });
});

// ─── CVE RAPORU ─────────────────────────────────────────────────────────────
// GET /api/admin-panel/lead-discovery/cve-report/export — CSV indirme (önce gelecek)
router.get("/admin-panel/lead-discovery/cve-report/export", requireAdmin, async (req: Request, res: Response) => {
  const minCvss = parseFloat(String(req.query["minCvss"] ?? "7.0"));
  const severityFilter = String(req.query["severity"] ?? "");
  const onlyExploit = req.query["exploit"] === "1";
  const onlyKev = req.query["kev"] === "1";

  const conditions = [gte(cveTrackerTable.cvssScore, String(minCvss))];
  if (severityFilter) conditions.push(eq(cveTrackerTable.severity, severityFilter));
  if (onlyExploit) conditions.push(eq(cveTrackerTable.exploitPublic, true));
  if (onlyKev) conditions.push(eq(cveTrackerTable.cisaKev, true));

  const rows = await db
    .select({
      cveId: cveTrackerTable.cveId,
      cvssScore: cveTrackerTable.cvssScore,
      severity: cveTrackerTable.severity,
      title: cveTrackerTable.title,
      exploitPublic: cveTrackerTable.exploitPublic,
      cisaKev: cveTrackerTable.cisaKev,
      patchAvailable: cveTrackerTable.patchAvailable,
      domain: cveDomainMatchesTable.domain,
      matchedProduct: cveDomainMatchesTable.matchedProduct,
      matchedVersion: cveDomainMatchesTable.matchedVersion,
      confidence: cveDomainMatchesTable.confidence,
      isPatched: cveDomainMatchesTable.isPatched,
    })
    .from(cveTrackerTable)
    .innerJoin(cveDomainMatchesTable, eq(cveDomainMatchesTable.cveId, cveTrackerTable.cveId))
    .where(and(...conditions))
    .orderBy(desc(cveTrackerTable.cvssScore), cveTrackerTable.cveId, cveDomainMatchesTable.domain);

  const header = "CVE ID,CVSS,Severity,Baslik,Exploit,CISA KEV,Yama,Domain,Urun,Versiyon,Guven,Yamalanmis\n";
  const body = rows.map(r =>
    [
      r.cveId,
      r.cvssScore ?? "",
      r.severity ?? "",
      `"${(r.title ?? "").replace(/"/g, '""')}"`,
      r.exploitPublic ? "Evet" : "Hayir",
      r.cisaKev ? "Evet" : "Hayir",
      r.patchAvailable ? "Evet" : "Hayir",
      r.domain,
      `"${(r.matchedProduct ?? "").replace(/"/g, '""')}"`,
      r.matchedVersion ?? "",
      r.confidence ?? "",
      r.isPatched ? "Evet" : "Hayir",
    ].join(",")
  ).join("\n");

  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="cve-raporu-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send("\uFEFF" + header + body); // BOM for Excel Turkish charset
});

// GET /api/admin-panel/lead-discovery/cve-report — CVE listesi + domain detayları
router.get("/admin-panel/lead-discovery/cve-report", requireAdmin, async (req: Request, res: Response) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  const minCvss = parseFloat(String(req.query["minCvss"] ?? "7.0"));
  const severityFilter = String(req.query["severity"] ?? "");
  const onlyExploit = req.query["exploit"] === "1";
  const onlyKev = req.query["kev"] === "1";

  const conditions = [gte(cveTrackerTable.cvssScore, String(minCvss))];
  if (severityFilter) conditions.push(eq(cveTrackerTable.severity, severityFilter));
  if (onlyExploit) conditions.push(eq(cveTrackerTable.exploitPublic, true));
  if (onlyKev) conditions.push(eq(cveTrackerTable.cisaKev, true));

  try {
    // CVE özet listesi — sadece eşleşmesi olan CVE'ler (INNER JOIN)
    const cveList = await db
      .select({
        cveId: cveTrackerTable.cveId,
        cvssScore: cveTrackerTable.cvssScore,
        severity: cveTrackerTable.severity,
        title: cveTrackerTable.title,
        exploitPublic: cveTrackerTable.exploitPublic,
        cisaKev: cveTrackerTable.cisaKev,
        patchAvailable: cveTrackerTable.patchAvailable,
        status: cveTrackerTable.status,
        detectedAt: cveTrackerTable.detectedAt,
        affectedDomainCount: count(cveDomainMatchesTable.id),
      })
      .from(cveTrackerTable)
      .innerJoin(cveDomainMatchesTable, eq(cveDomainMatchesTable.cveId, cveTrackerTable.cveId))
      .where(and(...conditions))
      .groupBy(cveTrackerTable.id)
      .orderBy(desc(cveTrackerTable.cvssScore), desc(count(cveDomainMatchesTable.id)))
      .limit(200);

    if (cveList.length === 0) {
      res.json({ total: 0, cves: [] });
      return;
    }

    // Etkilenen domain detayları — correlated subquery yerine basit JOIN
    // (domain_scans subquery'leri kaldırıldı: domain_scans.domain indexi olmadığında
    //  her eşleşme için full table scan → 5 dk timeout'a yol açıyordu)
    const cveIds = cveList.map(c => c.cveId);
    const domainRows = await db
      .select({
        cveId: cveDomainMatchesTable.cveId,
        domain: cveDomainMatchesTable.domain,
        matchedProduct: cveDomainMatchesTable.matchedProduct,
        matchedVersion: cveDomainMatchesTable.matchedVersion,
        confidence: cveDomainMatchesTable.confidence,
        isPatched: cveDomainMatchesTable.isPatched,
        wafDetected: leadCandidatesTable.wafDetected,
        wafProvider: leadCandidatesTable.wafProvider,
      })
      .from(cveDomainMatchesTable)
      .leftJoin(leadCandidatesTable, eq(leadCandidatesTable.id, cveDomainMatchesTable.leadCandidateId))
      .where(inArray(cveDomainMatchesTable.cveId, cveIds))
      .orderBy(cveDomainMatchesTable.domain);

    // domain listesini CVE'lere bağla
    const domainMap = new Map<string, typeof domainRows>();
    for (const row of domainRows) {
      if (!row.cveId) continue;
      const list = domainMap.get(row.cveId) ?? [];
      list.push(row);
      domainMap.set(row.cveId, list);
    }

    const cves = cveList.map(c => ({
      ...c,
      cvssScore: c.cvssScore != null ? Number(c.cvssScore) : null,
      domains: domainMap.get(c.cveId) ?? [],
    }));

    res.json({ total: cves.length, cves });
  } catch (err: unknown) {
    req.log.error({ err }, "CVE raporu sorgusu başarısız");
    res.status(500).json({ error: "CVE raporu alınamadı." });
  }
});

// POST /api/admin-panel/lead-discovery/rescan-manual-domains
// domain_scans tablosundaki tüm domain'leri lead_candidates'a kopyalar (yoksa) ve
// WAF enrichment + kalifikasyon için sıraya alır. Admin panelden tek tıkla tetiklenir.
router.post("/admin-panel/lead-discovery/rescan-manual-domains", requireAdmin, async (req: Request, res: Response) => {
  try {
    // Distinct domain listesi — test domain'lerini ve geçersiz kayıtları çıkar
    const dsRows = await db.execute(sql`
      SELECT DISTINCT ON (domain) domain, overall_score, waf_detected, waf_provider, waf_confidence, id as scan_id
      FROM domain_scans
      WHERE overall_score > 0
        AND domain NOT LIKE '%.nip.io'
        AND domain NOT LIKE '192%'
        AND domain NOT LIKE '10.%'
      ORDER BY domain, created_at DESC
    `);

    const domains = (dsRows.rows ?? []) as Array<{
      domain: string;
      overall_score: number;
      waf_detected: boolean;
      waf_provider: string | null;
      waf_confidence: number | null;
      scan_id: number;
    }>;

    if (domains.length === 0) {
      res.json({ inserted: 0, reset: 0, total: 0, domains: [] });
      return;
    }

    // lead_candidates'ta olmayan domain'leri bul
    const domainList = domains.map(d => d.domain);
    const existingRows = await db.execute(sql`
      SELECT domain FROM lead_candidates WHERE domain = ANY(${domainList})
    `);
    const existingSet = new Set((existingRows.rows as { domain: string }[]).map(r => r.domain));

    let inserted = 0;
    let reset = 0;

    for (const row of domains) {
      const isQualified = row.overall_score < 60;

      if (!existingSet.has(row.domain)) {
        // Yoksa ekle — tier2: tekrar tam tarama yapılacak
        await db.execute(sql`
          INSERT INTO lead_candidates
            (domain, source, scan_status, scan_id, risk_score,
             is_qualified, tier, scan_depth, last_scanned_at,
             waf_detected, waf_provider, waf_confidence, waf_enriched_at, waf_enrichment_status,
             created_at, updated_at)
          VALUES
            (${row.domain}, 'manual_scan', 'pending', ${row.scan_id}, ${row.overall_score},
             ${isQualified}, 'tier2', 'full', NOW(),
             ${row.waf_detected ?? null}, ${row.waf_provider ?? null}, ${row.waf_confidence ?? null},
             ${row.waf_detected != null ? sql`NOW()` : sql`NULL`},
             ${row.waf_detected != null ? 'enriched' : null},
             NOW(), NOW())
          ON CONFLICT (domain) DO NOTHING
        `);
        inserted++;
      } else {
        // Var ise scan_status'ı pending'e al (tier2) — yeniden taranacak
        await db.execute(sql`
          UPDATE lead_candidates SET
            scan_status          = 'pending',
            tier                 = 'tier2',
            updated_at           = NOW()
          WHERE domain = ${row.domain}
            AND scan_status NOT IN ('scanning', 'prescreening')
        `);
        reset++;
      }
    }

    res.json({ inserted, reset, total: domains.length, domains: domainList });

    // Arka planda kalifikasyon başlat
    setImmediate(async () => {
      try {
        await qualifyPendingCandidates(domains.length + 10);
        logger.info({ count: domains.length }, "rescan-manual-domains: kalifikasyon tamamlandı");
      } catch (err) {
        logger.error({ err }, "rescan-manual-domains: kalifikasyon hatası");
      }
    });
  } catch (err) {
    logger.error({ err }, "rescan-manual-domains error");
    res.status(500).json({ error: "İşlem başarısız" });
  }
});

// ─── GET /api/admin-panel/lead-discovery/port-risk ────────────────────────────
// included_in_index domain_scans içinde riskli port açık olanları listeler.
// port: 3306 (MySQL), 21 (FTP), 3389 (RDP)
router.get("/admin-panel/lead-discovery/port-risk", requireAdmin, async (req: Request, res: Response) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  try {
    const rows = await db.execute(sql`
      WITH latest AS (
        SELECT DISTINCT ON (domain)
          domain,
          shodan_open_ports,
          overall_score,
          sector,
          city,
          waf_detected,
          waf_provider,
          created_at
        FROM domain_scans
        WHERE included_in_index = true
          AND shodan_open_ports IS NOT NULL
          AND jsonb_array_length(shodan_open_ports) > 0
        ORDER BY domain, created_at DESC
      )
      SELECT
        domain,
        overall_score,
        sector,
        city,
        waf_detected,
        waf_provider,
        ARRAY(
          SELECT (elem->>'port')::int
          FROM jsonb_array_elements(shodan_open_ports) elem
          WHERE (elem->>'port')::int IN (3306, 21, 3389, 5900, 27017, 6379, 5432, 1433)
        ) as risky_ports,
        (3306 = ANY(ARRAY(SELECT (elem->>'port')::int FROM jsonb_array_elements(shodan_open_ports) elem))) as mysql_open,
        (21 = ANY(ARRAY(SELECT (elem->>'port')::int FROM jsonb_array_elements(shodan_open_ports) elem))) as ftp_open,
        (3389 = ANY(ARRAY(SELECT (elem->>'port')::int FROM jsonb_array_elements(shodan_open_ports) elem))) as rdp_open,
        (5900 = ANY(ARRAY(SELECT (elem->>'port')::int FROM jsonb_array_elements(shodan_open_ports) elem))) as vnc_open,
        (27017 = ANY(ARRAY(SELECT (elem->>'port')::int FROM jsonb_array_elements(shodan_open_ports) elem))) as mongo_open,
        (6379 = ANY(ARRAY(SELECT (elem->>'port')::int FROM jsonb_array_elements(shodan_open_ports) elem))) as redis_open
      FROM latest
      WHERE (
        3306 = ANY(ARRAY(SELECT (elem->>'port')::int FROM jsonb_array_elements(shodan_open_ports) elem))
        OR 21 = ANY(ARRAY(SELECT (elem->>'port')::int FROM jsonb_array_elements(shodan_open_ports) elem))
        OR 3389 = ANY(ARRAY(SELECT (elem->>'port')::int FROM jsonb_array_elements(shodan_open_ports) elem))
        OR 5900 = ANY(ARRAY(SELECT (elem->>'port')::int FROM jsonb_array_elements(shodan_open_ports) elem))
        OR 27017 = ANY(ARRAY(SELECT (elem->>'port')::int FROM jsonb_array_elements(shodan_open_ports) elem))
        OR 6379 = ANY(ARRAY(SELECT (elem->>'port')::int FROM jsonb_array_elements(shodan_open_ports) elem))
      )
      ORDER BY overall_score ASC
      LIMIT 500
    `);

    type PortRiskRow = {
      domain: string; overall_score: number; sector: string | null; city: string | null;
      waf_detected: boolean | null; waf_provider: string | null;
      risky_ports: number[]; mysql_open: boolean; ftp_open: boolean; rdp_open: boolean;
      vnc_open: boolean; mongo_open: boolean; redis_open: boolean;
    };
    const domains = (rows.rows ?? []) as PortRiskRow[];

    const summary = {
      total: domains.length,
      mysql: domains.filter(d => d.mysql_open).length,
      ftp:   domains.filter(d => d.ftp_open).length,
      rdp:   domains.filter(d => d.rdp_open).length,
      vnc:   domains.filter(d => d.vnc_open).length,
      mongo: domains.filter(d => d.mongo_open).length,
      redis: domains.filter(d => d.redis_open).length,
    };

    res.json({ summary, domains });
  } catch (err) {
    req.log.error({ err }, "Port risk sorgusu başarısız");
    res.status(500).json({ error: "Port risk verisi alınamadı." });
  }
});

// ─── POST /api/admin-panel/lead-discovery/bist-retag ─────────────────────────
// Mevcut lead_candidates kayıtlarını ticker/bistIndexes bilgisiyle etiketler.
// Body: { rows: [{ domain, ticker, bistIndexes, bistMarket }] }
// Sadece UPDATE yapar — yeni kayıt eklemez.
router.post("/admin-panel/lead-discovery/bist-retag", requireAdmin, async (req: Request, res: Response) => {
  try {
    type RetagRow = { domain?: string; ticker?: string; bistIndexes?: string; bistMarket?: string };
    const rows: RetagRow[] = Array.isArray(req.body?.rows) ? req.body.rows : [];
    if (rows.length === 0) return void res.status(400).json({ error: "rows boş" });

    const normalize = (d: string) =>
      d.replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/.*$/, "").trim().toLowerCase();
    const clean = (v: string | null | undefined): string | null => (v?.trim() || null);

    let updated = 0;
    const notFound: string[] = [];

    for (const r of rows) {
      if (!r.domain) continue;
      const domain = normalize(r.domain);
      const ticker = clean(r.ticker);
      const bi = clean(r.bistIndexes);
      const bm = clean(r.bistMarket);
      const isPublic = ticker != null;
      const isBist30  = !!(bi?.toUpperCase().includes("BIST 30"));
      const isBist100 = !!(bi?.toUpperCase().includes("BIST 100"));
      const isBist500 = !!(bi?.toUpperCase().includes("BIST 500"));

      const result = await db.execute(sql`
        UPDATE lead_candidates SET
          ticker            = COALESCE(${ticker}, ticker),
          bist_indexes      = COALESCE(${bi},     bist_indexes),
          bist_market       = COALESCE(${bm},     bist_market),
          is_public_company = is_public_company OR ${isPublic},
          is_bist30         = is_bist30  OR ${isBist30},
          is_bist100        = is_bist100 OR ${isBist100},
          is_bist500        = is_bist500 OR ${isBist500},
          updated_at        = now()
        WHERE domain = ${domain}
      `);
      if ((result.rowCount ?? 0) > 0) updated++;
      else notFound.push(domain);
    }

    req.log.info({ updated, notFound: notFound.length }, "BIST retag tamamlandı");
    res.json({ updated, notFound });
  } catch (err) {
    req.log.error(err, "BIST retag hatası");
    res.status(500).json({ error: "BIST retag başarısız" });
  }
});

// ─── GET /api/admin-panel/bist-analysis ──────────────────────────────────────
router.get("/admin-panel/bist-analysis", requireAdmin, async (req: Request, res: Response) => {
  try {
    type SrRow = Record<string, string | null>;

    // --- Özet ---
    const summaryResult = await db.execute<SrRow>(sql`
      SELECT
        COUNT(*)::text                                                                                                      AS total_bist_companies,
        COUNT(CASE WHEN lc.domain IS NOT NULL THEN 1 END)::text                                                            AS with_domain,
        COUNT(CASE WHEN lc.scan_id IS NOT NULL THEN 1 END)::text                                                           AS in_cyberstep_db,
        COUNT(CASE WHEN (COALESCE(ds.critical_cve_count,0)+COALESCE(ds.high_cve_count,0))>0 THEN 1 END)::text             AS with_cve,
        COUNT(CASE WHEN COALESCE(ds.open_ports_count,0)>0 THEN 1 END)::text                                               AS with_open_ports,
        COUNT(CASE WHEN COALESCE(ds.critical_cve_count,0)>0 THEN 1 END)::text                                             AS with_critical_cve,
        ROUND(COALESCE(AVG(NULLIF(ds.open_ports_count,0)),0),1)::text                                                     AS avg_open_ports,
        ROUND(COALESCE(AVG(lc.risk_score),0),1)::text                                                                     AS avg_ai_score
      FROM lead_candidates lc
      LEFT JOIN domain_scans ds ON ds.id = lc.scan_id
      WHERE lc.is_public_company = true
    `);
    const sr = (summaryResult.rows[0] ?? {}) as SrRow;
    const totalBist = parseInt(sr.total_bist_companies ?? "0");
    const withDomain = parseInt(sr.with_domain ?? "0");
    const inDb = parseInt(sr.in_cyberstep_db ?? "0");
    const withCve = parseInt(sr.with_cve ?? "0");
    const summary = {
      total_bist_companies: totalBist,
      with_domain:          withDomain,
      with_domain_pct:      totalBist > 0 ? Math.round(withDomain / totalBist * 100) : 0,
      in_cyberstep_db:      inDb,
      in_cyberstep_db_pct:  totalBist > 0 ? Math.round(inDb / totalBist * 100) : 0,
      with_cve:             withCve,
      with_cve_pct:         totalBist > 0 ? Math.round(withCve / totalBist * 100) : 0,
      with_open_ports:      parseInt(sr.with_open_ports ?? "0"),
      with_critical_cve:    parseInt(sr.with_critical_cve ?? "0"),
      avg_open_ports:       parseFloat(sr.avg_open_ports ?? "0"),
      avg_ai_score:         parseFloat(sr.avg_ai_score ?? "0"),
    };

    // --- Endekse göre ---
    const byIndexResult = await db.execute<SrRow>(sql`
      SELECT
        COUNT(CASE WHEN lc.is_bist30 THEN 1 END)::text AS bist30_total,
        COUNT(CASE WHEN lc.is_bist30 AND (COALESCE(ds.critical_cve_count,0)+COALESCE(ds.high_cve_count,0))>0 THEN 1 END)::text AS bist30_with_cve,
        COALESCE(SUM(CASE WHEN lc.is_bist30 THEN ds.critical_cve_count ELSE 0 END),0)::text AS bist30_critical_cve,
        ROUND(COALESCE(AVG(CASE WHEN lc.is_bist30 THEN lc.risk_score END),0),1)::text AS bist30_avg_score,
        COUNT(CASE WHEN lc.is_bist100 THEN 1 END)::text AS bist100_total,
        COUNT(CASE WHEN lc.is_bist100 AND (COALESCE(ds.critical_cve_count,0)+COALESCE(ds.high_cve_count,0))>0 THEN 1 END)::text AS bist100_with_cve,
        COALESCE(SUM(CASE WHEN lc.is_bist100 THEN ds.critical_cve_count ELSE 0 END),0)::text AS bist100_critical_cve,
        ROUND(COALESCE(AVG(CASE WHEN lc.is_bist100 THEN lc.risk_score END),0),1)::text AS bist100_avg_score,
        COUNT(CASE WHEN lc.is_bist500 THEN 1 END)::text AS bist500_total,
        COUNT(CASE WHEN lc.is_bist500 AND (COALESCE(ds.critical_cve_count,0)+COALESCE(ds.high_cve_count,0))>0 THEN 1 END)::text AS bist500_with_cve,
        COALESCE(SUM(CASE WHEN lc.is_bist500 THEN ds.critical_cve_count ELSE 0 END),0)::text AS bist500_critical_cve,
        ROUND(COALESCE(AVG(CASE WHEN lc.is_bist500 THEN lc.risk_score END),0),1)::text AS bist500_avg_score
      FROM lead_candidates lc
      LEFT JOIN domain_scans ds ON ds.id = lc.scan_id
      WHERE lc.is_public_company = true
    `);
    const bi = (byIndexResult.rows[0] ?? {}) as SrRow;
    const by_index = {
      bist30:  { total: parseInt(bi.bist30_total  ?? "0"), with_cve: parseInt(bi.bist30_with_cve  ?? "0"), avg_ai_score: parseFloat(bi.bist30_avg_score  ?? "0"), critical_cve_count: parseInt(bi.bist30_critical_cve  ?? "0") },
      bist100: { total: parseInt(bi.bist100_total ?? "0"), with_cve: parseInt(bi.bist100_with_cve ?? "0"), avg_ai_score: parseFloat(bi.bist100_avg_score ?? "0"), critical_cve_count: parseInt(bi.bist100_critical_cve ?? "0") },
      bist500: { total: parseInt(bi.bist500_total ?? "0"), with_cve: parseInt(bi.bist500_with_cve ?? "0"), avg_ai_score: parseFloat(bi.bist500_avg_score ?? "0"), critical_cve_count: parseInt(bi.bist500_critical_cve ?? "0") },
    };

    // --- Sektöre göre ---
    const sectorResult = await db.execute<SrRow>(sql`
      SELECT
        COALESCE(lc.sector,'Diğer') AS sector,
        COUNT(*)::text AS total,
        COUNT(CASE WHEN (COALESCE(ds.critical_cve_count,0)+COALESCE(ds.high_cve_count,0))>0 THEN 1 END)::text AS with_cve,
        COALESCE(SUM(ds.critical_cve_count),0)::text AS critical_cve_count,
        ROUND(COALESCE(AVG(ds.open_ports_count),0),1)::text AS avg_open_ports,
        ROUND(COALESCE(AVG(lc.risk_score),0),1)::text AS avg_ai_score
      FROM lead_candidates lc
      LEFT JOIN domain_scans ds ON ds.id = lc.scan_id
      WHERE lc.is_public_company = true
      GROUP BY 1
      ORDER BY COALESCE(AVG(lc.risk_score),100) ASC, COUNT(*) DESC
    `);
    const by_sector = (sectorResult.rows ?? []).map((r: SrRow) => {
      const avgScore = parseFloat(r.avg_ai_score ?? "0");
      return {
        sector:             String(r.sector ?? "Diğer"),
        total:              parseInt(r.total ?? "0"),
        with_cve:           parseInt(r.with_cve ?? "0"),
        critical_cve_count: parseInt(r.critical_cve_count ?? "0"),
        avg_open_ports:     parseFloat(r.avg_open_ports ?? "0"),
        avg_ai_score:       avgScore,
        risk_level:         avgScore < 30 ? "Yüksek" : avgScore < 60 ? "Orta" : "Düşük",
      };
    });

    // --- Pazara göre ---
    const marketResult = await db.execute<SrRow>(sql`
      SELECT
        COALESCE(lc.bist_market,'Bilinmiyor') AS market,
        COUNT(*)::text AS total,
        ROUND(COALESCE(AVG(lc.risk_score),0),1)::text AS avg_ai_score,
        COUNT(CASE WHEN COALESCE(ds.critical_cve_count,0)>0 THEN 1 END)::text AS with_critical_cve
      FROM lead_candidates lc
      LEFT JOIN domain_scans ds ON ds.id = lc.scan_id
      WHERE lc.is_public_company = true
      GROUP BY 1
      ORDER BY COUNT(*) DESC
    `);
    const by_market = (marketResult.rows ?? []).map((r: SrRow) => ({
      market:            String(r.market ?? "Bilinmiyor"),
      total:             parseInt(r.total ?? "0"),
      avg_ai_score:      parseFloat(r.avg_ai_score ?? "0"),
      with_critical_cve: parseInt(r.with_critical_cve ?? "0"),
    }));

    // --- En riskli şirketler (düşük skor = yüksek risk) ---
    type TopRiskSrRow = SrRow & { cve_summary_raw?: string };
    const topRiskResult = await db.execute<TopRiskSrRow>(sql`
      SELECT
        lc.ticker,
        COALESCE(lc.company_name, lc.scraped_company_name) AS company_name,
        lc.domain,
        lc.sector,
        lc.bist_market,
        lc.risk_score::text AS ai_score,
        COALESCE(ds.critical_cve_count,0)::text AS critical_cve_count,
        COALESCE(ds.open_ports_count,0)::text AS open_ports_count,
        ds.cve_summary::text AS cve_summary_raw
      FROM lead_candidates lc
      LEFT JOIN domain_scans ds ON ds.id = lc.scan_id
      WHERE lc.is_public_company = true AND lc.risk_score IS NOT NULL
      ORDER BY lc.risk_score ASC
      LIMIT 20
    `);
    type CveItem = { service: string; cveId: string; description: string; cvssScore: number };
    const top_risk_companies = (topRiskResult.rows ?? []).map((r: TopRiskSrRow) => {
      const aiScore = parseInt(r.ai_score ?? "0");
      let cve_list: CveItem[] = [];
      try {
        const raw: CveItem[] = r.cve_summary_raw ? JSON.parse(r.cve_summary_raw) : [];
        cve_list = raw.filter(c => c.cvssScore >= 9.0).sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0));
      } catch { /* ignore parse errors */ }
      return {
        ticker:             String(r.ticker ?? ""),
        company_name:       String(r.company_name ?? ""),
        domain:             String(r.domain ?? ""),
        sector:             String(r.sector ?? ""),
        market:             String(r.bist_market ?? ""),
        ai_score:           aiScore,
        critical_cve_count: parseInt(r.critical_cve_count ?? "0"),
        open_ports_count:   parseInt(r.open_ports_count ?? "0"),
        risk_level:         aiScore < 30 ? "Yüksek" : aiScore < 60 ? "Orta" : "Düşük",
        cve_list,
      };
    });

    // --- Kritik CVE'li BIST şirketleri (drill-down için) ---
    type CritSrRow = SrRow & { cve_summary_raw?: string; is_bist30?: string; is_bist100?: string; is_bist500?: string };
    const criticalCveResult = await db.execute<CritSrRow>(sql`
      SELECT
        lc.ticker,
        COALESCE(lc.company_name, lc.scraped_company_name) AS company_name,
        lc.domain,
        lc.sector,
        lc.bist_market,
        lc.is_bist30::text AS is_bist30,
        lc.is_bist100::text AS is_bist100,
        lc.is_bist500::text AS is_bist500,
        COALESCE(ds.critical_cve_count,0)::text AS critical_cve_count,
        ds.cve_summary::text AS cve_summary_raw
      FROM lead_candidates lc
      LEFT JOIN domain_scans ds ON ds.id = lc.scan_id
      WHERE lc.is_public_company = true AND COALESCE(ds.critical_cve_count,0) > 0
      ORDER BY ds.critical_cve_count DESC
    `);
    type CveItem2 = { service: string; cveId: string; description: string; cvssScore: number };
    const critical_cve_companies = (criticalCveResult.rows ?? []).map((r: CritSrRow) => {
      let cve_list: CveItem2[] = [];
      try {
        const raw: CveItem2[] = r.cve_summary_raw ? JSON.parse(r.cve_summary_raw) : [];
        cve_list = raw.filter(c => c.cvssScore >= 9.0).sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0));
        if (cve_list.length === 0) {
          cve_list = raw.filter(c => c.cvssScore >= 7.0).sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0));
        }
      } catch { /* ignore */ }
      return {
        ticker:             String(r.ticker ?? ""),
        company_name:       String(r.company_name ?? ""),
        domain:             String(r.domain ?? ""),
        sector:             String(r.sector ?? ""),
        market:             String(r.bist_market ?? ""),
        is_bist30:          r.is_bist30 === "true",
        is_bist100:         r.is_bist100 === "true",
        is_bist500:         r.is_bist500 === "true",
        critical_cve_count: parseInt(r.critical_cve_count ?? "0"),
        cve_list,
      };
    });

    // --- LinkedIn içerik kartları ---
    const highRiskSectors = by_sector.filter(s => s.risk_level === "Yüksek").slice(0, 3);
    const linkedin_cards = [
      {
        id: "bist_genel",
        theme: "cyan",
        title: "BIST Sirketi Siber Risk Ozeti",
        stats: [
          { label: "Halka Acik Sirket", value: String(summary.total_bist_companies) },
          { label: "Siber Risk Tespit", value: `%${summary.with_cve_pct}` },
          { label: "Kritik CVE", value: String(summary.with_critical_cve) },
        ],
      },
      {
        id: "bist_endeks",
        theme: "amber",
        title: "Endekse Gore Risk Profili",
        stats: [
          { label: "BIST 30 Kritik CVE", value: String(by_index.bist30.critical_cve_count) },
          { label: "BIST 100 Kritik CVE", value: String(by_index.bist100.critical_cve_count) },
          { label: "BIST 500 Kritik CVE", value: String(by_index.bist500.critical_cve_count) },
        ],
      },
      {
        id: "bist_sektor",
        theme: "red",
        title: "En Yuksek Riskli Sektorler",
        stats: highRiskSectors.length > 0
          ? highRiskSectors.map(s => ({ label: s.sector, value: `Kritik: ${s.critical_cve_count}` }))
          : [{ label: "Henuz veri yok", value: "" }],
      },
      {
        id: "bist_cta",
        theme: "cyan",
        title: "Sirketinizin Risk Skorunu Ogreniyi",
        stats: [{ label: "cyberstep.io", value: "Ucretsiz Analiz" }],
      },
    ];

    res.json({
      generated_at: new Date().toISOString(),
      summary,
      by_index,
      by_sector,
      by_market,
      top_risk_companies,
      critical_cve_companies,
      linkedin_cards,
    });
  } catch (err) {
    req.log.error({ err }, "BIST analizi başarısız");
    res.status(500).json({ error: "BIST analizi alınamadı." });
  }
});

export default router;
