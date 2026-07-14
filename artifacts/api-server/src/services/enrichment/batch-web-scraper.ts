/**
 * Batch Web Contact & Company Intelligence Scraper
 *
 * lead_candidates tablosundaki tarif bekleyen domain'leri saatlik 4 partide işler.
 * Tamamen ücretsiz — AI çağrısı yok.
 *
 * Rate limiting kararları:
 *   CONCURRENCY=5 (10'dan düşürüldü): Natro/Turhost gibi paylaşımlı hosting
 *   sağlayıcılarına paralel çok istek göndermeyi önler. Aynı IP bloğundan gelen
 *   trafik abuse sayılıp server IP'yi blacklist'e sokabilir — bu CyberStep'in
 *   kendi izlediği Spamhaus/SURBL listelerine düşmek demek.
 *
 *   INTER_CHUNK_DELAY: 5 domain'lik her chunk'tan sonra 300-600ms bekle.
 *   User-Agent: CyberStep-Bot/1.0 +https://cyberstep.io/bot (web-scraper.ts)
 *
 * Resumable tasarım:
 *   SELECT ... FOR UPDATE SKIP LOCKED ile atomik batch claim → in_progress
 *   Server restart/crash sonrası stale in_progress satırlar resetlenir.
 *   WHERE: NULL | failed | 90 günden eski scraped (tazeleme döngüsü)
 *
 * Throughput: BATCH_SIZE=200, CONCURRENCY=5, her 15 dk → ~400/saat
 */

import { sql } from "drizzle-orm";
import { db } from "@workspace/db";
import { logger } from "../../lib/logger";
import { scrapeDomain } from "./web-scraper";

const BATCH_SIZE        = 200;
const CONCURRENCY       = 5;                    // Hosting sağlayıcısı koruması
const BATCH_DEADLINE_MS = 18 * 60 * 1000;       // 18 dk (wrapCron watchdog 25dk)
const INTER_CHUNK_DELAY = () => 300 + Math.random() * 300; // 300-600ms jitter
const REFRESH_DAYS      = 90;                   // Kaç günde bir yeniden tara

const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

export interface WebScrapeBatchResult {
  processed: number;
  scraped: number;
  no_data: number;
  failed: number;
  cost_estimate_usd: number;
}

// ─── Ana Batch Fonksiyonu ─────────────────────────────────────────────────────

export async function runWebScrapeBatch(): Promise<WebScrapeBatchResult> {
  const stats = { processed: 0, scraped: 0, no_data: 0, failed: 0 };
  const batchStart = Date.now();

  // Atomik batch claim: SELECT ... FOR UPDATE SKIP LOCKED + hemen in_progress işaretle
  // Bu sayede crash/restart sonrası aynı domain çift işlenmez.
  const rows = await db.execute<{
    id: number;
    domain: string;
    company_name: string | null;
    scraped_company_name: string | null;
  }>(sql`
    WITH claimed AS (
      SELECT id
      FROM lead_candidates
      WHERE is_alive IS TRUE
        AND (
          web_scrape_status IS NULL
          OR web_scrape_status = 'failed'
          OR (
            web_scrape_status = 'scraped'
            AND web_scraped_at < NOW() - INTERVAL '${sql.raw(String(REFRESH_DAYS))} days'
          )
        )
      ORDER BY
        CASE
          WHEN source = 'certstream-bridge' THEN 1
          WHEN source = 'crt_sh' OR source = 'crtsh' THEN 2
          ELSE 3
        END,
        created_at ASC
      LIMIT ${BATCH_SIZE}
      FOR UPDATE SKIP LOCKED
    )
    UPDATE lead_candidates lc
    SET web_scrape_status = 'in_progress'
    FROM claimed
    WHERE lc.id = claimed.id
    RETURNING lc.id, lc.domain, lc.company_name, lc.scraped_company_name
  `);

  const candidates = rows.rows;
  logger.info({ count: candidates.length }, "Web scrape batch başladı");

  if (candidates.length === 0) {
    return { ...stats, cost_estimate_usd: 0 };
  }

  // ─── Concurrency ile işle ────────────────────────────────────────────────
  for (let i = 0; i < candidates.length; i += CONCURRENCY) {
    if (Date.now() - batchStart > BATCH_DEADLINE_MS) {
      logger.warn(
        { processed: stats.processed, remaining: candidates.length - stats.processed },
        "Web scrape: 18dk deadline aşıldı, kalan domainler bir sonraki çalışmaya bırakılıyor",
      );
      // Deadline'a takılan in_progress satırları failed'e döndür — sonraki tur retry eder
      const remaining = candidates.slice(i + CONCURRENCY);
      if (remaining.length > 0) {
        const ids = remaining.map(r => r.id);
        await db.execute(sql`
          UPDATE lead_candidates
          SET web_scrape_status = 'failed', web_scraped_at = NOW()
          WHERE id = ANY(${ids})
        `).catch(() => { /* sessiz hata — zaten failed kalır */ });
      }
      break;
    }

    const chunk = candidates.slice(i, i + CONCURRENCY);

    // ─── Faz 1: HTTP fetch'leri eş zamanlı yap (DB bağlantısı tutma) ──────────
    // DB yazımları fetch sırasında YAPILMAZ — uzun HTTP timeout'ları DB
    // bağlantılarını boşta tutup "connection terminated" hatasına yol açıyordu.
    type FetchResult =
      | { id: number; domain: string; status: "no_data"; httpStatus: number | null }
      | { id: number; domain: string; status: "scraped"; httpStatus: number | null; result: Awaited<ReturnType<typeof scrapeDomain>>["data"] & object }
      | { id: number; domain: string; status: "fetch_error"; err: unknown };

    const fetchResults = await Promise.all(chunk.map(async (row): Promise<FetchResult> => {
      const companyName = row.company_name ?? row.scraped_company_name ?? null;
      try {
        const { httpStatus, data: result } = await scrapeDomain(row.domain, companyName);
        if (!result) return { id: row.id, domain: row.domain, status: "no_data", httpStatus };
        return { id: row.id, domain: row.domain, status: "scraped", httpStatus, result };
      } catch (err) {
        return { id: row.id, domain: row.domain, status: "fetch_error", err };
      }
    }));

    // ─── Faz 2: DB yazımları sıralı yap (bağlantı pool koruması) ─────────────
    for (const fr of fetchResults) {
      try {
        if (fr.status === "no_data") {
          await db.execute(sql`
            UPDATE lead_candidates
            SET web_scrape_status = 'no_data',
                web_scraped_at    = NOW(),
                http_status       = ${fr.httpStatus}
            WHERE id = ${fr.id}
          `);
          stats.no_data++;
        } else if (fr.status === "scraped") {
          const { result } = fr;
          const now = new Date();
          await db.execute(sql`
            UPDATE lead_candidates SET
              web_scrape_status      = 'scraped',
              web_scraped_at         = ${now},
              http_status            = ${fr.httpStatus},
              web_scrape_source_url  = ${result.sourceUrl},

              -- İletişim (mevcut veriler korunur, yeni veri varsa ekle)
              scraped_phone          = COALESCE(scraped_phone,        ${result.phone}),
              scraped_address        = COALESCE(scraped_address,      ${result.address}),
              scraped_company_name   = COALESCE(scraped_company_name, ${result.companyName}),
              web_scrape_email       = COALESCE(web_scrape_email,     ${result.email}),

              -- Şirket profili (regex tabanlı, ücretsiz)
              company_founded_year   = COALESCE(company_founded_year, ${result.foundedYear}),
              is_b2b                 = ${result.isB2b},
              has_ecommerce          = ${result.hasEcommerce},
              has_kvkk_page          = ${result.hasKvkkPage},
              has_careers_page       = ${result.hasCareersPage},
              cms_detected           = COALESCE(cms_detected,         ${result.cmsDetected}),
              social_linkedin_url    = COALESCE(social_linkedin_url,  ${result.linkedinUrl}),
              social_instagram_url   = COALESCE(social_instagram_url, ${result.instagramUrl}),

              -- Coğrafya: web scrape (ücretsiz regex) > mevcut değer
              city                   = COALESCE(city, ${result.city}),

              -- KVKK PII sınıflandırması
              pii_classification     = ${result.piiClassification},

              -- Sektör: mevcut (Haiku/AI) veri varsa koru, sadece boşları doldur
              sector                 = COALESCE(sector, ${result.sector}),
              sector_confidence      = CASE
                WHEN sector IS NULL AND ${result.sector} IS NOT NULL
                  THEN ${result.sectorConfidence !== null ? String(result.sectorConfidence) : null}::numeric
                ELSE sector_confidence
              END,
              enrichment_status      = CASE
                WHEN sector IS NULL AND ${result.sector} IS NOT NULL THEN 'enriched'
                ELSE enrichment_status
              END,
              enrichment_method      = CASE
                WHEN sector IS NULL AND ${result.sector} IS NOT NULL THEN 'web_scrape'
                ELSE enrichment_method
              END

            WHERE id = ${fr.id}
          `);
          // ─── KVKK accountability log ────────────────────────────────────────
          const hasPii = !!(result.email || result.phone || result.address);
          if (hasPii) {
            await db.execute(sql`
              INSERT INTO data_processing_log
                (lead_candidate_id, domain, data_collected, pii_classification, source_url)
              VALUES (
                ${fr.id},
                ${fr.domain},
                ${JSON.stringify({ email: !!result.email, phone: !!result.phone, address: !!result.address })},
                ${result.piiClassification},
                ${result.sourceUrl}
              )
            `).catch(() => { /* log kaydı başarısız olsa da scrape verisi korunur */ });
          }
          stats.scraped++;
        } else {
          // fetch_error
          logger.warn({ domain: fr.domain, err: fr.err }, "Web scrape domain hatası");
          await db.execute(sql`
            UPDATE lead_candidates
            SET web_scrape_status = 'failed',
                web_scraped_at    = NOW()
            WHERE id = ${fr.id}
          `);
          stats.failed++;
        }
      } catch (dbErr) {
        logger.warn({ domain: fr.domain, err: dbErr }, "Web scrape DB yazma hatası");
        // DB yazma başarısız — in_progress kalır, stale cleanup sonraki çalışmada retry eder
        stats.failed++;
      }
      stats.processed++;
    }

    // Rate limiting: hosting sağlayıcısı koruması için chunk'lar arası jitter
    if (i + CONCURRENCY < candidates.length) {
      await sleep(INTER_CHUNK_DELAY());
    }
  }

  const cost_estimate_usd = 0;
  logger.info({ ...stats }, "Web scrape batch tamamlandı");
  return { ...stats, cost_estimate_usd };
}

// ─── Startup Temizlik Fonksiyonları ───────────────────────────────────────────

/**
 * is_alive=FALSE olan domainleri hemen 'no_data' yap — HTTP çekmeye gerek yok.
 */
export async function markDeadDomainsNoData(): Promise<number> {
  const result = await db.execute<{ count: string }>(sql`
    WITH updated AS (
      UPDATE lead_candidates
      SET web_scrape_status = 'no_data',
          web_scraped_at    = NOW()
      WHERE web_scrape_status IS NULL
        AND is_alive IS FALSE
      RETURNING id
    )
    SELECT COUNT(*) AS count FROM updated
  `);
  return parseInt((result.rows[0] as { count: string })?.count ?? "0", 10);
}

/**
 * Stale in_progress satırları temizler.
 * Process crash/restart sonrası 2 saatten eski in_progress satırlar
 * failed'e döndürülür — bir sonraki batch retry eder.
 */
export async function resetStaleInProgress(): Promise<number> {
  const result = await db.execute<{ count: string }>(sql`
    WITH updated AS (
      UPDATE lead_candidates
      SET web_scrape_status = 'failed'
      WHERE web_scrape_status = 'in_progress'
        AND web_scraped_at IS NOT NULL
        AND web_scraped_at < NOW() - INTERVAL '2 hours'
      RETURNING id
    )
    SELECT COUNT(*) AS count FROM updated
  `);
  const count = parseInt((result.rows[0] as { count: string })?.count ?? "0", 10);
  if (count > 0) {
    logger.info({ count }, "Stale in_progress web scrape satırları failed'e döndürüldü");
  }
  return count;
}
