/**
 * Batch Web Contact & Company Intelligence Scraper
 *
 * lead_candidates tablosundaki web_scrape_status=NULL ve is_alive=TRUE olan
 * domainleri saatlik 4 partide işler. Tamamen ücretsiz — AI çağrısı yok.
 *
 * Throughput hedefi:
 *   BATCH_SIZE=200, CONCURRENCY=10, her 15 dakika → 800/saat → ~4.5 gün backlog
 */

import { sql } from "drizzle-orm";
import { db } from "@workspace/db";
import { logger } from "../../lib/logger";
import { scrapeDomain } from "./web-scraper";

const BATCH_SIZE = 200;
const CONCURRENCY = 10;
const BATCH_DEADLINE_MS = 18 * 60 * 1000; // 18 dk (wrapCron watchdog 25dk)

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

  // is_alive=TRUE domainleri öncelik sırasına göre al
  const rows = await db.execute<{
    id: number;
    domain: string;
    company_name: string | null;
    scraped_company_name: string | null;
  }>(sql`
    SELECT id, domain, company_name, scraped_company_name
    FROM lead_candidates
    WHERE web_scrape_status IS NULL
      AND is_alive IS TRUE
    ORDER BY
      CASE
        WHEN source = 'certstream-bridge' THEN 1
        WHEN source = 'crt_sh' OR source = 'crtsh' THEN 2
        ELSE 3
      END,
      created_at ASC
    LIMIT ${BATCH_SIZE}
  `);

  const candidates = rows.rows;
  logger.info({ count: candidates.length }, "Web scrape batch başladı");

  if (candidates.length === 0) {
    return { ...stats, cost_estimate_usd: 0 };
  }

  // ─── Concurrency ile işle ────────────────────────────────────────────────
  for (let i = 0; i < candidates.length; i += CONCURRENCY) {
    // Duvar saati limiti kontrolü
    if (Date.now() - batchStart > BATCH_DEADLINE_MS) {
      logger.warn(
        { processed: stats.processed, remaining: candidates.length - stats.processed },
        "Web scrape: 18dk deadline aşıldı, kalan domainler bir sonraki çalışmaya bırakılıyor",
      );
      break;
    }

    const chunk = candidates.slice(i, i + CONCURRENCY);

    await Promise.all(chunk.map(async (row) => {
      const companyName = row.company_name ?? row.scraped_company_name ?? null;

      try {
        const result = await scrapeDomain(row.domain, companyName);

        if (!result) {
          await db.execute(sql`
            UPDATE lead_candidates
            SET web_scrape_status = 'no_data',
                web_scraped_at    = NOW()
            WHERE id = ${row.id}
          `);
          stats.no_data++;
        } else {
          const now = new Date();

          await db.execute(sql`
            UPDATE lead_candidates SET
              web_scrape_status      = 'scraped',
              web_scraped_at         = ${now},
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

              -- Sektör: web scrape bulursa haiku adımına gerek yok
              sector                 = COALESCE(sector, ${result.sector}),
              enrichment_status      = CASE
                WHEN sector IS NULL AND ${result.sector} IS NOT NULL THEN 'enriched'
                ELSE enrichment_status
              END,
              enrichment_method      = CASE
                WHEN sector IS NULL AND ${result.sector} IS NOT NULL THEN 'web_scrape'
                ELSE enrichment_method
              END

            WHERE id = ${row.id}
          `);
          stats.scraped++;
        }
      } catch (err) {
        logger.warn({ domain: row.domain, err }, "Web scrape domain hatası");
        try {
          await db.execute(sql`
            UPDATE lead_candidates
            SET web_scrape_status = 'failed',
                web_scraped_at    = NOW()
            WHERE id = ${row.id}
          `);
        } catch {
          // DB yazma hatası — sonraki cron tekrar dener (web_scrape_status NULL kaldı)
        }
        stats.failed++;
      }

      stats.processed++;
    }));
  }

  const cost_estimate_usd = 0; // Tamamen ücretsiz — AI çağrısı yok

  logger.info({ ...stats }, "Web scrape batch tamamlandı");
  return { ...stats, cost_estimate_usd };
}

// ─── Startup Cleanup ──────────────────────────────────────────────────────────
// is_alive=FALSE olan domainleri hemen 'no_data' yap — HTTP çekmeye gerek yok.
// Server restart'ta bir kez çalışır, 0 satır bulunca otomatik durur.

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
