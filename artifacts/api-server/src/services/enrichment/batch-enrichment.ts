/**
 * Batch Haiku Enrichment
 *
 * lead_candidates tablosundaki enrichment_status='pending' olan domainleri
 * Claude Haiku ile toplu olarak zenginleştirir.
 * Her batch 500 domain; 02:30 gece cron'u veya admin manuel tetikleme ile çalışır.
 */
import { sql } from "drizzle-orm";
import { db } from "@workspace/db";
import { logger } from "../../lib/logger";
import { enrichDomain, normalizeCity } from "./haiku-enrichment";

const BATCH_SIZE = 2000;
const DELAY_MS = 150; // ~6.5 istek/sn — Haiku rate limit güvenli aralığı

function sleep(ms: number) {
  return new Promise<void>(resolve => setTimeout(resolve, ms));
}

export interface BatchResult {
  processed: number;
  enriched: number;
  no_match: number;
  failed: number;
  cost_estimate_usd: number;
}

export async function runEnrichmentBatch(): Promise<BatchResult> {
  const stats = { processed: 0, enriched: 0, no_match: 0, failed: 0 };

  const rows = await db.execute<{
    id: number;
    domain: string;
    company_name: string | null;
    scraped_company_name: string | null;
  }>(sql`
    SELECT id, domain, company_name, scraped_company_name
    FROM lead_candidates
    WHERE enrichment_status = 'pending'
      AND sector IS NULL
    ORDER BY
      CASE
        WHEN source = 'certstream-bridge' THEN 1
        WHEN source = 'crt_sh' OR source = 'crtsh' THEN 2
        ELSE 3
      END,
      id ASC
    LIMIT ${BATCH_SIZE}
  `);

  const candidates = rows.rows;
  logger.info({ count: candidates.length }, "Haiku enrichment batch başladı");

  if (candidates.length === 0) {
    return { ...stats, cost_estimate_usd: 0 };
  }

  for (const row of candidates) {
    const now = new Date();
    try {
      await db.execute(sql`
        UPDATE lead_candidates
        SET enrichment_attempted_at = ${now}
        WHERE id = ${row.id}
      `);

      const companyName = row.company_name ?? row.scraped_company_name ?? null;
      const result = await enrichDomain(row.domain, companyName);

      const completedAt = new Date();
      await db.execute(sql`
        UPDATE lead_candidates
        SET sector                  = COALESCE(sector, ${result.sector}),
            city                    = COALESCE(city, ${result.city}),
            region                  = COALESCE(region, ${result.region}),
            enrichment_status       = ${result.sector ? "enriched" : "no_match"},
            enrichment_method       = 'haiku_inference',
            enrichment_confidence   = ${result.confidence},
            enrichment_completed_at = ${completedAt}
        WHERE id = ${row.id}
      `);

      if (result.sector) stats.enriched++;
      else stats.no_match++;
    } catch (err) {
      logger.warn({ domain: row.domain, err }, "Haiku enrichment hatası");
      await db.execute(sql`
        UPDATE lead_candidates
        SET enrichment_status = 'failed',
            enrichment_attempted_at = ${now}
        WHERE id = ${row.id}
      `);
      stats.failed++;
    }

    stats.processed++;
    await sleep(DELAY_MS);
  }

  // Haiku: ~$0.8/M input + $4/M output. ~200 token/domain → ~$0.00016/domain
  const cost_estimate_usd = stats.processed * 0.00016;

  logger.info({ ...stats, cost_estimate_usd }, "Haiku enrichment batch tamamlandı");
  return { ...stats, cost_estimate_usd };
}
