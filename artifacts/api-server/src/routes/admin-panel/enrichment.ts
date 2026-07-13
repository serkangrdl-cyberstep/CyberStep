/**
 * Admin Panel — Web Scraper Domain Enrichment Endpoints
 *
 * POST /api/admin-panel/enrichment/run             — batch'i fire-and-forget başlat
 * GET  /api/admin-panel/enrichment/status          — istatistik + ilerleme
 * POST /api/admin-panel/enrichment/retry-failed    — failed → pending sıfırla
 * GET  /api/admin-panel/enrichment/dashboard       — sektör/şehir dağılımı + cron geçmişi
 * POST /api/admin-panel/enrichment/normalize-cities — mevcut DB kayıtlarını normalize et
 */
import { Router } from "express";
import type { Request, Response } from "express";
import { sql } from "drizzle-orm";
import { db } from "@workspace/db";
import { requireAdmin } from "./middleware";
import { logger } from "../../lib/logger";

const router = Router();

let batchRunning = false;

router.post("/admin-panel/enrichment/run", requireAdmin, async (_req: Request, res: Response) => {
  if (batchRunning) {
    res.json({ queued: false, message: "Batch zaten çalışıyor, lütfen bekleyin" });
    return;
  }

  batchRunning = true;
  res.json({ queued: true, message: "Batch başlatıldı — 500 domain işlenecek" });

  setImmediate(async () => {
    try {
      const { runEnrichmentBatch } = await import("../../services/enrichment/batch-enrichment");
      const result = await runEnrichmentBatch();
      logger.info({ result }, "Manuel enrichment batch tamamlandı");
    } catch (err) {
      logger.error({ err }, "Manuel enrichment batch hatası");
    } finally {
      batchRunning = false;
    }
  });
});

router.get("/admin-panel/enrichment/status", requireAdmin, async (_req: Request, res: Response) => {
  try {
    const result = await db.execute<{
      total: number;
      pending: number;
      enriched: number;
      no_match: number;
      failed: number;
    }>(sql`
      SELECT
        COUNT(*)                                                    AS total,
        COUNT(*) FILTER (WHERE enrichment_status = 'pending')      AS pending,
        COUNT(*) FILTER (WHERE enrichment_status = 'enriched')     AS enriched,
        COUNT(*) FILTER (WHERE enrichment_status = 'no_match')     AS no_match,
        COUNT(*) FILTER (WHERE enrichment_status = 'failed')       AS failed
      FROM lead_candidates
    `);

    const row = result.rows[0] ?? { total: 0, pending: 0, enriched: 0, no_match: 0, failed: 0 };
    const total = Number(row.total);
    const pending = Number(row.pending);
    const enriched = Number(row.enriched);
    const noMatch = Number(row.no_match);
    const failed = Number(row.failed);
    const done = enriched + noMatch + failed;
    const completionPct = total > 0 ? Math.round((done / total) * 1000) / 10 : 0;
    const estimatedBatches = Math.ceil(pending / 500);
    const estimatedCost = Math.round(total * 0.00016 * 100) / 100;

    res.json({
      total,
      pending,
      enriched,
      no_match: noMatch,
      failed,
      completion_pct: completionPct,
      estimated_remaining_batches: estimatedBatches,
      estimated_cost_usd: estimatedCost,
      batch_running: batchRunning,
    });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

router.post("/admin-panel/enrichment/retry-failed", requireAdmin, async (_req: Request, res: Response) => {
  try {
    const result = await db.execute<{ count: number }>(sql`
      UPDATE lead_candidates
      SET enrichment_status = 'pending',
          enrichment_attempted_at = NULL,
          enrichment_completed_at = NULL
      WHERE enrichment_status = 'failed'
      RETURNING id
    `);
    const count = result.rows.length;
    logger.info({ count }, "Failed enrichment kayıtları pending'e alındı");
    res.json({ reset: count, message: `${count} kayıt yeniden kuyruğa alındı` });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// ─── GET /api/admin-panel/enrichment/dashboard ───────────────────────────────
router.get("/admin-panel/enrichment/dashboard", requireAdmin, async (_req: Request, res: Response) => {
  try {
    const [progress, sectorDist, cityDist, cronHistory, normalizeIssues] = await Promise.all([
      // Genel ilerleme
      db.execute<{
        total: number; sector_filled: number; city_filled: number;
        both_filled: number; enriched: number; pending: number; no_match: number; failed: number;
        last_web_scrape_run: string | null; last_sector_run: string | null;
      }>(sql`
        SELECT
          COUNT(*)                                                               AS total,
          COUNT(*) FILTER (WHERE sector IS NOT NULL AND sector != '')            AS sector_filled,
          COUNT(*) FILTER (WHERE city IS NOT NULL AND city != '')               AS city_filled,
          COUNT(*) FILTER (WHERE sector IS NOT NULL AND sector != ''
                             AND city IS NOT NULL AND city != '')               AS both_filled,
          COUNT(*) FILTER (WHERE enrichment_status = 'enriched')               AS enriched,
          COUNT(*) FILTER (WHERE enrichment_status = 'pending')                AS pending,
          COUNT(*) FILTER (WHERE enrichment_status = 'no_match')               AS no_match,
          COUNT(*) FILTER (WHERE enrichment_status = 'failed')                 AS failed,
          MAX(web_scraped_at)                                                   AS last_web_scrape_run,
          MAX(sector_enriched_at)                                               AS last_sector_run
        FROM lead_candidates
      `),

      // Sektör dağılımı (tüm lead_candidates)
      db.execute<{ sector: string; count: number }>(sql`
        SELECT sector, COUNT(*) AS count
        FROM lead_candidates
        WHERE sector IS NOT NULL AND sector != ''
        GROUP BY sector
        ORDER BY count DESC
        LIMIT 20
      `),

      // Şehir dağılımı — INITCAP(LOWER(...)) ile büyük/küçük harf varyantlarını (İSTANBUL, İstanbul) birleştir
      db.execute<{ city: string; count: number }>(sql`
        SELECT INITCAP(LOWER(city)) AS city, COUNT(*) AS count
        FROM lead_candidates
        WHERE city IS NOT NULL AND city != ''
        GROUP BY INITCAP(LOWER(city))
        ORDER BY count DESC
        LIMIT 20
      `),

      // Son cron çalışmaları (enrichment ile ilgili)
      db.execute<{
        job_name: string; status: string; started_at: string;
        ended_at: string | null; processed_count: number | null; duration_ms: number | null; error_message: string | null;
      }>(sql`
        SELECT job_name, status, started_at, ended_at, processed_count, duration_ms, error_message
        FROM cron_job_runs
        WHERE job_name IN ('haiku_enrichment', 'sector_enrichment', 'waf_enrichment', 'lead_tr_enrich', 'lead_web_enrich')
        ORDER BY started_at DESC
        LIMIT 30
      `),

      // Normalize edilmemiş şehir değerleri (bug check)
      db.execute<{ city: string; count: number }>(sql`
        SELECT city, COUNT(*) AS count
        FROM lead_candidates
        WHERE city IS NOT NULL AND city != ''
          AND city NOT IN (
            'İstanbul','Ankara','İzmir','Bursa','Antalya',
            'Adana','Konya','Gaziantep','Kayseri','Mersin',
            'Eskişehir','Diyarbakır','Samsun','Trabzon','Kocaeli',
            'Manisa','Denizli','Şanlıurfa','Malatya','Balıkesir'
          )
        GROUP BY city
        ORDER BY count DESC
        LIMIT 30
      `),
    ]);

    const p = progress.rows[0] ?? {};

    res.json({
      progress: {
        total:          Number(p.total ?? 0),
        sector_filled:  Number(p.sector_filled ?? 0),
        city_filled:    Number(p.city_filled ?? 0),
        both_filled:    Number(p.both_filled ?? 0),
        enriched:       Number(p.enriched ?? 0),
        pending:        Number(p.pending ?? 0),
        no_match:       Number(p.no_match ?? 0),
        failed:         Number(p.failed ?? 0),
        last_web_scrape_run: p.last_web_scrape_run ?? null,
        last_sector_run:     p.last_sector_run ?? null,
        batch_running:  batchRunning,
      },
      sector_dist: sectorDist.rows.map(r => ({ sector: r.sector, count: Number(r.count) })),
      city_dist:   cityDist.rows.map(r => ({ city: r.city, count: Number(r.count) })),
      cron_history: cronHistory.rows.map(r => ({
        job_name:        r.job_name,
        status:          r.status,
        started_at:      r.started_at,
        ended_at:        r.ended_at,
        processed_count: r.processed_count,
        duration_ms:     r.duration_ms,
        error_message:   r.error_message,
      })),
      normalize_issues: normalizeIssues.rows.map(r => ({ city: r.city, count: Number(r.count) })),
    });
  } catch (err) {
    logger.error({ err }, "Enrichment dashboard hatası");
    res.status(500).json({ error: String(err) });
  }
});

// ─── POST /api/admin-panel/enrichment/normalize-cities ───────────────────────
// Mevcut DB'deki non-canonical şehir adlarını düzeltir (Istanbul→İstanbul vb.)
// CITY_ALIASES map'inden otomatik olarak tüm alias → canonical eşlemelerini uygular.
router.post("/admin-panel/enrichment/normalize-cities", requireAdmin, async (_req: Request, res: Response) => {
  try {
    const { CITY_ALIASES } = await import("../../services/enrichment/haiku-enrichment");

    // Canonical değerleri grupla: canonical → [alias1, alias2, ...]
    const byCanonical = new Map<string, string[]>();
    for (const [alias, canonical] of Object.entries(CITY_ALIASES)) {
      if (!canonical) continue; // null = skip (belirsiz yerler)
      if (alias === canonical.toLowerCase()) continue; // zaten doğru
      const list = byCanonical.get(canonical) ?? [];
      list.push(alias);
      byCanonical.set(canonical, list);
    }

    let totalUpdated = 0;
    const details: Array<{ from: string; to: string; count: number }> = [];

    for (const [canonical, aliases] of byCanonical.entries()) {
      // Hem exact alias hem de orijinal yazım varyantlarını kapsa
      // (alias listesi lowercase — DB'de her case var olabilir)
      // SQL: WHERE LOWER(city) = ANY(ARRAY[...])
      const result = await db.execute<{ id: number; old_city: string }>(sql`
        UPDATE lead_candidates
        SET city = ${canonical},
            region = (SELECT region FROM (VALUES
              ('İstanbul','Marmara'),('Ankara','İç Anadolu'),('İzmir','Ege'),
              ('Bursa','Marmara'),('Antalya','Akdeniz'),('Adana','Akdeniz'),
              ('Konya','Akdeniz'),('Gaziantep','Güneydoğu Anadolu'),('Kayseri','İç Anadolu'),
              ('Mersin','Akdeniz'),('Eskişehir','Marmara'),('Diyarbakır','Güneydoğu Anadolu'),
              ('Samsun','Karadeniz'),('Trabzon','Karadeniz'),('Kocaeli','Marmara'),
              ('Manisa','Ege'),('Denizli','Ege'),('Şanlıurfa','Güneydoğu Anadolu'),
              ('Malatya','Doğu Anadolu'),('Balıkesir','Marmara'),
              ('Adıyaman','Güneydoğu Anadolu'),('Afyonkarahisar','Ege'),('Ağrı','Doğu Anadolu'),
              ('Amasya','Karadeniz'),('Artvin','Karadeniz'),('Aydın','Ege'),
              ('Bilecik','Marmara'),('Bingöl','Doğu Anadolu'),('Bitlis','Doğu Anadolu'),
              ('Bolu','Marmara'),('Burdur','Akdeniz'),('Çanakkale','Marmara'),
              ('Çankırı','İç Anadolu'),('Çorum','Karadeniz'),('Diyarbakır','Güneydoğu Anadolu'),
              ('Düzce','Marmara'),('Edirne','Marmara'),('Elazığ','Doğu Anadolu'),
              ('Erzincan','Doğu Anadolu'),('Erzurum','Doğu Anadolu'),
              ('Giresun','Karadeniz'),('Gümüşhane','Karadeniz'),('Hakkari','Güneydoğu Anadolu'),
              ('Hatay','Akdeniz'),('Iğdır','Doğu Anadolu'),('Isparta','Akdeniz'),
              ('Kahramanmaraş','Akdeniz'),('Karabük','Karadeniz'),('Karaman','Akdeniz'),
              ('Kars','Doğu Anadolu'),('Kastamonu','Karadeniz'),
              ('Kırıkkale','İç Anadolu'),('Kırklareli','Marmara'),('Kırşehir','İç Anadolu'),
              ('Kilis','Güneydoğu Anadolu'),('Kütahya','Ege'),
              ('Mardin','Güneydoğu Anadolu'),('Muğla','Ege'),('Muş','Doğu Anadolu'),
              ('Nevşehir','İç Anadolu'),('Niğde','İç Anadolu'),('Ordu','Karadeniz'),
              ('Osmaniye','Akdeniz'),('Rize','Karadeniz'),('Sakarya','Marmara'),
              ('Siirt','Güneydoğu Anadolu'),('Sinop','Karadeniz'),('Sivas','İç Anadolu'),
              ('Şırnak','Güneydoğu Anadolu'),('Tekirdağ','Marmara'),('Tokat','Karadeniz'),
              ('Tunceli','Doğu Anadolu'),('Uşak','Ege'),('Van','Doğu Anadolu'),
              ('Yalova','Marmara'),('Yozgat','İç Anadolu'),('Zonguldak','Karadeniz')
            ) AS t(city_name, region_name)
            WHERE city_name = ${canonical})
        WHERE LOWER(REPLACE(city, u&'\0307', '')) = ANY(${aliases}::text[])
          AND city != ${canonical}
        RETURNING id, city AS old_city
      `);
      const count = result.rows.length;
      if (count > 0) {
        totalUpdated += count;
        details.push({ from: aliases.join(", "), to: canonical, count });
      }
    }

    logger.info({ totalUpdated, details }, "Şehir normalizasyonu tamamlandı");
    res.json({ updated: totalUpdated, details });
  } catch (err) {
    logger.error({ err }, "Şehir normalizasyon hatası");
    res.status(500).json({ error: String(err) });
  }
});

export default router;
