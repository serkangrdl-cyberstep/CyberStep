/**
 * Katman 2 — Sektör Keyword Enrichment
 *
 * lead_candidates.sector + sector_confidence alanlarını doldurur.
 * Öncelik: TLD kuralı > keyword_multi (2+ eşleşme) > keyword_single (1 eşleşme)
 * Eşleşme yoksa: sector=NULL, sector_confidence=NULL — "Diğer" kullanılmaz.
 *
 * Mevcut yanlış 'teknoloji' kayıtları da yeniden hesaplanır.
 * Her run: önce qualified (is_qualified=true), sonra kalan backlog.
 */
import { sql } from "drizzle-orm";
import { db } from "@workspace/db";
import { logger } from "../lib/logger";

// ─── Sabitler ────────────────────────────────────────────────────────────────
const BATCH_LIMIT = 5000;

// ─── Sektör keyword haritası ─────────────────────────────────────────────────
const SECTOR_KEYWORDS: Record<string, string[]> = {
  "Sağlık":        ["doktor", "klinik", "hastane", "dis", "saglik", "eczane", "ecza", "medikal", "hekim", "poliklinik", "tip"],
  "Lojistik":      ["nakliye", "lojistik", "kargo", "tasima", "tasimacilik", "sevkiyat", "depo", "ambar", "filo"],
  "İnşaat":        ["insaat", "yapi", "beton", "emlak", "konut", "villa", "muhendislik", "mimarlik", "tesisat"],
  "Hukuk":         ["hukuk", "avukat", "noter", "dava", "baro"],
  "Eğitim":        ["okul", "egitim", "kurs", "akademi", "universite", "kolej", "dershane"],
  "Gıda/HoReCa":  ["restoran", "cafe", "yemek", "catering", "lokanta", "pastane", "gida"],
  "Otomotiv":      ["oto", "araba", "arac", "garaj", "karoseri", "lastik"],
  "Finans":        ["muhasebe", "mali", "finans", "yatirim", "sigorta", "borsa"],
  "Tarım":         ["tarim", "bahce", "tohum", "gubre", "hayvan", "ziraat"],
  "Üretim/Sanayi": ["fabrika", "imalat", "uretim", "sanayi", "makine", "metal", "tekstil", "dokuma"],
};

// ─── TLD kural tablosu ───────────────────────────────────────────────────────
const TLD_RULES: { suffix: string; sector: string }[] = [
  { suffix: ".gov.tr",  sector: "Kamu" },
  { suffix: ".bel.tr",  sector: "Belediye" },
  { suffix: ".edu.tr",  sector: "Eğitim" },
  { suffix: ".k12.tr",  sector: "Eğitim" },
  { suffix: ".pol.tr",  sector: "Kamu" },
  { suffix: ".net.tr",  sector: "Telecom/ISP" },
];

// ─── Yardımcı Fonksiyonlar ───────────────────────────────────────────────────

function normalizeTR(text: string): string {
  return text
    .toLowerCase()
    .replace(/ş/g, "s").replace(/ç/g, "c").replace(/ğ/g, "g")
    .replace(/ı/g, "i").replace(/ö/g, "o").replace(/ü/g, "u")
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function domainToSlug(domain: string): string {
  const slug = domain
    .replace(/\.(com|net|org|bel|gov|edu|k12|pol|av|dr|tsk|kep|gen|web|biz|info|name)\.tr$/, "")
    .replace(/\.tr$/, "")
    .replace(/\.com$/, "");
  return normalizeTR(slug.replace(/[-_.]/g, " "));
}

type SectorConfidence = "tld_rule" | "keyword_multi" | "keyword_single";
interface SectorResult { sector: string; confidence: SectorConfidence }

export function inferSector(
  domain: string,
  companyName: string | null,
  scrapedCompanyName: string | null,
): SectorResult | null {
  // 1. TLD kuralı — en yüksek öncelik
  const domainLower = domain.toLowerCase();
  for (const rule of TLD_RULES) {
    if (domainLower.endsWith(rule.suffix)) {
      return { sector: rule.sector, confidence: "tld_rule" };
    }
  }

  // 2. Keyword eşleştirme: domain slug + company name (normalize edilmiş)
  const slug = domainToSlug(domain);
  const nameText = normalizeTR(
    [companyName, scrapedCompanyName].filter(Boolean).join(" ")
  );
  const combined = `${slug} ${nameText}`;

  let bestSector: string | null = null;
  let bestCount = 0;

  for (const [sector, keywords] of Object.entries(SECTOR_KEYWORDS)) {
    const count = keywords.filter(kw => combined.includes(kw)).length;
    if (count > bestCount) {
      bestCount = count;
      bestSector = sector;
    }
  }

  if (bestSector && bestCount >= 2) return { sector: bestSector, confidence: "keyword_multi" };
  if (bestSector && bestCount === 1) return { sector: bestSector, confidence: "keyword_single" };
  return null;
}

// ─── Ana Cron Fonksiyonu ─────────────────────────────────────────────────────

interface SectorEnrichmentResult {
  processed: number;
  updated: number;
  cleared: number;
  skipped: number;
  sectorDistribution: Record<string, number>;
}

export async function runSectorEnrichmentCron(
  priorityQualifiedOnly = false,
): Promise<SectorEnrichmentResult> {
  // Qualified önce, sonra kalan — ORDER BY is_qualified DESC
  // sector_enriched_at IS NULL veya sector='teknoloji' AND sector_confidence IS NULL
  // (eski yanlış atamalar yeniden hesaplanır)
  const rows = await db.execute<{
    id: number;
    domain: string;
    company_name: string | null;
    scraped_company_name: string | null;
    sector: string | null;
    sector_confidence: string | null;
    is_qualified: boolean;
  }>(sql`
    SELECT id, domain, company_name, scraped_company_name, sector, sector_confidence, is_qualified
    FROM lead_candidates
    WHERE (
      sector_enriched_at IS NULL
      OR (sector = 'teknoloji' AND sector_confidence IS NULL)
    )
    ${priorityQualifiedOnly ? sql`AND is_qualified = true` : sql``}
    ORDER BY is_qualified DESC, id ASC
    LIMIT ${BATCH_LIMIT}
  `);

  const candidates = rows.rows;

  if (candidates.length === 0) {
    logger.info("Sektör enrichment: işlenecek kayıt yok");
    return { processed: 0, updated: 0, cleared: 0, skipped: 0, sectorDistribution: {} };
  }

  let updated = 0;
  let cleared = 0;
  let skipped = 0;
  const sectorDist: Record<string, number> = {};

  for (const row of candidates) {
    const result = inferSector(row.domain, row.company_name, row.scraped_company_name);
    const now = new Date();

    if (result) {
      // Eşleşme bulundu → sector + confidence güncelle
      await db.execute(sql`
        UPDATE lead_candidates
        SET sector = ${result.sector},
            sector_confidence = ${result.confidence},
            sector_enriched_at = ${now}
        WHERE id = ${row.id}
      `);
      sectorDist[result.sector] = (sectorDist[result.sector] ?? 0) + 1;
      updated++;
    } else if (row.sector !== null || row.sector_confidence !== null) {
      // Eşleşme yok + mevcut değer var (yanlış atama) → temizle
      await db.execute(sql`
        UPDATE lead_candidates
        SET sector = NULL,
            sector_confidence = NULL,
            sector_enriched_at = ${now}
        WHERE id = ${row.id}
      `);
      cleared++;
    } else {
      // Eşleşme yok + zaten null → sadece timestamp'i işaretle
      await db.execute(sql`
        UPDATE lead_candidates
        SET sector_enriched_at = ${now}
        WHERE id = ${row.id}
      `);
      skipped++;
    }
  }

  logger.info({
    processed: candidates.length,
    updated,
    cleared,
    skipped,
    sectorDistribution: sectorDist,
  }, "Sektör enrichment batch tamamlandı");

  return {
    processed: candidates.length,
    updated,
    cleared,
    skipped,
    sectorDistribution: sectorDist,
  };
}
