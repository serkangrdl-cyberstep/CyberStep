/**
 * Arama motoru dorking ile Türk domain keşfi.
 *
 * API key gerektirmez — DuckDuckGo HTML (html.duckduckgo.com/html) arama
 * sonuçlarını scrape eder. .tr uzantılı domainleri lead_candidates tablosuna
 * ekler.
 *
 * Not: Daha önce Bing kullanılıyordu ancak Bing'in HTML yapısı/anti-bot
 * kontrolleri değişti ve scraper sürekli 0 sonuç dönmeye başladı (crawler'a
 * boş/JS-render edilmiş sayfa döndürüyor gibi görünüyor). DuckDuckGo'nun
 * "html" (no-JS, lite) endpoint'i scraping'e daha toleranslı ve sabit bir
 * markup'a sahip.
 *
 * Rate limit: Sorgular arası 5 saniye bekleme, günde 1 kez çalışır.
 * Not: DuckDuckGo HTML yapısı değişirse selector güncellenmesi gerekebilir.
 */
import axios from "axios";
import * as cheerio from "cheerio";
import { db } from "@workspace/db";
import { discoveryRunsTable, leadCandidatesTable } from "@workspace/db";
import { eq, sql } from "drizzle-orm";
import { logger } from "../../lib/logger";
import { shouldExcludeFromPipeline } from "../leadScoringService";

const DUCKDUCKGO_SEARCH_URL = "https://html.duckduckgo.com/html/";
const RATE_LIMIT_MS = 5_000;

const DORK_QUERIES = [
  { q: 'site:com.tr "KVKK" "kurumsal"', label: "KVKK Kurumsal .com.tr" },
  { q: 'site:net.tr "iletişim" "hakkımızda"', label: "Kurumsal .net.tr" },
  { q: 'site:com.tr "ERP" "üretim" OR "imalat"', label: "ERP İmalat .com.tr" },
  { q: 'site:com.tr "Microsoft 365" OR "Office 365"', label: "M365 kullananlar" },
  { q: 'site:com.tr "siber güvenlik" OR "bilgi güvenliği"', label: "Siber güvenlik bilinçli" },
  { q: 'site:org.tr "dernek" OR "vakıf" "kurumsal"', label: "Dernek/Vakıf .org.tr" },
  { q: 'site:com.tr "ISO 27001" OR "bilgi güvenliği yönetim sistemi"', label: "ISO 27001 .com.tr" },
];

function extractRootDomain(hostname: string): string {
  const clean = hostname.replace(/^\*\./, "").toLowerCase();
  const parts = clean.split(".");
  if (parts[parts.length - 1] === "tr" && parts.length >= 3) return parts.slice(-3).join(".");
  return parts.slice(-2).join(".");
}

function parseDomainsFromDuckDuckGoHtml(html: string): string[] {
  const $ = cheerio.load(html);
  const domains: string[] = [];

  $("a.result__a, a.result__url").each((_, el) => {
    const href = $(el).attr("href");
    if (!href) return;
    try {
      // DuckDuckGo html.duckduckgo.com sonuçları çoğu zaman
      // //duckduckgo.com/l/?uddg=<encoded-real-url>&... redirect linki döner.
      const raw = href.startsWith("//") ? `https:${href}` : href;
      const url = new URL(raw, "https://duckduckgo.com");
      let target = url;
      const uddg = url.searchParams.get("uddg");
      if (uddg) {
        target = new URL(decodeURIComponent(uddg));
      }
      const hostname = target.hostname.replace(/^www\./, "");
      if (hostname.endsWith(".tr")) domains.push(hostname);
    } catch {}
  });

  $(".result__url, .result__snippet").each((_, el) => {
    const text = $(el).text().trim().toLowerCase();
    const match = text.match(/([a-z0-9.-]+\.tr)\b/);
    if (match?.[1]) domains.push(match[1]);
  });

  return [...new Set(domains)];
}

export interface SearchDorkingResult {
  runId: number;
  queriesRun: number;
  domainsFound: number;
  addedToLeads: number;
}

export async function runSearchDorking(): Promise<SearchDorkingResult> {
  const [run] = await db.insert(discoveryRunsTable).values({
    source: "search_dorking",
    runParams: { queries: DORK_QUERIES.map(q => q.label) },
    status: "running",
  }).returning();
  const runId = run!.id;

  try {
    const discovered = new Map<string, string>();
    let queriesRun = 0;

    for (const dork of DORK_QUERIES) {
      try {
        const resp = await axios.post(
          DUCKDUCKGO_SEARCH_URL,
          new URLSearchParams({ q: dork.q, kl: "tr-tr" }).toString(),
          {
            headers: {
              "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
              "Accept-Language": "tr-TR,tr;q=0.9",
              "Accept": "text/html,application/xhtml+xml",
              "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout: 15_000,
          },
        );

        const html = typeof resp.data === "string" ? resp.data : "";
        const domains = parseDomainsFromDuckDuckGoHtml(html);

        for (const raw of domains) {
          const root = extractRootDomain(raw);
          if (!root || root.length < 5) continue;
          if (shouldExcludeFromPipeline(root, null).exclude) continue;
          if (!discovered.has(root)) discovered.set(root, dork.label);
        }

        logger.info({ query: dork.label, domainsFound: domains.length }, "Search dorking: sorgu tamamlandı");
        queriesRun++;
      } catch (err: unknown) {
        logger.warn({ query: dork.label, err: String(err) }, "Search dorking: sorgu başarısız, devam ediliyor");
      }

      await new Promise(r => setTimeout(r, RATE_LIMIT_MS));
    }

    let added = 0;
    for (const [domain, queryLabel] of discovered) {
      const inserted = await db.insert(leadCandidatesTable).values({
        domain,
        source: "search_dorking",
        sourceData: { discoveryMethod: "duckduckgo_dorking", query: queryLabel },
        scanStatus: "pending",
      }).onConflictDoUpdate({
        target: leadCandidatesTable.domain,
        set: {
          sourceData: sql`COALESCE(lead_candidates.source_data, excluded.source_data)`,
        },
      }).returning();
      if (inserted.length > 0) added++;
    }

    await db.update(discoveryRunsTable)
      .set({ status: "completed", totalFound: discovered.size, totalAdded: added, completedAt: new Date() })
      .where(eq(discoveryRunsTable.id, runId));

    logger.info({ runId, queriesRun, domainsFound: discovered.size, added }, "Search dorking discovery tamamlandı");
    return { runId, queriesRun, domainsFound: discovered.size, addedToLeads: added };

  } catch (err) {
    await db.update(discoveryRunsTable)
      .set({ status: "failed", errorMessage: String(err) })
      .where(eq(discoveryRunsTable.id, runId));
    throw err;
  }
}
