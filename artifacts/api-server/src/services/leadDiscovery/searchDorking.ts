/**
 * Bing arama motoru dorking ile Türk domain keşfi.
 *
 * API key gerektirmez — Bing arama sonuçlarını scrape eder.
 * .tr uzantılı domainleri lead_candidates tablosuna ekler.
 *
 * Rate limit: Sorgular arası 5 saniye bekleme, günde 1 kez çalışır.
 * Not: Bing HTML yapısı değişirse selector güncellenmesi gerekebilir.
 */
import axios from "axios";
import * as cheerio from "cheerio";
import { db } from "@workspace/db";
import { discoveryRunsTable, leadCandidatesTable } from "@workspace/db";
import { eq, sql } from "drizzle-orm";
import { logger } from "../../lib/logger";
import { shouldExcludeFromPipeline } from "../leadScoringService";

const BING_SEARCH_URL = "https://www.bing.com/search";
const RATE_LIMIT_MS = 5_000;

const DORK_QUERIES = [
  { q: 'site:com.tr "KVKK" "kurumsal"', label: "KVKK Kurumsal .com.tr" },
  { q: 'site:net.tr "iletişim" "hakkımızda"', label: "Kurumsal .net.tr" },
  { q: 'site:com.tr "ERP" "üretim" OR "imalat"', label: "ERP İmalat .com.tr" },
  { q: 'site:com.tr "Microsoft 365" OR "Office 365"', label: "M365 kullananlar" },
  { q: 'site:com.tr "siber güvenlik" OR "bilgi güvenliği"', label: "Siber güvenlik bilinçli" },
];

function extractRootDomain(hostname: string): string {
  const clean = hostname.replace(/^\*\./, "").toLowerCase();
  const parts = clean.split(".");
  if (parts[parts.length - 1] === "tr" && parts.length >= 3) return parts.slice(-3).join(".");
  return parts.slice(-2).join(".");
}

function parseDomainsFromBingHtml(html: string): string[] {
  const $ = cheerio.load(html);
  const domains: string[] = [];

  $("li.b_algo h2 a, li.b_algo .b_title h2 a, #b_results .b_algo h2 a").each((_, el) => {
    const href = $(el).attr("href");
    if (!href) return;
    try {
      const url = new URL(href);
      const hostname = url.hostname.replace(/^www\./, "");
      if (hostname.endsWith(".tr")) domains.push(hostname);
    } catch {}
  });

  $("cite, .b_attribution cite").each((_, el) => {
    const text = $(el).text().trim().toLowerCase();
    const match = text.match(/^([a-z0-9.-]+\.tr)/);
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
        const resp = await axios.get(BING_SEARCH_URL, {
          params: { q: dork.q, count: 50 },
          headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Accept-Language": "tr-TR,tr;q=0.9",
            "Accept": "text/html,application/xhtml+xml",
          },
          timeout: 15_000,
        });

        const html = typeof resp.data === "string" ? resp.data : "";
        const domains = parseDomainsFromBingHtml(html);

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
        sourceData: { discoveryMethod: "bing_dorking", query: queryLabel },
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
