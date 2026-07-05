/**
 * CTI Feed İzleme Servisi
 *
 * Güvenlik odaklı RSS/Atom feed'lerini her 6 saatte bir kontrol eder.
 * Fortinet PSIRT, VulnCheck Blog, USOM, Anthropic Red Team, vb.
 * Alakalı içerikleri claude-sonnet-4-6 ile değerlendirir.
 */

import { db } from "@workspace/db";
import { intelFeedItemsTable, intelFeedSourcesTable } from "@workspace/db";
import { eq, and, gte, desc } from "drizzle-orm";
import { getClaudeAiFn } from "../ai-client";
import { logger } from "../../lib/logger";

const INTEL_FEEDS = [
  {
    key: "fortinet_psirt",
    name: "Fortinet PSIRT",
    feedUrl: "https://www.fortiguard.com/rss/ir.xml",
    category: "vendor_advisory",
    priority: "critical",
  },
  {
    key: "cisco_security",
    name: "Cisco Security Advisories",
    feedUrl: "https://tools.cisco.com/security/center/psirtrss20.xml",
    category: "vendor_advisory",
    priority: "high",
  },
  {
    key: "vulncheck_blog",
    name: "VulnCheck Blog",
    feedUrl: "https://vulncheck.com/blog/rss",
    category: "exploit_intel",
    priority: "high",
  },
  {
    key: "exploitdb",
    name: "Exploit-DB",
    feedUrl: "https://www.exploit-db.com/rss.xml",
    category: "exploit_intel",
    priority: "medium",
  },
  {
    key: "crowdstrike_blog",
    name: "CrowdStrike Blog",
    feedUrl: "https://www.crowdstrike.com/en-us/blog/feed/",
    category: "threat_actor",
    priority: "medium",
  },
  {
    key: "mandiant_blog",
    name: "Mandiant / Google Cloud Threat Intel",
    feedUrl: "https://cloud.google.com/blog/topics/threat-intelligence/rss",
    category: "threat_actor",
    priority: "medium",
  },
  {
    key: "usom",
    name: "USOM Duyuruları",
    feedUrl: "https://www.usom.gov.tr/rss",
    category: "regulation",
    priority: "high",
  },
  {
    key: "btk",
    name: "BTK Haberler",
    feedUrl: "https://www.btk.gov.tr/haberler/rss",
    category: "regulation",
    priority: "high",
  },
  {
    key: "bleeping_security",
    name: "BleepingComputer",
    feedUrl: "https://www.bleepingcomputer.com/feed/",
    category: "exploit_intel",
    priority: "medium",
  },
] as const;

type FeedPriority = "critical" | "high" | "medium";

interface FeedItem {
  title: string;
  url: string;
  summary: string;
  publishedAt: Date | null;
}

async function parseFeed(feedUrl: string): Promise<FeedItem[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const res = await fetch(feedUrl, {
      signal: controller.signal,
      headers: { "User-Agent": "CyberStep-IntelWatcher/1.0" },
    });
    clearTimeout(timer);
    if (!res.ok) return [];
    const xml = await res.text();

    const items: FeedItem[] = [];
    const itemRx = /<item>([\s\S]*?)<\/item>/g;
    let m: RegExpExecArray | null;
    while ((m = itemRx.exec(xml)) !== null) {
      const block = m[1] ?? "";
      const title = (/<title><!\[CDATA\[([\s\S]*?)\]\]><\/title>|<title>([^<]*)<\/title>/.exec(block)?.[1] ?? "").trim();
      const link  = (/<link>([\s\S]*?)<\/link>/.exec(block)?.[1] ?? "").trim();
      const desc  = (/<description><!\[CDATA\[([\s\S]*?)\]\]><\/description>|<description>([^<]*)<\/description>/.exec(block)?.[1] ?? "").replace(/<[^>]+>/g, "").slice(0, 400).trim();
      const pubRaw = (/<pubDate>([\s\S]*?)<\/pubDate>/.exec(block)?.[1] ?? "").trim();
      const pubAt  = pubRaw ? new Date(pubRaw) : null;
      if (title && link) items.push({ title, url: link, summary: desc, publishedAt: pubAt });
    }
    return items;
  } catch {
    clearTimeout(timer);
    return [];
  }
}

const RELEVANCE_KEYWORDS = [
  "türkiye", "turkey", "kvkk", "btk", "usom",
  "fortinet", "fortigate", "cisco", "palo alto",
  "ransomware", "fidye", "exploit", "vulnerability", "güvenlik",
  "kev", "critical", "rce", "authentication bypass",
];

function quickRelevanceCheck(title: string, summary: string): boolean {
  const text = (title + " " + summary).toLowerCase();
  return RELEVANCE_KEYWORDS.some((k) => text.includes(k));
}

async function classifyWithClaude(
  item: FeedItem,
  category: string,
  priority: FeedPriority,
): Promise<{ relevant: boolean; score: number; tags: string[]; reason: string }> {
  if (priority === "medium" && !quickRelevanceCheck(item.title, item.summary)) {
    return { relevant: false, score: 0, tags: [], reason: "keyword_miss" };
  }

  try {
    const ai = getClaudeAiFn();
    // Timeout guard: yapay zeka çağrısı takılırsa (ağ sorunu vb.) bu cron
    // saatlerce "running" durumunda kilitli kalmasın diye 25sn sınır konuldu.
    const result = await Promise.race([
      ai(`Feed öğesi CyberStep.io için alakalı mı?
CyberStep: Türkiye işletme siber güvenlik SaaS platformu.
Müşteriler: SOC/NOC servisi, CVE izleme, Fortinet entegrasyonu, KVKK uyum.

Başlık: ${item.title}
Özet: ${item.summary?.slice(0, 300) || ""}
Kategori: ${category}

Sadece JSON döndür:
{"relevant":true,"score":0-100,"tags":["fortinet","ransomware","kvkk"],"reason":"1 cümle"}`),
      new Promise<string>((_, reject) =>
        setTimeout(() => reject(new Error("classifyWithClaude timeout")), 25_000),
      ),
    ]);

    const cleaned = result.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const parsed = JSON.parse(cleaned) as { relevant: boolean; score: number; tags: string[]; reason: string };
    return parsed;
  } catch {
    const relevant = priority === "critical" || quickRelevanceCheck(item.title, item.summary);
    return { relevant, score: relevant ? 60 : 10, tags: [], reason: "keyword_fallback" };
  }
}

export interface FeedCheckResult {
  feedsChecked: number;
  newItems: number;
  relevantItems: number;
  highPriorityAlerts: number;
}

export async function checkIntelFeeds(): Promise<FeedCheckResult> {
  const seenSet = new Set<string>();
  const existing = await db.select({ url: intelFeedItemsTable.itemUrl }).from(intelFeedItemsTable);
  existing.forEach((r) => seenSet.add(r.url));

  let newItems = 0;
  let relevantItems = 0;
  let highPriorityAlerts = 0;

  for (const feed of INTEL_FEEDS) {
    try {
      const items = await parseFeed(feed.feedUrl);
      await db.insert(intelFeedSourcesTable).values({
        sourceKey: feed.key,
        name: feed.name,
        feedUrl: feed.feedUrl,
        category: feed.category,
        lastCheckedAt: new Date(),
      }).onConflictDoUpdate({
        target: intelFeedSourcesTable.sourceKey,
        set: { lastCheckedAt: new Date() },
      });

      for (const item of items.slice(0, 20)) {
        if (seenSet.has(item.url)) continue;
        seenSet.add(item.url);

        const classification = await classifyWithClaude(item, feed.category, feed.priority as FeedPriority);

        if (classification.relevant && item.publishedAt) {
          await db.insert(intelFeedSourcesTable).values({
            sourceKey: feed.key,
            name: feed.name,
            feedUrl: feed.feedUrl,
            category: feed.category,
            lastNewItemAt: new Date(),
          }).onConflictDoUpdate({
            target: intelFeedSourcesTable.sourceKey,
            set: { lastNewItemAt: new Date() },
          });
        }

        await db.insert(intelFeedItemsTable).values({
          sourceKey: feed.key,
          itemUrl: item.url,
          title: item.title,
          summary: item.summary,
          publishedAt: item.publishedAt,
          isRelevant: classification.relevant,
          relevanceScore: classification.score,
          relevanceReason: classification.reason,
          tags: classification.tags,
        }).onConflictDoNothing();

        newItems++;
        if (classification.relevant) relevantItems++;
        if (classification.relevant && classification.score >= 80) highPriorityAlerts++;

        await new Promise((r) => setTimeout(r, 300));
      }
    } catch (err) {
      logger.warn({ feedKey: feed.key, err }, "Intel feed kontrol hatası");
    }
  }

  logger.info({ feedsChecked: INTEL_FEEDS.length, newItems, relevantItems, highPriorityAlerts }, "Intel feeds tarandı");
  return { feedsChecked: INTEL_FEEDS.length, newItems, relevantItems, highPriorityAlerts };
}

export async function getRecentRelevantItems(limit = 20) {
  return db.select()
    .from(intelFeedItemsTable)
    .where(eq(intelFeedItemsTable.isRelevant, true))
    .orderBy(desc(intelFeedItemsTable.relevanceScore))
    .limit(limit);
}

export async function getFeedStatus() {
  const sources = await db.select().from(intelFeedSourcesTable);
  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const recentCounts = await db.select({
    sourceKey: intelFeedItemsTable.sourceKey,
  }).from(intelFeedItemsTable)
    .where(gte(intelFeedItemsTable.createdAt, since24h));

  const countMap = recentCounts.reduce<Record<string, number>>((acc, r) => {
    acc[r.sourceKey] = (acc[r.sourceKey] ?? 0) + 1;
    return acc;
  }, {});

  return sources.map((s) => ({
    ...s,
    newToday: countMap[s.sourceKey] ?? 0,
  }));
}
