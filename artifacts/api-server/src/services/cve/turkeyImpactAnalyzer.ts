import { db, cveTrackerTable, cveDomainMatchesTable, customerTechStackTable, domainScansTable } from "@workspace/db";
import { eq, ilike, and, sql, isNotNull } from "drizzle-orm";
import { logger } from "../../lib/logger";
import type { CVEEntry } from "./cveFeedReader";

export interface TurkeyImpactResult {
  totalAffected: number;
  criticalAffected: number;
  sectorBreakdown: Record<string, number>;
  cityBreakdown: Record<string, number>;
  topDomains: Array<{ domain: string; matchedProduct: string; confidence: number }>;
}

// ── CVE Ürün Kategorisi ────────────────────────────────────────────────────
type CveProdCategory =
  | "browser"       // Chrome, Firefox, Safari, Edge, V8, Gecko, WebKit
  | "os"            // Windows, Linux, Android, iOS, macOS, kernel
  | "hardware"      // Firmware, BIOS, UEFI, router, switch
  | "network-device"// FortiGate, Palo Alto, Cisco IOS, Junos
  | "web-server"    // Apache, Nginx, IIS, Tomcat, JBoss
  | "database"      // MySQL, PostgreSQL, MongoDB, Redis, Oracle
  | "cms"           // WordPress, Drupal, Joomla, Magento
  | "library"       // OpenSSL, log4j, Spring, curl, Jackson
  | "mobile"        // WhatsApp, Instagram, Facebook, Telegram, Signal — mobil uygulama CVE'leri
  | "application";  // genel uygulama (catch-all)

/**
 * CPE part tipi (a/o/h) sunucu tarafı alaka kontrolü için kullanılır.
 * "o" (OS) ve "h" (hardware) CVE'leri domain eşleştirmesinden kesinlikle elenmelidir.
 * Sadece "a" (application) ve "*" (belirsiz) eşleştirmeye sokulur.
 */
export function isCpeServerSideEligible(cpePart?: string): boolean {
  if (!cpePart || cpePart === "*" || cpePart === "a") return true;
  return false; // "o" (os) veya "h" (hardware) → elenir
}

/**
 * CVE affected product'ı kategorilendirir.
 * Vendor + product birleşimindeki anahtar kelimelere göre sınıflandırır.
 * İkinci savunma katmanı: CPE part tipi isCpeServerSideEligible() ile daha önce kontrol edilmeli.
 */
export function classifyCveProduct(vendor: string, product: string): CveProdCategory {
  const t = `${vendor} ${product}`.toLowerCase().replace(/_/g, " ");

  if (/\b(chrome|chromium|v8|gecko|webkit|firefox|safari|edge|opera|internet.?explorer|trident|blink)\b/.test(t))
    return "browser";

  if (/\b(windows|linux|android|ios\b|macos|mac os|ubuntu|debian|centos|red.?hat|rhel|fedora|kernel|freebsd|openbsd|solaris)\b/.test(t))
    return "os";

  if (/\b(firmware|bios|uefi|bootloader|baseboard|ipmi|idrac|ilo)\b/.test(t))
    return "hardware";

  if (/\b(fortigate|fortios|fortiweb|fortimanager|palo.?alto|panorama|cisco (ios|asa|nx-os)|junos|juniper|aruba|extreme)\b/.test(t))
    return "network-device";

  if (/\b(apache|nginx|iis|tomcat|jboss|weblogic|websphere|lighttpd|caddy|gunicorn|httpd)\b/.test(t))
    return "web-server";

  if (/\b(mysql|postgresql|mongodb|redis|elasticsearch|oracle (database|db)|mssql|sql server|sqlite|mariadb|influxdb|cassandra|couchdb)\b/.test(t))
    return "database";

  if (/\b(wordpress|drupal|joomla|magento|typo3|prestashop|opencart|woocommerce)\b/.test(t))
    return "cms";

  if (/\b(openssl|libssl|curl\b|log4j|log4shell|spring|struts|jackson|zlib|libpng|freetype|shiro|xstream|bouncycastle|bouncy.castle)\b/.test(t))
    return "library";

  // Bilinen mobil uygulama CVE'leri — sunucu tarafı bir web hizmetiyle eşleşemez.
  // WhatsApp VOIP/RCE açıkları (CVE-2019-3568 vb.), Facebook, Instagram, Signal,
  // Telegram, TikTok gibi uygulamalar domain taraması kapsamı dışındadır.
  if (/\b(whatsapp|instagram|facebook\b|messenger\b|signal\b|telegram\b|tiktok|snapchat|twitter\b|wechat|viber|skype\b|line\s+messenger)\b/.test(t))
    return "mobile";

  // Google Pixel — mobil cihaz; GPU/kernel driver açıkları sunucu altyapısıyla ilgisiz.
  if (/\bgoogle\s+pixel\b|\bpixel\s+\d|\bgpixel\b/.test(t))
    return "mobile";

  // Microsoft masaüstü Office uygulamaları — web sunucusu kapsamı dışında.
  // NOT: "Exchange Server" ve "SharePoint Server" sunucu ürünüdür — bu listede YOK.
  if (/\bmicrosoft\s+(word|excel|powerpoint|onenote|visio|access\b|publisher)\b/.test(t))
    return "mobile"; // client-side desktop uygulama olarak işaretle

  return "application";
}

/**
 * Shadow IT servis kategorisini (Türkçe DB değeri) genel türe çevirir.
 * domain_scans.shadow_it_services[].category alanı Türkçe saklanıyor.
 */
function normalizeShadowCategory(shadowCategory: string): string {
  const c = (shadowCategory ?? "").toLowerCase();
  if (c.includes("kütüphane")) return "library";
  if (c.includes("analitik")) return "analytics";
  if (c.includes("cdn") || c.includes("güvenlik / cdn")) return "cdn";
  if (c.includes("güvenlik")) return "security";
  if (c.includes("cms")) return "cms";
  if (c.includes("e-ticaret")) return "ecommerce";
  if (c.includes("pazarlama")) return "marketing";
  if (c.includes("tasarım")) return "design";
  if (c.includes("iletişim") || c.includes("medya") || c.includes("canlı destek")) return "communication";
  if (c.includes("yapay zeka") || c.includes("ai")) return "ai";
  if (c.includes("ödeme") || c.includes("randevu")) return "payment";
  return "other";
}

/**
 * CVE kategorisi ile shadow IT servis kategorisi uyumlu mu?
 *
 * Dönen değerler:
 *   compatible: false → eşleşme tamamen reddet
 *   confidenceDelta: negatif → confidence'ı düşür
 *   note: string → cve_domain_matches.match_note alanına yaz
 */
function checkCategoryCompatibility(
  cveCategory: CveProdCategory,
  shadowType: string,
): { compatible: boolean; confidenceDelta: number; note?: string } {
  // ── Kesinlikle uyumsuz: browser/OS/hardware/mobil uygulama/ağ cihazı CVE'si
  //    web teknoloji shadow IT servisiyle eşleşemez
  if (cveCategory === "browser") {
    return { compatible: false, confidenceDelta: -100,
      note: "BROWSER CVE — sunucu tarafı shadow IT eşleşmesi geçersiz" };
  }
  if (cveCategory === "os") {
    return { compatible: false, confidenceDelta: -100,
      note: "İŞLETİM SİSTEMİ CVE — web servisi shadow IT eşleşmesi geçersiz" };
  }
  if (cveCategory === "hardware") {
    return { compatible: false, confidenceDelta: -100,
      note: "DONANIM/FİRMWARE CVE — web servisi eşleşmesi geçersiz" };
  }
  if (cveCategory === "mobile") {
    return { compatible: false, confidenceDelta: -100,
      note: "MOBİL UYGULAMA CVE — WhatsApp/Facebook/Instagram gibi mobil uygulamalar web servisi kapsamı dışında" };
  }
  if (cveCategory === "network-device") {
    // Ağ cihazı CVE'si yalnızca güvenlik/CDN kategorisinde bir anlam taşıyabilir
    if (shadowType === "cdn" || shadowType === "security") {
      return { compatible: true, confidenceDelta: -20,
        note: "AĞ CİHAZI CVE — CDN/güvenlik eşleşmesi — manuel doğrulama önerilir" };
    }
    return { compatible: false, confidenceDelta: -100,
      note: "AĞ CİHAZI CVE — web servisi shadow IT eşleşmesi geçersiz" };
  }

  // ── Tam uyumlu kombinasyonlar
  if (cveCategory === "cms" && shadowType === "cms") {
    return { compatible: true, confidenceDelta: +10 }; // bonus: kesin eşleşme
  }
  if (cveCategory === "library" && shadowType === "library") {
    return { compatible: true, confidenceDelta: +5 };
  }
  if (cveCategory === "web-server" && (shadowType === "cdn" || shadowType === "security")) {
    return { compatible: true, confidenceDelta: 0 };
  }

  // ── Kısmen uyumlu / belirsiz kombinasyonlar — düşük güven + not
  if (cveCategory === "database" && ["library", "cms", "ecommerce"].includes(shadowType)) {
    return { compatible: true, confidenceDelta: -15,
      note: "VERİTABANI CVE — dolaylı eşleşme, manuel doğrulama gerekli" };
  }
  if (cveCategory === "application") {
    return { compatible: true, confidenceDelta: -15,
      note: "Genel uygulama CVE — kategori belirsiz, manuel doğrulama önerilir" };
  }

  // ── Diğer tüm kombinasyonlar: uyumsuz ama agresif reddetme
  return { compatible: true, confidenceDelta: -25,
    note: `${cveCategory.toUpperCase()} CVE — ${shadowType} kategorisi uyuşmuyor, doğrulama gerekli` };
}

/** Simple version comparison without semver — returns true if currentVersion falls in [start, end) */
function isVersionVulnerable(
  currentVersion: string,
  startInclusive?: string,
  endExclusive?: string,
): boolean {
  if (!startInclusive && !endExclusive) return true;
  try {
    const parse = (v: string) => v.split(".").map(p => parseInt(p.replace(/[^0-9]/g, "")) || 0);
    const cmp = (a: number[], b: number[]): number => {
      for (let i = 0; i < Math.max(a.length, b.length); i++) {
        const diff = (a[i] ?? 0) - (b[i] ?? 0);
        if (diff !== 0) return diff;
      }
      return 0;
    };
    const curr = parse(currentVersion);
    if (startInclusive && cmp(curr, parse(startInclusive)) < 0) return false;
    if (endExclusive && cmp(curr, parse(endExclusive)) >= 0) return false;
    return true;
  } catch {
    return true;
  }
}

export async function analyzeTurkeyImpact(cve: CVEEntry): Promise<TurkeyImpactResult> {
  await db.update(cveTrackerTable).set({
    status: "scanning",
    trScanStartedAt: new Date(),
  }).where(eq(cveTrackerTable.cveId, cve.cveId));

  const matchMap = new Map<string, {
    domain: string;
    customerId: number | null;
    leadCandidateId: number | null;
    matchedProduct: string;
    matchedVersion: string | null;
    confidence: number;
    matchNote: string | null;
  }>();

  // ── 1. customer_tech_stack eşleştirmesi ───────────────────────────────────
  // Önemli: customer_tech_stack.vendor = servis adı ("Google Analytics / Tag Manager"),
  // CVE.vendor = firma adı ("Google"). Bunları ilike ile çapraz eşleştirmek yanlış.
  // Çözüm: sadece CVE.product ile tech stack vendor (servis adı) eşleştirilir.
  for (const product of cve.affectedProducts) {
    const pLower = (product.product ?? "").toLowerCase().replace(/_/g, " ").trim();
    if (pLower.length < 4) continue; // Çok kısa ürün adları çok geniş eşleşir

    // CPE part tipi kontrolü — katman 1: OS/hardware CVE'lerini keyword sınıflandırmasına sokmadan ele
    if (!isCpeServerSideEligible(product.cpePart)) {
      logger.debug({ cveId: cve.cveId, cpePart: product.cpePart, product: product.product }, "CPE part=o/h — tech stack eşleştirmesinden elendi");
      continue;
    }

    const cveCategory = classifyCveProduct(product.vendor ?? "", product.product ?? "");

    // Browser/OS/hardware/mobile CVE'leri tech stack'te hiç eşleştirilmez — katman 2: keyword kontrolü
    if (["browser", "os", "hardware", "mobile"].includes(cveCategory)) continue;

    const rows = await db.select({
      domain: customerTechStackTable.domain,
      customerId: customerTechStackTable.customerId,
      leadCandidateId: customerTechStackTable.leadCandidateId,
      vendor: customerTechStackTable.vendor,
      product: customerTechStackTable.product,
      version: customerTechStackTable.version,
      confidence: customerTechStackTable.confidence,
    }).from(customerTechStackTable).where(
      and(
        // Sadece ürün adı eşleştirmesi — vendor-match çok geniş, false positive üretir
        ilike(customerTechStackTable.vendor, `%${product.product!.replace(/_/g, " ")}%`),
        and(
          sql`${customerTechStackTable.leadCandidateId} IS NOT NULL OR ${customerTechStackTable.customerId} IS NOT NULL`,
        ),
      )
    );

    for (const row of rows) {
      if (product.versionEndExcluding && row.version) {
        if (!isVersionVulnerable(row.version, product.versionStartIncluding, product.versionEndExcluding)) continue;
      }

      const existing = matchMap.get(row.domain);
      const conf = row.confidence ?? 50;
      if (!existing || conf > existing.confidence) {
        matchMap.set(row.domain, {
          domain: row.domain,
          customerId: row.customerId ?? null,
          leadCandidateId: row.leadCandidateId ?? null,
          matchedProduct: `${row.vendor ?? ""} ${row.product ?? ""}`.trim(),
          matchedVersion: row.version ?? null,
          confidence: conf,
          matchNote: null,
        });
      }
    }
  }

  // ── 2. domain_scans.shadow_it_services eşleştirmesi ──────────────────────
  // customer_tech_stack'e girmeyen (manuel taranmış) domain'leri de kapsar.
  {
    const trDomains = await db.select({
      domain: domainScansTable.domain,
      shadowItServices: domainScansTable.shadowItServices,
    }).from(domainScansTable);

    for (const scan of trDomains) {
      if (!scan.domain || matchMap.has(scan.domain)) continue;
      const services = (scan.shadowItServices ?? []) as Array<{ name: string; category: string; version?: string }>;
      if (services.length === 0) continue;

      for (const product of cve.affectedProducts) {
        const pLower = (product.product ?? "").toLowerCase().replace(/_/g, " ").trim();
        if (pLower.length < 4) continue;

        // CPE part tipi kontrolü — katman 1: OS/hardware CVE'lerini shadow IT eşleştirmesinden ele
        if (!isCpeServerSideEligible(product.cpePart)) continue;

        const cveCategory = classifyCveProduct(product.vendor ?? "", product.product ?? "");

        const matched = services.find(s => s.name.toLowerCase().includes(pLower));
        if (!matched) continue;

        const shadowType = normalizeShadowCategory(matched.category ?? "");
        const compat = checkCategoryCompatibility(cveCategory, shadowType);

        if (!compat.compatible) {
          logger.debug(
            { domain: scan.domain, cveCategory, shadowType, note: compat.note },
            "CVE-shadow IT kategori uyumsuzluğu — eşleşme reddedildi",
          );
          continue;
        }

        const finalConfidence = Math.max(0, Math.min(100, 75 + compat.confidenceDelta));

        matchMap.set(scan.domain, {
          domain: scan.domain,
          customerId: null,
          leadCandidateId: null,
          matchedProduct: matched.name,
          matchedVersion: matched.version ?? null,
          confidence: finalConfidence,
          matchNote: compat.note ?? null,
        });
        break;
      }
    }
  }

  const matches = Array.from(matchMap.values());

  if (matches.length > 0) {
    await db.insert(cveDomainMatchesTable).values(
      matches.map(m => ({
        cveId: cve.cveId,
        domain: m.domain,
        customerId: m.customerId ?? undefined,
        leadCandidateId: m.leadCandidateId ?? undefined,
        matchedProduct: m.matchedProduct,
        matchedVersion: m.matchedVersion ?? undefined,
        confidence: m.confidence,
        matchNote: m.matchNote ?? undefined,
      }))
    ).onConflictDoNothing();
  }

  // Sector + city breakdown from lead_candidates table
  const sectorBreakdown: Record<string, number> = {};
  const cityBreakdown: Record<string, number> = {};

  if (matches.length > 0) {
    const { leadCandidatesTable: lct } = await import("@workspace/db");
    for (const m of matches) {
      if (!m.leadCandidateId) continue;
      const [lead] = await db.select({ sector: lct.sector, city: lct.city })
        .from(lct)
        .where(eq(lct.id, m.leadCandidateId));
      if (lead?.sector) sectorBreakdown[lead.sector] = (sectorBreakdown[lead.sector] ?? 0) + 1;
      if (lead?.city) cityBreakdown[lead.city] = (cityBreakdown[lead.city] ?? 0) + 1;
    }
  }

  const criticalThreshold = (cve.cisaKev || cve.exploitPublic) ? 60 : 75;
  const criticalAffected = matches.filter(m => m.confidence >= criticalThreshold).length;
  const topDomains = matches
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 10)
    .map(m => ({ domain: m.domain, matchedProduct: m.matchedProduct, confidence: m.confidence }));

  await db.update(cveTrackerTable).set({
    trAffectedDomains: matches.length,
    trCriticalDomains: criticalAffected,
    trSectorsAffected: sectorBreakdown,
    trTopCities: cityBreakdown,
    trScanCompletedAt: new Date(),
  }).where(eq(cveTrackerTable.cveId, cve.cveId));

  logger.info({ cveId: cve.cveId, totalAffected: matches.length, criticalAffected }, "Türkiye etki analizi tamamlandı");

  return { totalAffected: matches.length, criticalAffected, sectorBreakdown, cityBreakdown, topDomains };
}

/**
 * Retroaktif CVE–domain eşleştirme:
 * Mevcut cve_tracker kayıtlarını domain_scans.shadow_it_services ile tekrar eşleştirir.
 * Günlük cron ile çalışarak yeni eklenen domain_scans kayıtlarını mevcut CVE'lerle eşleştirir.
 */
export async function rematchCveDomains(): Promise<{ newMatches: number; cveCount: number }> {
  const cves = await db.select({
    cveId: cveTrackerTable.cveId,
    affectedProducts: cveTrackerTable.affectedProducts,
  }).from(cveTrackerTable)
    .where(and(
      sql`${cveTrackerTable.status} != 'detected'`,
      isNotNull(cveTrackerTable.affectedProducts),
      sql`jsonb_array_length(${cveTrackerTable.affectedProducts}) > 0`,
    ));

  if (cves.length === 0) return { newMatches: 0, cveCount: 0 };

  const domainScans = await db.select({
    domain: domainScansTable.domain,
    shadowItServices: domainScansTable.shadowItServices,
  }).from(domainScansTable)
    .where(and(
      isNotNull(domainScansTable.shadowItServices),
      sql`jsonb_array_length(${domainScansTable.shadowItServices}::jsonb) > 0`,
    ));

  if (domainScans.length === 0) return { newMatches: 0, cveCount: cves.length };

  type AffectedProduct = { vendor?: string; product?: string; cpePart?: string; versionStartIncluding?: string; versionEndExcluding?: string };
  type ShadowService = { name: string; category?: string; version?: string };

  let totalNew = 0;
  let processedCves = 0;

  for (const cve of cves) {
    // Event loop starvation koruması: 1392 CVE x 35218 domain gibi büyük veri
    // setlerinde bu senkron döngü saatlerce Node event loop'unu bloke edip diğer
    // cron'ların (örn. lead_qual) tetiklenmesini engelleyebiliyordu. Her 10 CVE'de
    // bir event loop'a kontrolü geri veriyoruz.
    processedCves++;
    if (processedCves % 10 === 0) {
      await new Promise<void>((resolve) => setImmediate(resolve));
    }

    const products = (cve.affectedProducts ?? []) as AffectedProduct[];

    const toInsert: Array<{
      cveId: string;
      domain: string;
      matchedProduct: string;
      matchedVersion?: string;
      confidence: number;
      matchNote?: string;
    }> = [];

    for (const scan of domainScans) {
      const services = (scan.shadowItServices ?? []) as ShadowService[];
      if (services.length === 0) continue;

      for (const product of products) {
        const pLower = (product.product ?? "").toLowerCase().replace(/_/g, " ").trim();
        if (pLower.length < 4) continue;

        // CPE part tipi kontrolü — katman 1: OS/hardware CVE'lerini retroaktif re-match'ten ele
        if (!isCpeServerSideEligible(product.cpePart)) continue;

        const cveCategory = classifyCveProduct(product.vendor ?? "", product.product ?? "");

        const matched = services.find(s => s.name.toLowerCase().includes(pLower));
        if (!matched) continue;

        const shadowType = normalizeShadowCategory(matched.category ?? "");
        const compat = checkCategoryCompatibility(cveCategory, shadowType);
        if (!compat.compatible) continue;

        const finalConfidence = Math.max(0, Math.min(100, 70 + compat.confidenceDelta));

        toInsert.push({
          cveId: cve.cveId,
          domain: scan.domain,
          matchedProduct: matched.name,
          matchedVersion: matched.version,
          confidence: finalConfidence,
          matchNote: compat.note,
        });
        break;
      }
    }

    if (toInsert.length > 0) {
      const result = await db.insert(cveDomainMatchesTable)
        .values(toInsert)
        .onConflictDoNothing();
      totalNew += toInsert.length;

      await db.update(cveTrackerTable)
        .set({ trAffectedDomains: sql`(SELECT COUNT(*)::int FROM cve_domain_matches WHERE cve_id = ${cve.cveId})` })
        .where(eq(cveTrackerTable.cveId, cve.cveId));

      void result;
    }
  }

  logger.info({ totalNew, cveCount: cves.length }, "CVE domain retroaktif re-match tamamlandı");
  return { newMatches: totalNew, cveCount: cves.length };
}
