/**
 * Web Contact & Company Intelligence Scraper
 *
 * Bir domain'in web sitesini ziyaret ederek iletişim bilgileri ve şirket
 * profilini çıkarır. Homepage + iletişim + hakkımızda sayfaları →
 * tamamen ücretsiz regex (email/telefon/sosyal/şehir/CMS/B2B).
 *
 * Stratejisi:
 *   1. Homepage  → meta açıklama, başlık, sosyal linkler, CMS, e-ticaret sinyali
 *   2. İletişim  → e-posta, telefon, adres (ilk eşleşen path alınır)
 *   3. Hakkımızda → kuruluş yılı (ilk eşleşen path)
 *   4. HEAD kontrol → /kvkk, /kariyer varlığı
 *   5. Ücretsiz şehir tespiti → 81 il adı metinde regex ile aranır
 */

import { logger } from "../../lib/logger";
import { TURKEY_CITIES, normalizeCity, SECTOR_LIST } from "./haiku-enrichment";

const FETCH_TIMEOUT_MS = 6_000;
const HEAD_TIMEOUT_MS = 4_000;
const MAX_HTML_BYTES = 250_000;

const CONTACT_PATHS = [
  "/iletisim", "/contact", "/bize-ulasin",
  "/iletisim.html", "/contact.html", "/bize-ulasin.html",
  "/iletisim/", "/contact/",
];

const ABOUT_PATHS = [
  "/hakkimizda", "/about", "/hakkinda", "/kurumsal",
  "/hakkimizda.html", "/about.html", "/kurumsal/",
];

const KVKK_PATHS = ["/kvkk", "/gizlilik", "/privacy", "/kvkk.html", "/gizlilik.html"];
const CAREER_PATHS = ["/kariyer", "/jobs", "/is-ilanlari", "/kariyer.html", "/jobs.html", "/ik/"];

// ─── Sonuç tipi ──────────────────────────────────────────────────────────────

export interface WebScrapeResult {
  // İletişim
  phone: string | null;
  address: string | null;
  email: string | null;
  // Şirket Profili
  companyName: string | null;
  foundedYear: number | null;
  isB2b: boolean;
  hasEcommerce: boolean;
  // Sayfa varlık kontrolleri
  hasKvkkPage: boolean;
  hasCareersPage: boolean;
  // Teknoloji
  cmsDetected: string | null;
  // Sosyal
  linkedinUrl: string | null;
  instagramUrl: string | null;
  // Ücretsiz regex tespiti
  city: string | null;
  sector: string | null;
  // Meta
  sourceUrl: string;
}

// ─── HTTP Yardımcıları ────────────────────────────────────────────────────────

const BOT_UA = "Mozilla/5.0 (compatible; CyberStep/1.0; +https://cyberstep.io/bot)";

async function fetchHtml(url: string): Promise<string | null> {
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: {
        "User-Agent": BOT_UA,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate",
      },
      redirect: "follow",
    });
    if (!res.ok) return null;
    const ct = res.headers.get("content-type") ?? "";
    if (!ct.includes("text/html") && !ct.includes("text/plain")) return null;
    const buf = await res.arrayBuffer();
    const slice = buf.byteLength > MAX_HTML_BYTES ? buf.slice(0, MAX_HTML_BYTES) : buf;
    return new TextDecoder("utf-8", { fatal: false }).decode(slice);
  } catch {
    return null;
  }
}

async function headOk(url: string): Promise<boolean> {
  try {
    const res = await fetch(url, {
      method: "HEAD",
      signal: AbortSignal.timeout(HEAD_TIMEOUT_MS),
      headers: { "User-Agent": BOT_UA },
      redirect: "follow",
    });
    return res.ok;
  } catch {
    return false;
  }
}

async function fetchFirstMatch(
  base: string,
  paths: string[],
): Promise<{ url: string; html: string } | null> {
  for (const p of paths) {
    const html = await fetchHtml(`https://${base}${p}`);
    if (html && html.length > 200) return { url: `https://${base}${p}`, html };
  }
  return null;
}

async function anyPathExists(base: string, paths: string[]): Promise<boolean> {
  for (const p of paths) {
    if (await headOk(`https://${base}${p}`)) return true;
  }
  return false;
}

// ─── Regex Çıkarıcılar ────────────────────────────────────────────────────────

const TITLE_RE = /<title[^>]*>([\s\S]*?)<\/title>/i;
const META_DESC_RE = /<meta[^>]*name=["']description["'][^>]*content=["']([^"']{10,500})["']/i;
const OG_DESC_RE = /<meta[^>]*property=["']og:description["'][^>]*content=["']([^"']{10,500})["']/i;
const EMAIL_RE = /\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,10})\b/g;
const PHONE_RE = /(?:\+90[\s\-]?|0090[\s\-]?|0)(?:\(\s*\d{3}\s*\)|\d{3})[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}/g;
const LINKEDIN_RE = /https?:\/\/(?:www\.)?linkedin\.com\/(?:company|in)\/([a-zA-Z0-9\-._À-ÿ%]+)\/?/gi;
const INSTAGRAM_RE = /https?:\/\/(?:www\.)?instagram\.com\/([a-zA-Z0-9._]+)\/?/gi;
const FACEBOOK_RE = /https?:\/\/(?:www\.)?facebook\.com\/([a-zA-Z0-9._\-]+)\/?/gi;
const FOUNDED_RE = /(?:(?:kurul(?:uş|du|an|muş)|since|established|founded)[^\d]{0,25}(\d{4}))|(?:©\s*(\d{4})(?:\s*[-–]\s*\d{4})?)|(?:(\d{4})\s*(?:yılından|yılında kuruldu|'den beri|'dan beri|den beri|dan beri))/i;

const EXCLUDED_EMAIL_PREFIXES = [
  "noreply", "no-reply", "mailer", "bounce", "postmaster",
  "webmaster", "daemon", "abuse", "spam", "unsubscribe",
];
const PREFERRED_EMAIL_PREFIXES = [
  "info", "iletisim", "contact", "bilgi", "satis", "destek",
  "support", "hello", "hizmet",
];

function extractEmails(html: string): string[] {
  const found = new Set<string>();
  const re = new RegExp(EMAIL_RE.source, "g");
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const e = m[1].toLowerCase();
    if (/\.(png|jpg|gif|svg|css|js|ico|woff|ttf|pdf)$/i.test(e)) continue;
    if (e.length > 100) continue;
    found.add(e);
  }
  return Array.from(found);
}

function rankBestEmail(emails: string[]): string | null {
  if (emails.length === 0) return null;
  const clean = emails.filter(e => !EXCLUDED_EMAIL_PREFIXES.some(x => e.startsWith(x + "@")));
  if (clean.length === 0) return null;
  return clean.sort((a, b) => {
    const ai = PREFERRED_EMAIL_PREFIXES.findIndex(p => a.startsWith(p));
    const bi = PREFERRED_EMAIL_PREFIXES.findIndex(p => b.startsWith(p));
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  })[0] ?? null;
}

function extractPhone(html: string): string | null {
  const m = html.match(PHONE_RE);
  if (!m) return null;
  return m[0].replace(/\s+/g, " ").trim();
}

function extractTitle(html: string): string | null {
  const m = html.match(TITLE_RE);
  if (!m) return null;
  const raw = stripHtml(m[1]).trim();
  // "Firma Adı | Ana Sayfa" → "Firma Adı"
  const cleaned = raw.split(/\s*[\|\-–—»]\s*/)[0].trim();
  return cleaned.length > 2 && cleaned.length < 200 ? cleaned : null;
}

function extractMetaDesc(html: string): string | null {
  const m = html.match(META_DESC_RE) ?? html.match(OG_DESC_RE);
  return m ? m[1].trim().slice(0, 500) : null;
}

function extractLinkedin(html: string): string | null {
  LINKEDIN_RE.lastIndex = 0;
  const m = LINKEDIN_RE.exec(html);
  if (!m) return null;
  // Normalize: https://linkedin.com/company/slug
  return `https://www.linkedin.com/company/${m[1]}`;
}

function extractInstagram(html: string): string | null {
  INSTAGRAM_RE.lastIndex = 0;
  const m = INSTAGRAM_RE.exec(html);
  if (!m) return null;
  const slug = m[1];
  if (["p", "reel", "explore", "hashtag", "accounts"].includes(slug)) return null;
  return `https://www.instagram.com/${slug}`;
}

function detectCms(html: string): string | null {
  if (/wp-content\/|wp-includes\//i.test(html)) return "wordpress";
  if (/cdn\.shopify\.com|shopify\.com\/s\//i.test(html)) return "shopify";
  if (/woocommerce|woo-commerce/i.test(html)) return "woocommerce";
  if (/joomla/i.test(html)) return "joomla";
  if (/drupal/i.test(html)) return "drupal";
  if (/magento/i.test(html)) return "magento";
  if (/prestashop/i.test(html)) return "prestashop";
  if (/opencart/i.test(html)) return "opencart";
  if (/squarespace-cdn|squarespace\.com/i.test(html)) return "squarespace";
  if (/wix\.com\/|wixsite\.com/i.test(html)) return "wix";
  if (/webflow\.io|webflow\.com/i.test(html)) return "webflow";
  return null;
}

function detectEcommerce(html: string): boolean {
  return /sepete[\s\-_]?ekle|add[\s\-_]?to[\s\-_]?cart|checkout|ödeme\s+yap|woocommerce|shopify|magento|prestashop|opencart|sepetim\b/i.test(html);
}

function detectB2b(html: string): boolean {
  return /\b(?:kurumsal|toptan|bayilik|bayi(?:ler)?|toptanc[ıi]|b2b|wholesale|distribut(?:or|ör)|teklif\s+al|sipari[şs]\s+formu|kurumsal\s+sat[ıi][şs])\b/i.test(html);
}

function extractFoundedYear(html: string): number | null {
  const m = html.match(FOUNDED_RE);
  if (!m) return null;
  const yr = parseInt((m[1] ?? m[2] ?? m[3] ?? "0"), 10);
  const now = new Date().getFullYear();
  return yr >= 1900 && yr <= now ? yr : null;
}

function extractAddress(text: string): string | null {
  const m = text.match(/([A-ZÇĞİÖŞÜa-zçğışöşü0-9][^.\n]{5,20}(?:Mah\.|Cad\.|Sokak|Sok\.|Blv\.|Bulvarı)[^.\n]{5,80})/i);
  return m ? m[0].replace(/\s+/g, " ").trim().slice(0, 300) : null;
}

function stripHtml(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&nbsp;/g, " ")
    .replace(/&#\d+;/g, " ")
    .replace(/\s{2,}/g, " ")
    .trim();
}

// ─── Ücretsiz Sektör Tespiti ─────────────────────────────────────────────────
// Her sektör için anahtar kelimeler — metin içinde kaç tane eşleşirse o kadar puan alır.
// En yüksek puanlı sektör seçilir (min 2 eşleşme şartı).

const SECTOR_KEYWORDS: Record<string, string[]> = {
  "Teknoloji & Yazılım": [
    "yazılım", "bilişim", "siber güvenlik", "siber", "cloud", "bulut",
    "uygulama", "platform", "saas", "erp", "crm", "hosting", "sunucu",
    "veri merkezi", "dijital dönüşüm", "otomasyon", "yapay zeka", "ai",
    "network", "altyapı", "entegrasyon", "api",
  ],
  "E-ticaret & Perakende": [
    "e-ticaret", "e ticaret", "mağaza", "alışveriş", "sepete ekle",
    "sepetim", "ürün kataloğu", "kargo", "teslimat", "indirim",
    "online satış", "b2c", "trendyol", "n11", "hepsiburada",
  ],
  "Finans & Bankacılık": [
    "banka", "bankacılık", "finans", "finansal", "sigorta",
    "kredi", "leasing", "faktoring", "yatırım", "borsa",
    "fon", "portföy", "muhasebe", "ödeme sistemi", "pos",
  ],
  "Sağlık & Klinik": [
    "hastane", "klinik", "sağlık", "tıp", "doktor", "hekim",
    "eczane", "ilaç", "ameliyat", "poliklinik", "diş", "dental",
    "diyaliz", "röntgen", "mri", "laboratuvar", "hasta",
  ],
  "Eğitim & Üniversite": [
    "okul", "üniversite", "eğitim", "kurs", "sertifika",
    "öğrenci", "öğretmen", "akademi", "kolej", "dershane",
    "mba", "lisans", "yüksek lisans", "öğretim",
  ],
  "İnşaat & Gayrimenkul": [
    "inşaat", "yapı", "gayrimenkul", "emlak", "konut",
    "villa", "daire", "proje geliştirme", "müteahhit", "tadilat",
    "mimarlık", "mimari", "yapılaşma", "arsa", "rezidans",
  ],
  "Üretim & Sanayi": [
    "üretim", "sanayi", "fabrika", "imalat", "montaj",
    "makine", "ekipman", "çelik", "metal", "plastik",
    "ambalaj", "kalıp", "bant", "endüstriyel",
  ],
  "Lojistik & Taşımacılık": [
    "lojistik", "taşımacılık", "nakliye", "kargo", "liman",
    "filo", "ulaştırma", "ithalat", "ihracat", "gümrük",
    "depolama", "sevkiyat", "freight", "kurye",
  ],
  "Turizm & Otelcilik": [
    "otel", "turizm", "tatil", "rezervasyon", "tur",
    "seyahat", "konaklama", "spa", "resort", "pansiyon",
    "apart", "villa kiralama", "incoming",
  ],
  "Medya & Yayıncılık": [
    "medya", "yayın", "gazete", "dergi", "haber",
    "televizyon", "radyo", "dijital medya", "reklam ajansı",
    "içerik", "prodüksiyon", "reklam",
  ],
  "Hukuk & Danışmanlık": [
    "hukuk", "avukat", "avukatlık", "danışmanlık", "mali müşavir",
    "denetim", "vergi", "noter", "yönetim danışmanlığı",
    "muhasebe", "audit", "hukuki",
  ],
  "Kamu & Belediye": [
    "belediye", "kamu", "bakanlık", "müdürlük",
    "vakıf", "dernek", "kurum", "büyükşehir", "ilçe",
    "enstitü", "ajans", "oda ", "birlik",
  ],
  "Enerji & Madencilik": [
    "enerji", "elektrik üretim", "doğalgaz", "güneş enerjisi",
    "rüzgar", "maden", "petrol", "yenilenebilir", "santral",
    "jeotermal", "hidroelektrik",
  ],
  "Tekstil & Moda": [
    "tekstil", "moda", "giyim", "konfeksiyon", "kumaş",
    "iplik", "dikiş", "hazır giyim", "tasarım evi",
    "butik", "koleksiyon", "sezon",
  ],
  "Gıda & Restoran": [
    "gıda", "yiyecek", "içecek", "restoran", "cafe",
    "fırın", "lokanta", "catering", "yemek", "market",
    "süpermarket", "organik", "gurme",
  ],
  "Otomotiv": [
    "otomotiv", "araç", "otomobil", "araba", "galeri",
    "yetkili servis", "yedek parça", "lastik", "oto ",
    "filo kiralama", "oto kiralama",
  ],
  "Tarım": [
    "tarım", "hayvancılık", "zirai", "tohum", "gübre",
    "sulama", "çiftlik", "tarımsal", "zirai ilaç",
    "sera", "organik tarım",
  ],
};

// Min puan = 2 eşleşme (false positive baskılar)
const SECTOR_MIN_SCORE = 2;

function detectSectorFromText(text: string): string | null {
  if (!text || text.length < 50) return null;
  const lower = text.toLowerCase();

  let bestSector: string | null = null;
  let bestScore = 0;

  for (const [sector, keywords] of Object.entries(SECTOR_KEYWORDS)) {
    let score = 0;
    for (const kw of keywords) {
      if (lower.includes(kw)) score++;
    }
    if (score > bestScore) {
      bestScore = score;
      bestSector = sector;
    }
  }

  if (bestScore < SECTOR_MIN_SCORE) return null;

  // SECTOR_LIST'teki formatla eşleşiyor mu doğrula
  return SECTOR_LIST.includes(bestSector ?? "") ? bestSector : null;
}

// ─── Ücretsiz Şehir Tespiti ───────────────────────────────────────────────────

function detectCityFromText(text: string): string | null {
  if (!text) return null;
  const lower = text.toLowerCase();
  for (const city of TURKEY_CITIES) {
    if (lower.includes(city.toLowerCase())) {
      return normalizeCity(city) ?? city;
    }
  }
  return null;
}

// ─── Ana Scraper Fonksiyonu ───────────────────────────────────────────────────

export async function scrapeDomain(
  domain: string,
  existingCompanyName?: string | null,
): Promise<WebScrapeResult | null> {
  const base = domain.replace(/^https?:\/\//, "").replace(/\/$/, "").toLowerCase();

  // 1. Homepage + İletişim sayfasını paralel çek (en kritik iki kaynak)
  const [homepageHtml, contactResult] = await Promise.all([
    fetchHtml(`https://${base}/`),
    fetchFirstMatch(base, CONTACT_PATHS),
  ]);

  // Her ikisi de başarısızsa erişilemeyen site
  if (!homepageHtml && !contactResult) return null;

  const homeHtml = homepageHtml ?? "";
  const contactHtml = contactResult?.html ?? "";
  const sourceUrl = contactResult?.url ?? `https://${base}/`;

  // 2. Hakkımızda sayfası (homepage'ten sonra, ayrı bir istek)
  const aboutResult = await fetchFirstMatch(base, ABOUT_PATHS);
  const aboutHtml = aboutResult?.html ?? "";

  // 3. KVKK ve kariyer varlık kontrolleri (paralel HEAD)
  const [hasKvkkPage, hasCareersPage] = await Promise.all([
    anyPathExists(base, KVKK_PATHS),
    anyPathExists(base, CAREER_PATHS),
  ]);

  // ─── Regex ile hızlı çıkarım ─────────────────────────────────────────────
  const combinedHtml = homeHtml + contactHtml;

  const emails = extractEmails(combinedHtml);
  const email = rankBestEmail(emails);
  const phone = extractPhone(contactHtml || homeHtml);
  const title = extractTitle(homeHtml);
  const metaDesc = extractMetaDesc(homeHtml);
  const linkedinUrl = extractLinkedin(combinedHtml);
  const instagramUrl = extractInstagram(combinedHtml);
  const cmsDetected = detectCms(homeHtml);
  const hasEcommerce = detectEcommerce(homeHtml);
  const isB2bRegex = detectB2b(homeHtml);
  const foundedYearRegex = extractFoundedYear(homeHtml + aboutHtml);

  const contactText = contactHtml ? stripHtml(contactHtml).slice(0, 700) : null;
  const aboutText = aboutHtml ? stripHtml(aboutHtml).slice(0, 1000) : null;
  const address = contactText ? extractAddress(contactText) : null;

  // ─── Ücretsiz şehir + sektör tespiti ─────────────────────────────────────
  // Şehir: iletişim + hakkımızda + adres metninde 81 il aranır
  // Sektör: iletişim + hakkımızda + meta açıklaması keyword scoring
  const combinedText = [contactText, aboutText, address].filter(Boolean).join(" ");
  const sectorText = [metaDesc, title, contactText, aboutText].filter(Boolean).join(" ");
  const city = detectCityFromText(combinedText);
  const sector = detectSectorFromText(sectorText);

  // ─── Sonuç birleştirme ────────────────────────────────────────────────────
  logger.debug({ domain: base, city, sector, email, phone: !!phone, cms: cmsDetected }, "web-scraper: tamamlandı");

  return {
    phone,
    address,
    email,
    companyName: title,
    foundedYear: foundedYearRegex,
    isB2b: isB2bRegex,
    hasEcommerce,
    hasKvkkPage,
    hasCareersPage,
    cmsDetected,
    linkedinUrl,
    instagramUrl,
    city,
    sector,
    sourceUrl,
  };
}
