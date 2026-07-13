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
  sectorConfidence: number | null;
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

// ─── Ağırlıklı Sektör Tespiti ─────────────────────────────────────────────────
// Ağırlık: 3 = ayırt edici (sektöre özgü), 2 = orta, 1 = generic/zayıf sinyal
// Eşik: topScore >= 3 VE birinci-ikinci arası >= 2 (aksi hâlde belirsiz → null)
// Yanlış etiket, boş etiketten daha zararlı — tie → null.

const SECTOR_KEYWORDS: Record<string, Array<[RegExp, number]>> = {
  "Teknoloji & Yazılım": [
    [/\byazılım\b/i, 3],        [/\bbilişim\b/i, 3],
    [/\bsiber güvenlik\b/i, 3], [/\bsiber\b/i, 2],
    [/\bveri merkezi\b/i, 3],   [/\bbulut\b/i, 2],
    [/\bsaas\b/i, 3],           [/\berp\b/i, 3],
    [/\bcrm\b/i, 2],            [/\bhosting\b/i, 2],
    [/\bentegrasyon\b/i, 2],    [/\bdijital dönüşüm\b/i, 2],
    [/\botomasyon\b/i, 2],      [/\byapay zeka\b/i, 2],
    [/\bteknoloji\b/i, 1],      [/\bapi\b/i, 1],
    [/\bplatform\b/i, 1],       [/\baltyapı\b/i, 1],
  ],
  "E-ticaret & Perakende": [
    [/\bsepete ekle\b/i, 3],    [/\be[- ]ticaret\b/i, 3],
    [/\bonline (mağaza|satış)\b/i, 3],
    [/\bmağaza\b/i, 2],         [/\balışveriş\b/i, 2],
    [/\bürün kataloğ/i, 2],     [/\bsepetim\b/i, 2],
    [/\bindirim\b/i, 1],        [/\bteslimat\b/i, 1],
    [/\bkargo\b/i, 1],          [/\bstok\b/i, 1],
  ],
  "Finans & Bankacılık": [
    [/\bbankacılık\b/i, 3],     [/\bfaktoring\b/i, 3],
    [/\bleasing\b/i, 3],        [/\bportföy\b/i, 3],
    [/\bvarlık yönetim/i, 3],   [/\bbes\b/i, 2],
    [/\bsigorta\b/i, 2],        [/\bkredi\b/i, 2],
    [/\byatırım\b/i, 2],        [/\bborsa\b/i, 2],
    [/\bfinans\b/i, 1],         [/\bödeme\b/i, 1],
    [/\bpos\b/i, 1],
  ],
  "Sağlık & Klinik": [
    [/\bhastane\b/i, 3],        [/\bpoliklinik\b/i, 3],
    [/\beczane\b/i, 3],         [/\btıp merkezi\b/i, 3],
    [/\bcerrahi\b/i, 3],        [/\bdiş\b/i, 2],
    [/\bdental\b/i, 2],         [/\bklinik\b/i, 2],
    [/\bmedikal\b/i, 2],        [/\blaboratuvar\b/i, 2],
    [/\bsağlık\b/i, 1],         [/\bdoktor\b/i, 1],
    [/\bilaç\b/i, 1],           [/\bhasta\b/i, 1],
  ],
  "Eğitim & Üniversite": [
    [/\büniversite\b/i, 3],     [/\bkolej\b/i, 3],
    [/\beğitim kurum/i, 3],     [/\bsertifika program/i, 3],
    [/\bokul\b/i, 2],           [/\bakademi\b/i, 2],
    [/\bdershane\b/i, 2],       [/\bmba\b/i, 2],
    [/\bkurs\b/i, 1],           [/\böğrenci\b/i, 1],
    [/\beğitim\b/i, 1],
  ],
  "İnşaat & Gayrimenkul": [
    [/\bmüteahhit\b/i, 3],      [/\binşaat\b/i, 3],
    [/\bgayrimenkul\b/i, 3],    [/\bproje geliştir/i, 3],
    [/\byapı market\b/i, 2],    [/\bemlak\b/i, 2],
    [/\brezidans\b/i, 2],       [/\bmimarlık\b/i, 2],
    [/\bkonut\b/i, 1],          [/\barsa\b/i, 1],
    [/\bdaire\b/i, 1],
  ],
  "Üretim & Sanayi": [
    [/\büretim tesisi\b/i, 3],  [/\bfabrika\b/i, 3],
    [/\bimalat\b/i, 3],         [/\bosb\b/i, 3],
    [/\bendüstriyel\b/i, 2],    [/\bkontrol paneli\b/i, 2],
    [/\bmakine\b/i, 2],         [/\bkalıp\b/i, 2],
    [/\büretim\b/i, 1],         [/\bsanayi\b/i, 1],
    [/\bmetal\b/i, 1],          [/\bçelik\b/i, 1],
  ],
  "Lojistik & Taşımacılık": [
    [/\blojistik\b/i, 3],       [/\btaşımacılık\b/i, 3],
    [/\bnakliye\b/i, 3],        [/\bgümrük\b/i, 3],
    [/\bsevkiyat\b/i, 2],       [/\bfilo\b/i, 2],
    [/\bdepolama\b/i, 2],       [/\bithalat\b/i, 2],
    [/\bihracat\b/i, 2],        [/\bkurye\b/i, 2],
    [/\bkargo\b/i, 1],
  ],
  "Turizm & Otelcilik": [
    [/\botel\b/i, 3],           [/\bresort\b/i, 3],
    [/\brezervasyon\b/i, 3],    [/\bkonaklama\b/i, 3],
    [/\bincoming\b/i, 3],       [/\btur (operat|şirket)/i, 3],
    [/\bseyahat\b/i, 2],        [/\bpansiyon\b/i, 2],
    [/\bspa\b/i, 2],            [/\btur\b/i, 1],
    [/\btatil\b/i, 1],
  ],
  "Medya & Yayıncılık": [
    [/\breklam ajans/i, 3],     [/\bdijital ajans\b/i, 3],
    [/\bgözete\b/i, 3],         [/\byayıncılık\b/i, 3],
    [/\bprodüksiyon\b/i, 2],    [/\bdijital medya\b/i, 2],
    [/\bhaber ajans/i, 2],      [/\bdergi\b/i, 2],
    [/\breklam\b/i, 1],         [/\biçerik\b/i, 1],
    [/\bmedya\b/i, 1],
  ],
  "Hukuk & Danışmanlık": [
    [/\bavukat(lık)?\b/i, 3],   [/\bhukuk büro/i, 3],
    [/\bmali müşavir\b/i, 3],   [/\byönetim danışman/i, 3],
    [/\bdenetim\b/i, 2],        [/\bvergi danışman/i, 2],
    [/\bnotes?\b/i, 2],         [/\baudit\b/i, 2],
    [/\bhukuk\b/i, 1],          [/\bdanışmanlık\b/i, 1],
    [/\bmuhasebe\b/i, 1],
  ],
  "Kamu & Belediye": [
    [/\bbelediye\b/i, 3],       [/\bbüyükşehir\b/i, 3],
    [/\bbakanlık\b/i, 3],       [/\bkamu kurumu\b/i, 3],
    [/\bmüdürlük\b/i, 2],       [/\bilçe\b/i, 2],
    [/\bvakıf\b/i, 2],          [/\benstitü\b/i, 2],
    [/\bdernek\b/i, 1],         [/\bkamu\b/i, 1],
  ],
  "Enerji & Madencilik": [
    [/\bgüneş enerjisi\b/i, 3], [/\bjeotermal\b/i, 3],
    [/\bhidroelektrik\b/i, 3],  [/\bdoğalgaz\b/i, 3],
    [/\bmaden\b/i, 3],          [/\bsantral\b/i, 3],
    [/\byenilenebilir enerji\b/i, 3],
    [/\bpetrol\b/i, 2],         [/\brüzgar\b/i, 2],
    [/\benerji\b/i, 1],
  ],
  "Tekstil & Moda": [
    [/\btekstil\b/i, 3],        [/\bkonfeksiyon\b/i, 3],
    [/\biplik\b/i, 3],          [/\bkumaş\b/i, 3],
    [/\bhazır giyim\b/i, 3],    [/\bmoda (tasarım|evi)/i, 3],
    [/\bgiyim\b/i, 2],          [/\bmoda\b/i, 1],
    [/\bkoleksiyon\b/i, 1],
  ],
  "Gıda & Restoran": [
    [/\bgıda (üretim|şirket|holding)/i, 3],
    [/\bcatering\b/i, 3],       [/\brestoran\b/i, 2],
    [/\bet ürünleri\b/i, 3],    [/\bsüt ürünleri\b/i, 3],
    [/\bfırın\b/i, 2],          [/\biçecek\b/i, 2],
    [/\bgıda\b/i, 1],           [/\byemek\b/i, 1],
  ],
  "Otomotiv": [
    [/\byetkili servis\b/i, 3], [/\botomotiv\b/i, 3],
    [/\byedek parça\b/i, 3],    [/\bfilo kiralama\b/i, 3],
    [/\bgaleri\b/i, 2],         [/\blastik\b/i, 2],
    [/\boto servis\b/i, 2],     [/\baraç kiralama\b/i, 2],
    [/\botomobil\b/i, 1],       [/\baraba\b/i, 1],
  ],
  "Tarım": [
    [/\bzirai\b/i, 3],          [/\bhayvancılık\b/i, 3],
    [/\btohum\b/i, 3],          [/\bgübre\b/i, 3],
    [/\borganik tarım\b/i, 3],  [/\bsera\b/i, 2],
    [/\bsulama sistem/i, 2],    [/\bçiftlik\b/i, 2],
    [/\btarımsal\b/i, 2],       [/\btarım\b/i, 1],
  ],
};

// Eşik: topScore >= 3 VE birinci-ikinci arasındaki fark >= 2
// Beraberlik veya düşük skor → null (yanlış etiket boş etiketten zararlı)
const SECTOR_MIN_SCORE = 3;
const SECTOR_MIN_GAP   = 2;

function detectSector(text: string): { sector: string | null; confidence: number } {
  if (!text || text.length < 50) return { sector: null, confidence: 0 };

  const scores: Record<string, number> = {};
  for (const [sector, patterns] of Object.entries(SECTOR_KEYWORDS)) {
    let score = 0;
    for (const [pattern, weight] of patterns) {
      if (pattern.test(text)) score += weight;
    }
    if (score > 0) scores[sector] = score;
  }

  const ranked = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  if (ranked.length === 0) return { sector: null, confidence: 0 };

  const [topSector, topScore] = ranked[0];
  const secondScore = ranked[1]?.[1] ?? 0;

  if (topScore < SECTOR_MIN_SCORE || topScore - secondScore < SECTOR_MIN_GAP) {
    return { sector: null, confidence: topScore };
  }
  // SECTOR_LIST doğrulaması
  const canonicalSector = SECTOR_LIST.includes(topSector) ? topSector : null;
  return { sector: canonicalSector, confidence: topScore };
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
  const { sector, confidence: sectorConfidence } = detectSector(sectorText);

  // ─── Sonuç birleştirme ────────────────────────────────────────────────────
  logger.debug({ domain: base, city, sector, sectorConfidence, email, phone: !!phone, cms: cmsDetected }, "web-scraper: tamamlandı");

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
    sectorConfidence: sectorConfidence > 0 ? sectorConfidence : null,
    sourceUrl,
  };
}
