/**
 * Haiku Domain Enrichment
 *
 * Claude Haiku kullanarak bir domain adından sektör ve şehir tahmini yapar.
 * Replit AI Integrations üzerinden çalışır (harici API key gerekmez).
 */
import { anthropic } from "@workspace/integrations-anthropic-ai";
import { logAiCost } from "../aiCostTracker";
import { logger } from "../../lib/logger";

const HAIKU_MODEL = "claude-haiku-4-5";

// Tutarlılık için sabit liste — model bu listedeki değerleri döndürmeli
export const SECTOR_LIST = [
  "Teknoloji & Yazılım",
  "E-ticaret & Perakende",
  "Finans & Bankacılık",
  "Sağlık & Klinik",
  "Eğitim & Üniversite",
  "İnşaat & Gayrimenkul",
  "Üretim & Sanayi",
  "Lojistik & Taşımacılık",
  "Turizm & Otelcilik",
  "Medya & Yayıncılık",
  "Hukuk & Danışmanlık",
  "Kamu & Belediye",
  "Enerji & Madencilik",
  "Tekstil & Moda",
  "Gıda & Restoran",
  "Otomotiv",
  "Tarım",
  "Diğer",
];

// Türkiye'nin tüm 81 ili — model bu listeden seçmeli
export const TURKEY_CITIES = [
  "Adana", "Adıyaman", "Afyonkarahisar", "Ağrı", "Aksaray",
  "Amasya", "Ankara", "Antalya", "Ardahan", "Artvin",
  "Aydın", "Balıkesir", "Bartın", "Batman", "Bayburt",
  "Bilecik", "Bingöl", "Bitlis", "Bolu", "Burdur",
  "Bursa", "Çanakkale", "Çankırı", "Çorum", "Denizli",
  "Diyarbakır", "Düzce", "Edirne", "Elazığ", "Erzincan",
  "Erzurum", "Eskişehir", "Gaziantep", "Giresun", "Gümüşhane",
  "Hakkari", "Hatay", "Iğdır", "Isparta", "İstanbul",
  "İzmir", "Kahramanmaraş", "Karabük", "Karaman", "Kars",
  "Kastamonu", "Kayseri", "Kırıkkale", "Kırklareli", "Kırşehir",
  "Kilis", "Kocaeli", "Konya", "Kütahya", "Malatya",
  "Manisa", "Mardin", "Mersin", "Muğla", "Muş",
  "Nevşehir", "Niğde", "Ordu", "Osmaniye", "Rize",
  "Sakarya", "Samsun", "Siirt", "Sinop", "Sivas",
  "Şanlıurfa", "Şırnak", "Tekirdağ", "Tokat", "Trabzon",
  "Tunceli", "Uşak", "Van", "Yalova", "Yozgat",
  "Zonguldak",
];

// ASCII/variant → canonical Turkish mapping (tüm 81 il + yaygın yanlış yazımlar)
// null = bu ilçe/yer tanımsız/anlamsız → DB'de NULL bırak
export const CITY_ALIASES: Record<string, string | null> = {
  // İstanbul
  "istanbul":         "İstanbul",
  "istambul":         "İstanbul",
  "istanbul ":        "İstanbul",
  // İzmir
  "izmir":            "İzmir",
  "izmır":            "İzmir",
  "smyrna":           "İzmir",
  // Ankara
  "ankara":           "Ankara",
  // Adana
  "adana":            "Adana",
  // Adıyaman
  "adiyaman":         "Adıyaman",
  "adıyaman":         "Adıyaman",
  // Afyonkarahisar
  "afyon":            "Afyonkarahisar",
  "afyonkarahisar":   "Afyonkarahisar",
  "afyonkarahi̇sar":   "Afyonkarahisar",
  // Ağrı
  "agri":             "Ağrı",
  "ağrı":             "Ağrı",
  // Amasya
  "amasya":           "Amasya",
  // Antalya
  "antalya":          "Antalya",
  // Artvin
  "artvin":           "Artvin",
  // Aydın
  "aydin":            "Aydın",
  "aydın":            "Aydın",
  // Balıkesir
  "balikesir":        "Balıkesir",
  "balıkesir":        "Balıkesir",
  // Bilecik
  "bilecik":          "Bilecik",
  // Bingöl
  "bingol":           "Bingöl",
  "bingöl":           "Bingöl",
  // Bitlis
  "bitlis":           "Bitlis",
  // Bolu
  "bolu":             "Bolu",
  // Burdur
  "burdur":           "Burdur",
  // Bursa
  "bursa":            "Bursa",
  // Çanakkale
  "canakkale":        "Çanakkale",
  "çanakkale":        "Çanakkale",
  // Çankırı
  "cankiri":          "Çankırı",
  "çankırı":          "Çankırı",
  "cankırı":          "Çankırı",
  // Çorum
  "corum":            "Çorum",
  "çorum":            "Çorum",
  // Denizli
  "denizli":          "Denizli",
  // Diyarbakır
  "diyarbakir":       "Diyarbakır",
  "diyarbakır":       "Diyarbakır",
  // Düzce
  "duzce":            "Düzce",
  "düzce":            "Düzce",
  // Edirne
  "edirne":           "Edirne",
  // Elazığ
  "elazig":           "Elazığ",
  "elazığ":           "Elazığ",
  "elazig ":          "Elazığ",
  // Erzincan
  "erzincan":         "Erzincan",
  // Erzurum
  "erzurum":          "Erzurum",
  // Eskişehir
  "eskisehir":        "Eskişehir",
  "eskişehir":        "Eskişehir",
  // Gaziantep
  "gaziantep":        "Gaziantep",
  "antep":            "Gaziantep",
  // Giresun
  "giresun":          "Giresun",
  // Gümüşhane
  "gumushane":        "Gümüşhane",
  "gümüşhane":        "Gümüşhane",
  "gumushane ":       "Gümüşhane",
  // Hakkari
  "hakkari":          "Hakkari",
  // Hatay
  "hatay":            "Hatay",
  "iskenderun":       "Hatay",
  "antakya":          "Hatay",
  // Iğdır
  "igdir":            "Iğdır",
  "ığdır":            "Iğdır",
  // Isparta
  "isparta":          "Isparta",
  // Kahramanmaraş
  "kahramanmaras":    "Kahramanmaraş",
  "kahramanmaraş":    "Kahramanmaraş",
  "maras":            "Kahramanmaraş",
  "k.maras":          "Kahramanmaraş",
  // Karabük
  "karabuk":          "Karabük",
  "karabük":          "Karabük",
  // Karaman
  "karaman":          "Karaman",
  // Kars
  "kars":             "Kars",
  // Kastamonu
  "kastamonu":        "Kastamonu",
  // Kayseri
  "kayseri":          "Kayseri",
  // Kırıkkale
  "kirikkale":        "Kırıkkale",
  "kırıkkale":        "Kırıkkale",
  // Kırklareli
  "kirklareli":       "Kırklareli",
  "kırklareli":       "Kırklareli",
  // Kırşehir
  "kirsehir":         "Kırşehir",
  "kırşehir":         "Kırşehir",
  // Kilis
  "kilis":            "Kilis",
  // Kocaeli
  "kocaeli":          "Kocaeli",
  "izmit":            "Kocaeli",
  // Konya
  "konya":            "Konya",
  // Kütahya
  "kutahya":          "Kütahya",
  "kütahya":          "Kütahya",
  // Malatya
  "malatya":          "Malatya",
  // Manisa
  "manisa":           "Manisa",
  // Mardin
  "mardin":           "Mardin",
  // Mersin
  "mersin":           "Mersin",
  "icel":             "Mersin",
  "içel":             "Mersin",
  // Muğla
  "mugla":            "Muğla",
  "muğla":            "Muğla",
  "bodrum":           "Muğla",
  "marmaris":         "Muğla",
  "fethiye":          "Muğla",
  // Muş
  "mus":              "Muş",
  "muş":              "Muş",
  // Nevşehir
  "nevsehir":         "Nevşehir",
  "nevşehir":         "Nevşehir",
  "kapadokya":        "Nevşehir",
  // Niğde
  "nigde":            "Niğde",
  "niğde":            "Niğde",
  // Ordu
  "ordu":             "Ordu",
  // Osmaniye
  "osmaniye":         "Osmaniye",
  // Rize
  "rize":             "Rize",
  // Sakarya
  "sakarya":          "Sakarya",
  "adapazari":        "Sakarya",
  "adapazarı":        "Sakarya",
  // Samsun
  "samsun":           "Samsun",
  // Siirt
  "siirt":            "Siirt",
  // Sinop
  "sinop":            "Sinop",
  // Sivas
  "sivas":            "Sivas",
  // Şanlıurfa
  "sanliurfa":        "Şanlıurfa",
  "şanliurfa":        "Şanlıurfa",
  "sanlıurfa":        "Şanlıurfa",
  "urfa":             "Şanlıurfa",
  "şanlıurfa":        "Şanlıurfa",
  // Şırnak
  "sirnak":           "Şırnak",
  "şırnak":           "Şırnak",
  // Tekirdağ
  "tekirdag":         "Tekirdağ",
  "tekirdağ":         "Tekirdağ",
  // Tokat
  "tokat":            "Tokat",
  // Trabzon
  "trabzon":          "Trabzon",
  // Tunceli
  "tunceli":          "Tunceli",
  "dersim":           "Tunceli",
  // Uşak
  "usak":             "Uşak",
  "uşak":             "Uşak",
  // Van
  "van":              "Van",
  // Yalova
  "yalova":           "Yalova",
  // Yozgat
  "yozgat":           "Yozgat",
  // Zonguldak
  "zonguldak":        "Zonguldak",

  // ── Eksik iller ──────────────────────────────────────────────────────────
  "aksaray":          "Aksaray",
  "ardahan":          "Ardahan",
  "bartin":           "Bartın",
  "bartın":           "Bartın",
  "batman":           "Batman",
  "bayburt":          "Bayburt",

  // ── Yaygın ilçe → ebeveyn il eşlemeleri ─────────────────────────────────
  // İstanbul ilçeleri
  "şişli":            "İstanbul",
  "şişli/istanbul":   "İstanbul",
  "maltepe":          "İstanbul",
  "esenler":          "İstanbul",
  "başakşehir":       "İstanbul",
  "üsküdar":          "İstanbul",
  "arnavutköy":       "İstanbul",
  "ataşehir":         "İstanbul",
  "mahmutbey":        "İstanbul",
  "bağcılar":         "İstanbul",
  "bahçelievler":     "İstanbul",
  "bakırköy":         "İstanbul",
  "beylikdüzü":       "İstanbul",
  "esenyurt":         "İstanbul",
  "kadıköy":          "İstanbul",
  "kartal":           "İstanbul",
  "pendik":           "İstanbul",
  "sultanbeyli":      "İstanbul",
  "tuzla":            "İstanbul",
  "ümraniye":         "İstanbul",
  "zeytinburnu":      "İstanbul",
  // Kocaeli ilçeleri
  "gebze":            "Kocaeli",
  "gölcük":           "Kocaeli",
  "körfez":           "Kocaeli",
  "çayırova":         "Kocaeli",
  "darıca":           "Kocaeli",
  "dilovası":         "Kocaeli",
  "kandıra":          "Kocaeli",
  "karamürsel":       "Kocaeli",
  "köseköy":          "Kocaeli",
  // Ankara ilçeleri
  "çankaya":          "Ankara",
  "etimesgut":        "Ankara",
  "sincan":           "Ankara",
  "keçiören":         "Ankara",
  "mamak":            "Ankara",
  "yenimahalle":      "Ankara",
  "kızılcahamam":     "Ankara",
  // Bursa ilçeleri
  "nilüfer":          "Bursa",
  "osmangazi":        "Bursa",
  "yıldırım":         "Bursa",
  "gemlik":           "Bursa",
  "mudanya":          "Bursa",
  // İzmir ilçeleri
  "bayındır":         "İzmir",
  "özdere":           "İzmir",
  "alaçatı":          "İzmir",
  "çeşme":            "İzmir",
  "bornova":          "İzmir",
  "buca":             "İzmir",
  "karşıyaka":        "İzmir",
  "konak":            "İzmir",
  "aliağa":           "İzmir",
  "bergama":          "İzmir",
  "kemalpaşa":        "İzmir",
  "menemen":          "İzmir",
  "seferihisar":      "İzmir",
  "torbalı":          "İzmir",
  // Aydın ilçeleri
  "söke":             "Aydın",
  "didim":            "Aydın",
  "kuşadası":         "Aydın",
  "nazilli":          "Aydın",
  // Antalya ilçeleri
  "manavgat":         "Antalya",
  "alanya":           "Antalya",
  "tekirova":         "Antalya",
  "serik":            "Antalya",
  "kemer":            "Antalya",
  "belek":            "Antalya",
  // Adana ilçeleri
  "seyhan":           "Adana",
  "çukurova":         "Adana",
  "sarıçam":          "Adana",
  "yüreğir":          "Adana",
  // Konya ilçeleri
  "çumra":            "Konya",
  "ereğli":           "Konya",
  "selçuklu":         "Konya",
  "meram":            "Konya",
  "karatay":          "Konya",
  // Hatay ilçeleri
  "arsuz":            "Hatay",
  "reyhanlı":         "Hatay",
  // Gaziantep ilçeleri
  "nizip":            "Gaziantep",
  "şahinbey":         "Gaziantep",
  "şehitkamil":       "Gaziantep",
  // Manisa ilçeleri
  "akhisar":          "Manisa",
  "turgutlu":         "Manisa",
  "salihli":          "Manisa",
  // Kastamonu ilçeleri
  "araç":             "Kastamonu",
  // Edirne ilçeleri
  "meriç":            "Edirne",
  "keşan":            "Edirne",
  // Osmaniye ilçeleri
  "toprakkale":       "Osmaniye",
  // Ordu ilçeleri
  "ünye":             "Ordu",
  "fatsa":            "Ordu",
  // Sakarya ilçeleri
  "arifiye":          "Sakarya",
  "serdivan":         "Sakarya",
  "erenler":          "Sakarya",
  // Mersin ilçeleri
  "tarsus":           "Mersin",
  "erdemli":          "Mersin",
  // Tekirdağ ilçeleri
  "çorlu":            "Tekirdağ",
  "çerkezköy":        "Tekirdağ",
  // Balıkesir ilçeleri
  "bandırma":         "Balıkesir",
  "ayvalık":          "Balıkesir",
  "gönen":            "Balıkesir",
  // Sivas ilçeleri
  "merkez/sivas":     "Sivas",
  // Genel/belirsiz — TURKEY_CITIES'da olan ama kayda değer
  "merkez":           null,
  "yuvacık":          "Kocaeli",
  "yukarıazıklı":     null,
  "oğulbey":          null,
  "sancak":           null,
  "marmaracık":       null,
  "kireçocağı":       null,
  "merkezefendi":     "Denizli",
  "ortaköy":          null,
};

export const CITY_TO_REGION: Record<string, string> = {
  // MARMARA
  "İstanbul": "Marmara", "Tekirdağ": "Marmara", "Edirne": "Marmara",
  "Kırklareli": "Marmara", "Balıkesir": "Marmara", "Çanakkale": "Marmara",
  "Bursa": "Marmara", "Yalova": "Marmara", "Kocaeli": "Marmara",
  "Sakarya": "Marmara", "Düzce": "Marmara", "Bolu": "Marmara",
  "Bilecik": "Marmara", "Eskişehir": "Marmara",
  // EGE
  "İzmir": "Ege", "Manisa": "Ege", "Afyonkarahisar": "Ege",
  "Kütahya": "Ege", "Uşak": "Ege", "Denizli": "Ege", "Muğla": "Ege", "Aydın": "Ege",
  // AKDENİZ
  "Antalya": "Akdeniz", "Isparta": "Akdeniz", "Burdur": "Akdeniz",
  "Konya": "Akdeniz", "Karaman": "Akdeniz", "Mersin": "Akdeniz",
  "Adana": "Akdeniz", "Osmaniye": "Akdeniz", "Hatay": "Akdeniz",
  "Kahramanmaraş": "Akdeniz",
  // İÇ ANADOLU
  "Ankara": "İç Anadolu", "Çankırı": "İç Anadolu", "Kırıkkale": "İç Anadolu",
  "Kırşehir": "İç Anadolu", "Nevşehir": "İç Anadolu", "Aksaray": "İç Anadolu",
  "Niğde": "İç Anadolu", "Kayseri": "İç Anadolu", "Sivas": "İç Anadolu",
  "Yozgat": "İç Anadolu",
  // KARADENİZ
  "Zonguldak": "Karadeniz", "Bartın": "Karadeniz", "Karabük": "Karadeniz",
  "Kastamonu": "Karadeniz", "Sinop": "Karadeniz", "Samsun": "Karadeniz",
  "Ordu": "Karadeniz", "Giresun": "Karadeniz", "Trabzon": "Karadeniz",
  "Rize": "Karadeniz", "Artvin": "Karadeniz", "Gümüşhane": "Karadeniz",
  "Bayburt": "Karadeniz", "Amasya": "Karadeniz", "Tokat": "Karadeniz",
  "Çorum": "Karadeniz",
  // DOĞU ANADOLU
  "Malatya": "Doğu Anadolu", "Elazığ": "Doğu Anadolu", "Tunceli": "Doğu Anadolu",
  "Bingöl": "Doğu Anadolu", "Erzincan": "Doğu Anadolu", "Erzurum": "Doğu Anadolu",
  "Kars": "Doğu Anadolu", "Ardahan": "Doğu Anadolu", "Iğdır": "Doğu Anadolu",
  "Ağrı": "Doğu Anadolu", "Van": "Doğu Anadolu", "Bitlis": "Doğu Anadolu",
  "Muş": "Doğu Anadolu",
  // GÜNEYDOĞU ANADOLU
  "Gaziantep": "Güneydoğu Anadolu", "Kilis": "Güneydoğu Anadolu",
  "Adıyaman": "Güneydoğu Anadolu", "Şanlıurfa": "Güneydoğu Anadolu",
  "Diyarbakır": "Güneydoğu Anadolu", "Mardin": "Güneydoğu Anadolu",
  "Batman": "Güneydoğu Anadolu", "Şırnak": "Güneydoğu Anadolu",
  "Siirt": "Güneydoğu Anadolu", "Hakkari": "Güneydoğu Anadolu",
};

export const REGIONS = [
  "Marmara", "Ege", "Akdeniz", "İç Anadolu",
  "Karadeniz", "Doğu Anadolu", "Güneydoğu Anadolu",
] as const;

export function getRegion(city: string | null | undefined): string | null {
  if (!city) return null;
  return CITY_TO_REGION[city] ?? null;
}

/**
 * Şehir adını normalize eder: "Istanbul" → "İstanbul", "Izmir" → "İzmir" vb.
 * Önce CITY_ALIASES'da arar, sonra TURKEY_CITIES listesinde case-insensitive kontrol yapar.
 */
export function normalizeCity(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  // Remove combining dot above (U+0307) produced by İ/Ş.toLowerCase() in Node
  const lower = trimmed.toLowerCase().replace(/\u0307/g, "");
  const alias = CITY_ALIASES[lower];
  if (alias) return alias;
  // Zaten listede varsa doğrudan döndür (case-sensitive tam eşleşme)
  if (TURKEY_CITIES.includes(trimmed)) return trimmed;
  // Case-insensitive fallback — Türkçe karakter normalize edilerek bak
  const normalized = trimmed
    .replace(/İ/g, "i").replace(/I/g, "i").replace(/Ş/g, "s").replace(/Ç/g, "c")
    .replace(/Ğ/g, "g").replace(/Ö/g, "o").replace(/Ü/g, "u").toLowerCase();
  const match = TURKEY_CITIES.find(c => {
    const cn = c.toLowerCase().replace(/\u0307/g, "")
      .replace(/ı/g, "i").replace(/ş/g, "s").replace(/ç/g, "c")
      .replace(/ğ/g, "g").replace(/ö/g, "o").replace(/ü/g, "u");
    return cn === normalized;
  });
  return match ?? null;
}

export interface EnrichmentResult {
  sector: string | null;
  city: string | null;
  region: string | null;
  confidence: "high" | "medium" | "low";
  reasoning: string;
}

function extractJson(raw: string): Record<string, unknown> {
  try {
    const m = raw.match(/\{[\s\S]*\}/);
    return m ? JSON.parse(m[0]) : {};
  } catch {
    return {};
  }
}

const CITY_LIST_PROMPT = TURKEY_CITIES.join(", ");

export async function enrichDomain(
  domain: string,
  companyName?: string | null,
): Promise<EnrichmentResult> {
  const prompt = `Sen bir Türkiye iş dünyası uzmanısın. Aşağıdaki domain adına bakarak şirketi analiz et.

Domain: ${domain}${companyName ? `\nŞirket Adı: ${companyName}` : ""}

Görev:
1. Bu şirketin sektörünü belirle (aşağıdaki Sektör Listesinden seç)
2. Şirketin Türkiye'deki muhtemel şehrini belirle (aşağıdaki Şehir Listesinden seç, TAM adıyla)
3. Güven seviyeni belirt

Sektör Listesi:
${SECTOR_LIST.join("\n")}

Türkiye Şehir Listesi (SADECE bu listeden seç, tam Türkçe adı kullan):
${CITY_LIST_PROMPT}

Kurallar:
- Domain adındaki ipuçlarını kullan (hastane→Sağlık, yazilim→Teknoloji vb.)
- .edu.tr → Eğitim, .gov.tr → Kamu, .bel.tr → Kamu (kesin, high confidence)
- Şehir belirleyemiyorsan null döndür
- Türkiye dışı bir şirketse null döndür
- Yeterli ipucu yoksa "Diğer" döndür, uydurma
- Şehir için MUTLAKA listeden birini seç, listede olmayan bir şehir yazma

SADECE JSON döndür, başka hiçbir şey yazma:
{"sector":"Teknoloji & Yazılım","city":"İstanbul","confidence":"medium","reasoning":"domain adında yazilim geçiyor"}`;

  const message = await anthropic.messages.create({
    model: HAIKU_MODEL,
    max_tokens: 200,
    messages: [{ role: "user", content: prompt }],
  });

  void logAiCost({
    task: "haiku-domain-enrichment",
    service: "domain-enrichment",
    model: HAIKU_MODEL,
    inputTokens: message.usage.input_tokens,
    outputTokens: message.usage.output_tokens,
    cacheType: "none",
  });

  const block = message.content[0];
  const raw = block?.type === "text" ? block.text : "";
  const parsed = extractJson(raw) as Partial<EnrichmentResult>;

  const sector = parsed.sector && SECTOR_LIST.includes(parsed.sector) ? parsed.sector : null;
  const city = normalizeCity(parsed.city as string | null | undefined);
  const region = getRegion(city);
  const confidence = (["high", "medium", "low"] as const).includes(parsed.confidence as "high" | "medium" | "low")
    ? (parsed.confidence as "high" | "medium" | "low")
    : "low";

  if (!sector) {
    logger.debug({ domain, raw }, "Haiku enrichment: sektör belirlenemedi");
  }

  return { sector, city, region, confidence, reasoning: String(parsed.reasoning ?? "") };
}
