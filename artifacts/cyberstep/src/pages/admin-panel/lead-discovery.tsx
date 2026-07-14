import { useState, useRef } from "react";
import { ChevronDown, ChevronUp, Download, AlertTriangle, ShieldAlert, RefreshCw, Search, X, Loader2, CheckCircle2, Clock, XCircle, Upload } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import pdfLeads from "../../data/pdf-leads-2026-06.json";
import { AdminLayout } from "../../components/admin-layout";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";

const BASE = "/api/admin-panel";

const PORT_INFO_MAP: Record<number, { note: string; risk: "critical" | "high" | "medium" | "low" }> = {
  22:    { note: "Şifreli; ama internete açıksa brute-force hedefi — anahtar kimlik doğrulama + IP kısıtlama önerilir", risk: "low" },
  25:    { note: "Mail sunucu-sunucu iletişimi — açık olması normal; open relay taraması önerilir", risk: "low" },
  53:    { note: "İsim sunucusu ise normal; open resolver ise DDoS amplifikasyon riski — zone transfer (AXFR) denetimi önerilir", risk: "low" },
  110:   { note: "Şifresiz olabilir — TLS zorunlu önerilir (POP3S/995 tercih edilmeli)", risk: "medium" },
  143:   { note: "Şifresiz olabilir — STARTTLS/IMAPS önerilir", risk: "medium" },
  161:   { note: "Varsayılan community string'lerle (public/private) sıkça istismar edilir", risk: "high" },
  389:   { note: "Şifresiz dizin servisi — internete açıksa AD bilgisi sızabilir", risk: "critical" },
  443:   { note: "Standart HTTPS — beklenen", risk: "low" },
  445:   { note: "İnternete asla açık olmamalı — EternalBlue/WannaCry risk vektörü", risk: "critical" },
  465:   { note: "Şifreli mail gönderimi (implicit TLS) — standart ve beklenen", risk: "low" },
  500:   { note: "Site-to-site VPN — beklenen açıklık", risk: "low" },
  587:   { note: "İstemci mail gönderimi (STARTTLS) — standart ve beklenen", risk: "low" },
  636:   { note: "Şifreli LDAP — yine de internete açık olması istisnai olmalı", risk: "high" },
  989:   { note: "Şifreli FTP veri kanalı", risk: "low" },
  990:   { note: "Şifreli FTP kontrol kanalı", risk: "low" },
  993:   { note: "Şifreli IMAP — standart ve beklenen", risk: "low" },
  995:   { note: "Şifreli POP3 — standart ve beklenen", risk: "low" },
  1433:  { note: "Microsoft SQL Server doğrudan internete açık — güvenlik duvarı ile kısıtlayın", risk: "critical" },
  1521:  { note: "Oracle veritabanı internete açık", risk: "critical" },
  1723:  { note: "Eski, kriptografik olarak kırılmış VPN protokolü — modern alternatiflere geçin", risk: "high" },
  1883:  { note: "IoT mesajlaşma — genelde kimlik doğrulamasız; internete açık olmamalı", risk: "high" },
  2375:  { note: "Docker daemon TLS olmadan açık — kimlik doğrulamasız; anında container ele geçirme riski", risk: "critical" },
  2376:  { note: "Docker daemon TLS ile açık — yine de internete açık olmamalı", risk: "high" },
  3000:  { note: "Node/React dev sunucusu tipik portu — production'da açık olmamalı", risk: "medium" },
  3306:  { note: "Veritabanı doğrudan internete açık — veri sızıntısı riski; güvenlik duvarı ile kısıtlayın", risk: "critical" },
  3389:  { note: "İnternete doğrudan açık RDP — en sık fidye yazılımı giriş noktası; VPN arkasına alın", risk: "critical" },
  4443:  { note: "FortiGate/firewall admin paneli sık kullanır — internete açıksa IP allowlist zorunlu", risk: "high" },
  4500:  { note: "VPN NAT traversal — beklenen açıklık", risk: "low" },
  5060:  { note: "Şifresiz VoIP sinyalleşmesi — toll-fraud riski", risk: "medium" },
  5061:  { note: "Şifreli VoIP sinyalleşmesi", risk: "low" },
  5432:  { note: "Veritabanı doğrudan internete açık — güvenlik duvarı zorunlu", risk: "critical" },
  5672:  { note: "Mesaj kuyruğu — internete açıksa veri/komut enjeksiyonu riski", risk: "high" },
  5900:  { note: "Genelde zayıf/şifresiz kimlik doğrulama — internete açık olmamalı", risk: "critical" },
  5984:  { note: "CouchDB HTTP API internete açık", risk: "critical" },
  6379:  { note: "Sıklıkla kimlik doğrulamasız çalışır — internete açıksa acil müdahale gerekir", risk: "critical" },
  6443:  { note: "İnternete açıksa küme tamamen ele geçirilebilir", risk: "critical" },
  8000:  { note: "Sıklıkla geliştirme ortamı — production'da açık olmamalı", risk: "medium" },
  8080:  { note: "Genelde proxy/dev sunucu — doğrudan internete açıksa kontrol edilmeli", risk: "low" },
  8443:  { note: "CDN varsa normal; yoksa FortiGate/yönetim arayüzü olabilir — context kontrolü şart", risk: "low" },
  8880:  { note: "Yalnızca tespit edilen CDN Cloudflare ise normal say — port numarasına güvenme", risk: "low" },
  8888:  { note: "Yönetim paneli portu internete açık", risk: "medium" },
  9090:  { note: "İzleme/yönetim paneli — genelde kimlik doğrulamasız; internete açık olmamalı", risk: "medium" },
  9200:  { note: "Varsayılan kurulumda kimlik doğrulama yoktur — indeks verileri herkese açık olabilir", risk: "critical" },
  10000: { note: "Webmin yönetim paneli internete açık — güvenlik duvarı önerilir", risk: "high" },
  10443: { note: "Alternatif admin GUI — internete açık olmamalı", risk: "high" },
  11211: { note: "DDoS amplifikasyon ve veri sızıntısı riski — internete kapalı olmalı", risk: "high" },
  27017: { note: "Geçmişte kitlesel veri sızıntılarının başlıca kaynağı — kimlik doğrulama zorunlu", risk: "critical" },
};

function resolvePortNote(product: string | null | undefined, storedNote: string | null | undefined, storedRisk: string | null | undefined): { note: string | null; risk: string | null } {
  const STALE = "Bilinmeyen servis — manuel doğrulama önerilir";
  if (!storedNote || storedNote === STALE) {
    const match = (product ?? "").match(/Port\s+(\d+)/i);
    if (match) {
      const portNum = parseInt(match[1]!, 10);
      const info = PORT_INFO_MAP[portNum];
      if (info) return { note: info.note, risk: info.risk };
    }
  }
  return { note: storedNote ?? null, risk: storedRisk ?? null };
}

interface Stats {
  total: number;
  pending: number;
  pendingTier2: number;
  pendingTier3: number;
  prescreening: number;
  scanning: number;
  scanned: number;
  qualified: number;
  withContact: number;
  teaserReady: number;
  teaserSent: number;
  bySource: Array<{ source: string; count: number }>;
}

interface DiscoveryRun {
  id: number;
  source: string;
  runParams: Record<string, unknown>;
  status: string;
  totalFound: number;
  totalAdded: number;
  startedAt: string;
  completedAt: string | null;
  errorMessage: string | null;
}

interface ShodanQuery {
  index: number;
  q: string;
  label: string;
  priority: number;
}

interface CVEBreakdown {
  total: number;
  critical: number;
  high: number;
  medium: number;
  informational: number;
  cisaKev: number;
}

interface CveDomainEntry {
  cveId: string;
  domain: string;
  matchedProduct: string | null;
  matchedVersion: string | null;
  confidence: number | null;
  isPatched: boolean | null;
  wafDetected: boolean | null;
  wafProvider: string | null;
}

interface CveReportEntry {
  cveId: string;
  cvssScore: number | null;
  severity: string | null;
  title: string | null;
  exploitPublic: boolean | null;
  cisaKev: boolean | null;
  patchAvailable: boolean | null;
  status: string | null;
  detectedAt: string | null;
  affectedDomainCount: number;
  domains: CveDomainEntry[];
}

interface CveReport {
  total: number;
  cves: CveReportEntry[];
}

interface EnrichmentDashboard {
  progress: {
    total: number; sector_filled: number; city_filled: number; both_filled: number;
    enriched: number; pending: number; no_match: number; failed: number;
    last_web_scrape_run: string | null; last_sector_run: string | null; batch_running: boolean;
    web_scrape_done: number; web_scrape_no_data: number; email_filled: number; phone_filled: number; scrape_pending: number; alive_total: number;
  };
  sector_dist: { sector: string; count: number }[];
  city_dist: { city: string; count: number }[];
  cron_history: {
    job_name: string; status: string; started_at: string;
    ended_at: string | null; processed_count: number | null;
    duration_ms: number | null; error_message: string | null;
  }[];
  normalize_issues: { city: string; count: number }[];
}

interface PortRiskDomain {
  domain: string;
  overall_score: number;
  sector: string | null;
  city: string | null;
  waf_detected: boolean | null;
  waf_provider: string | null;
  risky_ports: number[];
  mysql_open: boolean;
  ftp_open: boolean;
  rdp_open: boolean;
  vnc_open: boolean;
  mongo_open: boolean;
  redis_open: boolean;
}

interface PortRiskData {
  summary: { total: number; mysql: number; ftp: number; rdp: number; vnc: number; mongo: number; redis: number };
  domains: PortRiskDomain[];
}

interface SourceData {
  ip?: string;
  org?: string;
  port?: number;
  httpTitle?: string | null;
  shodanQuery?: string;
  product?: string;
  cveBreakdown?: CVEBreakdown;
  registeredDomain?: string;
  tld?: string;
  subdomains?: string[];
  issuer?: string;
  notBefore?: string;
  [key: string]: unknown;
}

interface LeadCandidate {
  id: number;
  domain: string;
  companyName: string | null;
  sector: string | null;
  subSector: string | null;
  sourceList: string | null;
  city: string | null;
  source: string;
  hasFortigate: boolean;
  scanStatus: string;
  riskScore: number | null;
  criticalFindings: number;
  findingHighlights: string[] | null;
  isQualified: boolean;
  contactName: string | null;
  contactTitle: string | null;
  contactEmail: string | null;
  teaserSubject: string | null;
  teaserBody: string | null;
  teaserGeneratedAt: string | null;
  teaserSentAt: string | null;
  sourceData: SourceData | null;
  contactSource: string | null;
  officerName: string | null;
  officerTitle: string | null;
  isrNotes: string | null;
  notes: string | null;
  httpStatus: number | null;
  isAlive: boolean | null;
  responseTimeMs: number | null;
  scrapedPhone: string | null;
  scrapedAddress: string | null;
  scrapedCompanyName: string | null;
  webScrapedAt: string | null;
  webScrapeStatus: string | null;
  webScrapeEmail: string | null;
  webScrapeSourceUrl: string | null;
  companyAboutSummary: string | null;
  companyServices: string[] | null;
  companyFoundedYear: number | null;
  isB2b: boolean | null;
  hasEcommerce: boolean | null;
  hasKvkkPage: boolean | null;
  hasCareersPage: boolean | null;
  cmsDetected: string | null;
  socialLinkedinUrl: string | null;
  socialInstagramUrl: string | null;
  createdAt: string;
  scanId: number | null;
  wafDetected: boolean | null;
  confidenceScore: number | null;
  blacklistScore: number | null;
  sslDaysRemaining: number | null;
  mailReputationScore: number | null;
  tier: string | null;
  ispOrganization: string | null;
  isrPromotedAt: string | null;
  isrCustomerId: number | null;
  ticker: string | null;
  bistIndexes: string | null;
  bistMarket: string | null;
  isPublicCompany: boolean;
  isBist30: boolean;
  isBist100: boolean;
  isBist500: boolean;
  sectorConfidence: string | null;
  wafEnrichmentStatus: string | null;
  isMunicipality: boolean;
}

interface SubdomainSummary {
  summary: { web_app: number; api: number; redirect: number; error_4xx: number; error_5xx: number; unreachable: number; unknown: number; total: number };
  topPriority: Array<{ domain: string; priorityScore: number; priorityReason: string; classification: string; httpStatus: number | null }>;
  processing: boolean;
}

function getWafBadge(confidenceScore: number | null, wafDetected: boolean | null): { label: string; color: "blue" | "amber" } {
  if (!wafDetected || (confidenceScore ?? 100) >= 85) return { label: "Tarama Engellenmedi", color: "blue" };
  if ((confidenceScore ?? 0) >= 70) return { label: "Kısmi Görünürlük", color: "amber" };
  return { label: "WAF Arkası", color: "amber" };
}

const SIGNAL_LABELS: Record<string, string> = {
  // ── salesSignal değerleri ───────────────────────────────────────
  fortinet_customer:        "Fortinet Müşterisi",
  cms_wordpress:            "WordPress",
  cdn_user:                 "CDN Kullanıcısı",
  microsoft_shop:           "Microsoft/Azure",
  budget_indicator_high:    "Yüksek Bütçe",
  budget_indicator_medium:  "Orta Bütçe",
  budget_indicator_low:     "Düşük Bütçe",
  budget_indicator_enterprise: "Kurumsal Bütçe",
  is_ecommerce:             "E-ticaret",
  mail_security:            "Mail Güvenliği",
  has_fortinet:             "Fortinet",
  has_waf:                  "WAF Aktif",
  waf_detected:             "WAF Tespit Edildi",
  open_rdp:                 "Açık RDP",
  cloud_hosted:             "Bulut Altyapı",
  has_citrix:               "Citrix",
  has_cisco:                "Cisco",
  has_paloalto:             "Palo Alto",
  has_checkpoint:           "Check Point",
  legacy_iis:               "Eski IIS",
  exposed_phpmyadmin:       "phpMyAdmin Açık",
  // ── category değerleri (t.category için fallback) ───────────────
  cdn:                      "CDN",
  waf:                      "WAF / Güvenlik Duvarı",
  analytics:                "Analitik Aracı",
  dns_provider:             "DNS Sağlayıcı",
  missing_header:           "Eksik HTTP Başlığı",
  mail:                     "E-posta Altyapısı",
  webserver:                "Web Sunucusu",
  hosting:                  "Hosting",
  firewall:                 "Güvenlik Duvarı",
  open_port:                "Açık Port",
  framework:                "Framework",
  language:                 "Programlama Dili",
  tls_version:              "TLS Sürümü",
  monitoring:               "İzleme",
  tag_manager:              "Etiket Yöneticisi",
  cms:                      "İçerik Yönetimi",
  ssl_ca:                   "SSL Sertifikası",
  ecommerce:                "E-ticaret Altyapısı",
  crm:                      "CRM",
  support:                  "Canlı Destek",
  payment:                  "Ödeme Altyapısı",
  mail_marketing:           "E-posta Pazarlama",
  company_name_from_cert:   "Şirket (Sertifikadan)",
};

const CLASSIFICATION_LABELS: Record<string, string> = {
  web_app: "Web Uygulaması", api: "API", redirect: "Yönlendirme (3xx)",
  error_4xx: "Hata (4xx)", error_5xx: "Sunucu Hatası (5xx)",
  unreachable: "Erişilemiyor", unknown: "Bilinmiyor",
};

interface DomainScan {
  id: number;
  domain: string;
  overallScore: number;
  spfPass: boolean;
  spfRecord: string | null;
  dmarcPass: boolean;
  dmarcRecord: string | null;
  dkimPass: boolean;
  dkimSelectors: string[];
  mxPass: boolean;
  mxRecords: Array<{ exchange: string; priority: number }>;
  sslPass: boolean;
  sslExpiry: string | null;
  sslIssuer: string | null;
  sslDaysUntilExpiry: number | null;
  hibpBreachCount: number;
  hibpBreaches: Array<{ name: string; breachDate: string; pwnCount: number; dataClasses: string[] }>;
  blacklisted: boolean;
  blacklistCount: number;
  shadowItServices: Array<{ name: string; category: string; risk: string; description: string; version?: string }>;
  httpHeadersScore: number;
  httpHeadersDetails: { hsts: boolean; xFrameOptions: boolean; xContentTypeOptions: boolean; csp: boolean; referrerPolicy: boolean } | null;
  urlhausListed: boolean;
  urlhausThreat: string | null;
  usomListed: boolean;
  cveSummary: Array<{ service: string; cveId: string; description: string; cvssScore: number }>;
  shodanOpenPorts: Array<{ port: number; protocol: string; service: string; product: string; version: string }> | null;
  shodanVulnCount: number;
  virusTotalMalicious: number;
  virusTotalSuspicious: number;
  safeBrowsingFlagged: boolean | null;
  wafDetected: boolean | null;
  wafProvider: string | null;
  confidenceScore: number | null;
  ctSubdomainCount: number;
  ctSubdomains: string[];
  sslLabsGrade: string | null;
  createdAt: string;
}

const CVE_DESCS: Record<string, string> = {
  "CVE-2007-6013": "Eski Wordpress gizli anahtar ifşası — güncelleme gerekli",
  "CVE-2016-1209": "Crypt_Blowfish sabit zamanlı karşılaştırma bypass — kimlik doğrulama riski",
  "CVE-2014-3704": "Drupal SQL injection (Drupalgeddon) — kritik",
  "CVE-2017-5638": "Apache Struts RCE — uzaktan kod çalıştırma",
  "CVE-2021-44228": "Log4Shell — Java Log4j uzaktan kod çalıştırma",
};

function FindingBadges({ highlights }: { highlights: string[] | null }) {
  if (!highlights || highlights.length === 0) return <span className="text-xs text-muted-foreground">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {highlights.map((h) => {
        const isCve = h.startsWith("CVE-");
        const desc = CVE_DESCS[h];
        return isCve ? (
          <a
            key={h}
            href={`https://nvd.nist.gov/vuln/detail/${h}`}
            target="_blank"
            rel="noopener noreferrer"
            title={desc ?? h}
            className="inline-block text-[10px] px-1.5 py-0.5 rounded bg-red-50 text-red-700 border border-red-200 hover:bg-red-100 font-mono"
          >
            {h}
          </a>
        ) : (
          <span key={h} className="inline-block text-[10px] px-1.5 py-0.5 rounded bg-orange-50 text-orange-700 border border-orange-200">
            {h}
          </span>
        );
      })}
    </div>
  );
}

function statusBadge(status: string) {
  const map: Record<string, string> = {
    pending: "bg-gray-100 text-gray-700",
    scanning: "bg-blue-100 text-blue-700",
    scanned: "bg-green-100 text-green-700",
    failed: "bg-red-100 text-red-700",
    disqualified: "bg-orange-100 text-orange-700",
  };
  const labels: Record<string, string> = {
    pending: "Bekliyor", scanning: "Taranıyor", scanned: "Tarandı",
    failed: "Hata", disqualified: "Elendi",
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${map[status] ?? "bg-gray-100 text-gray-600"}`}>
      {labels[status] ?? status}
    </span>
  );
}

function runStatusBadge(status: string) {
  if (status === "completed") return <Badge className="bg-green-100 text-green-700">Tamamlandı</Badge>;
  if (status === "running") return <Badge className="bg-blue-100 text-blue-700">Çalışıyor</Badge>;
  if (status === "failed") return <Badge className="bg-red-100 text-red-700">Hata</Badge>;
  return <Badge variant="secondary">{status}</Badge>;
}

interface TechStackItem {
  vendor: string;
  product?: string | null;
  category: string;
  salesSignal: string | null;
  securityRisk: string | null;
  securityNote?: string | null;
  evidence?: Record<string, unknown> | null;
}

interface CertstreamStatusData {
  bridgeActive: boolean;
  lastRunAt: string | null;
  lastRunSource: string | null;
  lastRunAdded: number;
  lastRunFound: number;
  totalLeads: number;
  totalAdded24h: number;
  totalFound24h: number;
  runs24h: number;
  recentRuns: Array<{
    id: number;
    source: string;
    status: string;
    totalFound: number;
    totalAdded: number;
    startedAt: string;
    completedAt: string | null;
  }>;
}

function RipeDnsWidget() {
  const { toast } = useToast();
  const qc = useQueryClient();

  const startRipe = useMutation({
    mutationFn: () =>
      fetch(`${BASE}/lead-discovery/ripe-dns`, { method: "POST" }).then((r) => r.json()),
    onSuccess: () => {
      toast({ description: "RIPE DNS keşfi arka planda başlatıldı." });
      qc.invalidateQueries({ queryKey: ["lead-discovery-stats"] });
    },
    onError: () => toast({ variant: "destructive", description: "RIPE DNS keşfi başlatılamadı." }),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>RIPE DNS Keşfi</CardTitle>
        <CardDescription>
          Türkiye IPv4 prefix'lerinden reverse DNS ile .tr domain keşfi — API key gerektirmez.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="bg-muted/40 rounded-md p-4 text-sm space-y-2">
          <div className="font-medium">Nasıl çalışır?</div>
          <ul className="text-xs space-y-0.5 list-disc list-inside text-muted-foreground">
            <li>stat.ripe.net → Türkiye IPv4 prefix listesi (~2000 prefix)</li>
            <li>Her prefix'ten örneklem IP seç, HackerTarget reverse DNS sorgula</li>
            <li>.tr uzantılı root domain'leri lead_candidates'e ekle</li>
            <li>Bulunan root domain'ler için HackerTarget subdomain lookup</li>
            <li>Rate limit: ~100 istek/gün → maxPrefixes=60 güvenli; gece 02:00 otomatik çalışır</li>
          </ul>
        </div>
        <div className="flex items-center gap-3">
          <Button onClick={() => startRipe.mutate()} disabled={startRipe.isPending}>
            {startRipe.isPending ? "Başlatılıyor..." : "RIPE DNS Keşfini Başlat"}
          </Button>
          <span className="text-xs text-muted-foreground">
            Tahmini süre: 5-15 dk. Arka planda çalışır.
          </span>
        </div>
        <div className="bg-blue-50 border border-blue-200 rounded-md p-3 text-xs text-blue-800">
          Otomatik çalışma: Her gece 02:00 (İstanbul saati). Gündüz test için yukarıdaki butonu kullanın.
        </div>
      </CardContent>
    </Card>
  );
}

function CertstreamWidget() {
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: cs, isLoading } = useQuery<CertstreamStatusData>({
    queryKey: ["certstream-status"],
    queryFn: () => fetch(`${BASE}/lead-discovery/certstream/status`).then((r) => r.json()),
    refetchInterval: 30_000,
  });

  const dispatch = useMutation({
    mutationFn: () =>
      fetch(`${BASE}/lead-discovery/certstream/dispatch`, { method: "POST" }).then((r) => r.json()),
    onSuccess: (data: { ok?: boolean; error?: string }) => {
      if (data?.error) { toast({ variant: "destructive", description: data.error }); return; }
      toast({ description: "GitHub Actions dispatch tetiklendi. ~2 dk içinde yeni lead'ler gelecek." });
      setTimeout(() => qc.invalidateQueries({ queryKey: ["certstream-status"] }), 5000);
    },
    onError: () => toast({ variant: "destructive", description: "Dispatch başarısız." }),
  });

  function toUtcDate(d: string | null | undefined): Date | null {
    if (!d) return null;
    // Drizzle timestamp() stringleri "Z" olmadan gelir; browser olmadan UTC olarak yorumlar
    const s = /[Zz]|[+-]\d{2}:?\d{2}/.test(d) ? d : d + "Z";
    return new Date(s);
  }

  const lastRunAgo = cs?.lastRunAt
    ? Math.round((Date.now() - (toUtcDate(cs.lastRunAt)?.getTime() ?? 0)) / 1000 / 60)
    : null;

  const isBridgeRecent = lastRunAgo != null && lastRunAgo < 120;

  function fmtDate(d: string | null) {
    if (!d) return "—";
    return (toUtcDate(d) ?? new Date(d)).toLocaleString("tr-TR", { dateStyle: "short", timeStyle: "short" });
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>CT Log Bridge — GitHub Actions</CardTitle>
            <CardDescription>
              certstream-server-go GitHub Actions VM'de çalışır, yakalanan .tr domainleri /api/internal/cert-ingest üzerinden lead_candidates'e aktarılır.
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <span className={`inline-block w-2.5 h-2.5 rounded-full ${isBridgeRecent ? "bg-green-500 animate-pulse" : "bg-slate-400"}`} />
            <span className={`text-sm font-medium ${isBridgeRecent ? "text-green-700" : "text-slate-500"}`}>
              {isBridgeRecent ? "Bridge Aktif" : lastRunAgo == null ? "Veri Yok" : `Son çalışma: ${lastRunAgo}dk önce`}
            </span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-5">
        {isLoading ? (
          <div className="text-sm text-muted-foreground">Yükleniyor...</div>
        ) : (
          <>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {[
                { label: "Son çalışma", value: lastRunAgo != null ? `${lastRunAgo} dk önce` : "—" },
                { label: "Son run eklenen", value: (cs?.lastRunAdded ?? 0).toLocaleString("tr-TR") },
                { label: "Son run bulunan", value: (cs?.lastRunFound ?? 0).toLocaleString("tr-TR") },
                { label: "Son 24s run sayısı", value: (cs?.runs24h ?? 0).toString() },
                { label: "Son 24s eklenen", value: (cs?.totalAdded24h ?? 0).toLocaleString("tr-TR") },
                { label: "CT bridge toplam", value: (cs?.totalLeads ?? 0).toLocaleString("tr-TR") },
              ].map((s) => (
                <div key={s.label} className="bg-muted/40 rounded-md px-3 py-2.5">
                  <div className="text-lg font-bold">{s.value}</div>
                  <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
                </div>
              ))}
            </div>

            <div className="bg-blue-50 border border-blue-200 rounded-md p-3 text-sm text-blue-800 space-y-1">
              <div className="font-medium">Nasıl çalışır?</div>
              <ul className="text-xs space-y-0.5 list-disc list-inside text-blue-700">
                <li>Saatte bir sunucumuz GitHub Actions'a workflow_dispatch gönderir (:05 dakikasında)</li>
                <li>GitHub Actions VM'de certstream-server-go başlar, tüm CT loglarını dinler (~8 dk)</li>
                <li>.tr TLD'li domainleri tespit eder, /api/internal/cert-ingest'e batch gönderir</li>
                <li>Ingest endpoint lead_candidates tablosuna UNIQUE constraint ile ekler</li>
                <li>BGP/RIPE bridge da aynı ingest endpoint'i kullanır (source: bgptools)</li>
              </ul>
            </div>

            {cs?.recentRuns && cs.recentRuns.length > 0 && (
              <div className="space-y-1.5">
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Son Çalışmalar</p>
                <div className="space-y-1.5">
                  {cs.recentRuns.map((r) => (
                    <div key={r.id} className="flex items-center justify-between gap-2 rounded-md border px-3 py-2 text-xs bg-muted/20">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="font-mono text-[11px] truncate text-foreground">{r.source}</span>
                        <span className="text-muted-foreground shrink-0">{fmtDate(r.startedAt)}</span>
                      </div>
                      <div className="flex items-center gap-3 shrink-0">
                        <span className="text-muted-foreground">{r.totalFound.toLocaleString("tr-TR")} bulundu</span>
                        <span className="font-medium text-emerald-700">+{r.totalAdded.toLocaleString("tr-TR")}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="flex items-center gap-3">
              <Button onClick={() => dispatch.mutate()} disabled={dispatch.isPending} variant="outline" size="sm">
                {dispatch.isPending ? "Çalıştırılıyor..." : "Şimdi Çalıştır"}
              </Button>
              <span className="text-xs text-muted-foreground">
                Otomatik: her saat :05. Manuel tetikleme ~2 dk sonra sonuç verir.
              </span>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

// ─── ISP Grup tipi ────────────────────────────────────────────────────────────
interface IspGroup {
  normalizedName: string;
  isActivePartnership: boolean;
  partnerContact: string | null;
  count: number;
  avgRiskScore: number;
  criticalFindingsTotal: number;
  lastScannedAt: string | null;
  leads: Array<{
    id: number;
    domain: string;
    companyName: string | null;
    riskScore: number | null;
    criticalFindings: number;
    ispOrganization: string | null;
    contactEmail: string | null;
    teaserSentAt: string | null;
    tier: string | null;
  }>;
}

interface IspPartnerRow {
  id: number;
  organizationNamePattern: string;
  partnerName: string;
  partnerContact: string | null;
  isActivePartnership: boolean;
}

function exportGroupToCsv(group: IspGroup) {
  const header = "Domain,Şirket,Risk Skoru,Kritik Bulgular,E-posta,Tier,ISP\n";
  const rows = group.leads.map(l =>
    [l.domain, l.companyName ?? "", l.riskScore ?? 0, l.criticalFindings, l.contactEmail ?? "", l.tier ?? "", l.ispOrganization ?? ""].join(",")
  ).join("\n");
  const blob = new Blob([header + rows], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url;
  a.download = `isp-${group.normalizedName.replace(/\s+/g, "-")}-leads.csv`;
  a.click(); URL.revokeObjectURL(url);
}

function IspGroupsView() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set());
  const [showPartnerMgmt, setShowPartnerMgmt] = useState(false);
  const [newPattern, setNewPattern] = useState("");
  const [newName, setNewName] = useState("");
  const [newContact, setNewContact] = useState("");

  const BASE = "/api/admin-panel/lead-discovery";

  const { data: groups, isLoading } = useQuery<IspGroup[]>({
    queryKey: ["isp-groups"],
    queryFn: () => fetch(`${BASE}/isp-groups`).then(r => r.json()),
  });

  const { data: partners } = useQuery<IspPartnerRow[]>({
    queryKey: ["isp-partners"],
    queryFn: () => fetch(`${BASE}/isp-partners`).then(r => r.json()),
    enabled: showPartnerMgmt,
  });

  const togglePartnership = useMutation({
    mutationFn: ({ id, val }: { id: number; val: boolean }) =>
      fetch(`${BASE}/isp-partners/${id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ isActivePartnership: val }) }).then(r => r.json()),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["isp-partners"] }); queryClient.invalidateQueries({ queryKey: ["isp-groups"] }); },
  });

  const addPartner = useMutation({
    mutationFn: () =>
      fetch(`${BASE}/isp-partners`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ organizationNamePattern: newPattern, partnerName: newName, partnerContact: newContact || undefined }) }).then(r => r.json()),
    onSuccess: () => {
      toast({ description: "ISP pattern eklendi." });
      setNewPattern(""); setNewName(""); setNewContact("");
      queryClient.invalidateQueries({ queryKey: ["isp-partners"] });
    },
  });

  const backfill = useMutation({
    mutationFn: () => fetch(`${BASE}/isp-backfill`, { method: "POST" }).then(r => r.json()),
    onSuccess: (d: { updated: number }) => {
      toast({ description: `${d.updated} lead güncellendi.` });
      queryClient.invalidateQueries({ queryKey: ["isp-groups"] });
    },
  });

  const toggleGroup = (name: string) => {
    setOpenGroups(prev => {
      const next = new Set(prev);
      next.has(name) ? next.delete(name) : next.add(name);
      return next;
    });
  };

  const riskColor = (score: number | null) => {
    if (!score) return "text-muted-foreground";
    if (score >= 70) return "text-red-600 font-semibold";
    if (score >= 40) return "text-amber-600 font-semibold";
    return "text-green-600";
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div>
              <CardTitle>ISP / Operatör Bazlı Lead Grupları</CardTitle>
              <CardDescription>
                Shodan org alanına göre normalize edilmiş {groups?.length ?? 0} operatör —{" "}
                {groups?.reduce((s, g) => s + g.count, 0) ?? 0} kalifikasyonlu lead
              </CardDescription>
            </div>
            <div className="flex gap-2 flex-wrap">
              <Button size="sm" variant="outline" onClick={() => backfill.mutate()} disabled={backfill.isPending} className="text-xs">
                {backfill.isPending ? "Çalışıyor..." : "Backfill ISP"}
              </Button>
              <Button size="sm" variant={showPartnerMgmt ? "default" : "outline"} onClick={() => setShowPartnerMgmt(p => !p)} className="text-xs">
                Partner Yönetimi
              </Button>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Partner Yönetimi Paneli */}
      {showPartnerMgmt && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">ISP Pattern Yönetimi</CardTitle>
            <CardDescription>Shodan org alanı bu pattern'larla ILIKE eşleştirilir ve normalize edilir.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-wrap gap-2 items-end">
              <div className="flex flex-col gap-1">
                <label className="text-xs text-muted-foreground">Pattern (% wildcard)</label>
                <Input placeholder="%Turk Telekomunikasyon%" value={newPattern} onChange={e => setNewPattern(e.target.value)} className="h-8 text-sm w-56" />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-muted-foreground">Normalize isim</label>
                <Input placeholder="Türk Telekom" value={newName} onChange={e => setNewName(e.target.value)} className="h-8 text-sm w-40" />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-muted-foreground">Kontak (opsiyonel)</label>
                <Input placeholder="ornek@isp.com" value={newContact} onChange={e => setNewContact(e.target.value)} className="h-8 text-sm w-40" />
              </div>
              <Button size="sm" onClick={() => addPartner.mutate()} disabled={!newPattern || !newName || addPartner.isPending}>Ekle</Button>
            </div>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Pattern</TableHead>
                    <TableHead>Partner Adı</TableHead>
                    <TableHead>Kontak</TableHead>
                    <TableHead>İş Birliği</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(partners ?? []).map(p => (
                    <TableRow key={p.id}>
                      <TableCell className="font-mono text-xs">{p.organizationNamePattern}</TableCell>
                      <TableCell className="text-sm">{p.partnerName}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{p.partnerContact ?? "—"}</TableCell>
                      <TableCell>
                        <Button
                          size="sm"
                          variant={p.isActivePartnership ? "default" : "outline"}
                          className={`text-xs h-6 ${p.isActivePartnership ? "bg-green-600 hover:bg-green-700" : ""}`}
                          onClick={() => togglePartnership.mutate({ id: p.id, val: !p.isActivePartnership })}
                        >
                          {p.isActivePartnership ? "Aktif Partner" : "Potansiyel"}
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {!(partners?.length) && (
                    <TableRow><TableCell colSpan={4} className="text-center text-muted-foreground py-4 text-sm">Henüz pattern yok.</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Gruplar — Accordion */}
      {isLoading && <div className="text-center text-muted-foreground py-12 text-sm">Yükleniyor...</div>}
      {!isLoading && !(groups?.length) && (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground text-sm">
            ISP bilgisi olan kalifikasyonlu lead bulunamadı. Backfill butonunu çalıştırın.
          </CardContent>
        </Card>
      )}
      {(groups ?? []).map(group => {
        const isOpen = openGroups.has(group.normalizedName);
        return (
          <Card key={group.normalizedName} className={group.isActivePartnership ? "border-green-500/40" : ""}>
            <button
              className="w-full text-left px-5 py-4 flex items-center gap-3 hover:bg-muted/30 transition-colors"
              onClick={() => toggleGroup(group.normalizedName)}
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-semibold text-sm">{group.normalizedName}</span>
                  {group.isActivePartnership ? (
                    <Badge className="bg-green-100 text-green-700 border border-green-300 text-[10px] px-1.5 py-0">Partner</Badge>
                  ) : (
                    <Badge variant="outline" className="text-[10px] px-1.5 py-0 text-muted-foreground">Potansiyel</Badge>
                  )}
                </div>
                <div className="flex gap-4 mt-1 text-xs text-muted-foreground flex-wrap">
                  <span><span className="font-medium text-foreground">{group.count}</span> lead</span>
                  <span>Ort. risk <span className={riskColor(group.avgRiskScore)}>{group.avgRiskScore}/100</span></span>
                  <span><span className="text-red-600 font-medium">{group.criticalFindingsTotal}</span> kritik bulgu</span>
                  {group.lastScannedAt && <span>Son tarama: {new Date(group.lastScannedAt).toLocaleDateString("tr-TR")}</span>}
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <Button
                  size="sm"
                  variant="outline"
                  className="text-xs h-7"
                  onClick={e => { e.stopPropagation(); exportGroupToCsv(group); }}
                >
                  CSV
                </Button>
                {isOpen ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
              </div>
            </button>

            {isOpen && (
              <div className="border-t">
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Domain</TableHead>
                        <TableHead>Şirket</TableHead>
                        <TableHead className="text-right">Risk</TableHead>
                        <TableHead className="text-right">Kritik</TableHead>
                        <TableHead>E-posta</TableHead>
                        <TableHead>Tier</TableHead>
                        <TableHead>ISP (raw)</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {group.leads.map(lead => (
                        <TableRow key={lead.id}>
                          <TableCell className="font-mono text-xs">{lead.domain}</TableCell>
                          <TableCell className="text-xs text-muted-foreground max-w-[160px] truncate">{lead.companyName ?? "—"}</TableCell>
                          <TableCell className={`text-right text-xs ${riskColor(lead.riskScore)}`}>{lead.riskScore ?? "—"}</TableCell>
                          <TableCell className="text-right text-xs">{lead.criticalFindings > 0 ? <span className="text-red-600 font-semibold">{lead.criticalFindings}</span> : "0"}</TableCell>
                          <TableCell className="text-xs text-muted-foreground">{lead.contactEmail ?? "—"}</TableCell>
                          <TableCell>
                            {lead.tier ? (
                              <span className={`text-[10px] font-bold border rounded px-1.5 py-0.5 ${
                                lead.tier === "tier1"
                                  ? "bg-green-100 text-green-700 border-green-300"
                                  : lead.tier === "tier2"
                                  ? "bg-blue-100 text-blue-700 border-blue-300"
                                  : "bg-orange-100 text-orange-700 border-orange-300"
                              }`}>
                                {lead.tier === "tier1" ? "T1" : lead.tier === "tier2" ? "T2" : "T3"}
                              </span>
                            ) : <span className="text-[10px] text-muted-foreground">—</span>}
                          </TableCell>
                          <TableCell className="text-[10px] text-muted-foreground max-w-[180px] truncate">{lead.ispOrganization ?? "—"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>
            )}
          </Card>
        );
      })}
    </div>
  );
}

type _BistCveItem = { service: string; cveId: string; description: string; cvssScore: number };
type _BistCveCo = { ticker: string; company_name: string; domain: string; sector: string; market: string; is_bist30: boolean; is_bist100: boolean; is_bist500: boolean; critical_cve_count: number; cve_list: _BistCveItem[] };

function BistDrillRow({ co }: { co: _BistCveCo }) {
  const [open, setOpen] = useState(false);
  const indexes = [co.is_bist30 && "BIST 30", co.is_bist100 && "BIST 100", co.is_bist500 && "BIST 500"].filter(Boolean).join(", ");
  return (
    <div className="border rounded-lg overflow-hidden">
      <button
        className="w-full flex items-center justify-between gap-2 px-3 py-2.5 text-left hover:bg-muted/40 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <div className="flex items-center gap-2 min-w-0">
          {co.ticker && <span className="font-mono text-xs font-bold text-primary shrink-0">{co.ticker}</span>}
          <span className="text-xs font-medium truncate">{co.company_name || co.domain}</span>
          <span className="text-[10px] text-muted-foreground truncate hidden sm:block">{co.domain}</span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {indexes && <span className="text-[10px] text-muted-foreground">{indexes}</span>}
          <span className="text-[10px] bg-red-600/20 text-red-400 border border-red-600/30 rounded px-1.5 py-0.5">{co.critical_cve_count} kritik</span>
          {open ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />}
        </div>
      </button>
      {open && (
        <div className="border-t bg-muted/20 px-3 py-2 space-y-2">
          {co.cve_list.length === 0 ? (
            <p className="text-xs text-muted-foreground py-1">CVE detayı yüklenemedi — tarama verisi eksik olabilir</p>
          ) : co.cve_list.map(cve => (
            <div key={cve.cveId} className="flex items-start justify-between gap-3 text-xs">
              <div className="min-w-0 space-y-0.5">
                <a
                  href={`https://www.cve.org/CVERecord?id=${cve.cveId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono font-bold text-cyan-400 hover:underline"
                >
                  {cve.cveId}
                </a>
                {cve.service && <div className="text-[10px] text-muted-foreground">Servis: {cve.service}</div>}
                {cve.description && <p className="text-muted-foreground line-clamp-2">{cve.description}</p>}
              </div>
              <span className="font-bold text-red-400 shrink-0">CVSS {cve.cvssScore?.toFixed(1)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function AdminLeadDiscovery() {
  const { toast } = useToast();
  const qc = useQueryClient();

  // ─── crt.sh form state ───────────────────────────────────────────────────
  const [crtshTlds, setCrtshTlds] = useState<string[]>([".com.tr", ".net.tr"]);
  const [daysBack, setDaysBack] = useState(30);
  const [minScore, setMinScore] = useState(10);
  const [domainLimit, setDomainLimit] = useState(300);

  // ─── Shodan form state ───────────────────────────────────────────────────
  const [selectedShodanQueries, setSelectedShodanQueries] = useState<number[]>([0, 2, 4]);

  // ─── Results pagination ──────────────────────────────────────────────────
  const [page, setPage] = useState(1);
  const [qualifiedPage, setQualifiedPage] = useState(1);
  const [filterQualified, setFilterQualified] = useState(false);
  const [filterHasContact, setFilterHasContact] = useState(false);
  const [filterNotSent, setFilterNotSent] = useState(false);
  // ─── Qualified tab filters ────────────────────────────────────────────────
  const [qPage, setQPage] = useState(1);
  const [qPageSize, setQPageSize] = useState(50);
  const [qSearch, setQSearch] = useState("");
  const [qSearchInput, setQSearchInput] = useState("");
  const [qTier, setQTier] = useState("");
  const [qSort, setQSort] = useState("risk_desc");
  const [qContact, setQContact] = useState(""); // "" | "has" | "no"
  const [qTeaser, setQTeaser] = useState(""); // "" | "has" | "sent" | "notsent"
  const [qMinScore, setQMinScore] = useState(0);
  const [qCriticalPort, setQCriticalPort] = useState(false);
  const [qMunicipality, setQMunicipality] = useState<"" | "only" | "exclude">("");
  const [qSector, setQSector] = useState(""); // "" | "__empty__" | free text
  const [qCity, setQCity] = useState(""); // "" | "__empty__" | free text
  const [qBistOnly, setQBistOnly] = useState(false);
  const [qBistIndex, setQBistIndex] = useState(""); // "" | "bist30" | "bist100" | "bist500"
  const [qPageInput, setQPageInput] = useState("");
  const [filterTier, setFilterTier] = useState<string>(""); // "", "tier1", "tier2", "tier3"
  const [filterMunicipality, setFilterMunicipality] = useState<"" | "only" | "exclude">("");
  const [filterSector, setFilterSector] = useState(""); // "" | "__empty__" | free text
  const [filterCity, setFilterCity] = useState(""); // "" | "__empty__" | free text
  const [filterBistOnly, setFilterBistOnly] = useState(false);
  const [filterBistIndex, setFilterBistIndex] = useState(""); // "" | "bist30" | "bist100" | "bist500"
  const [filterSource, setFilterSource] = useState("");
  const [filterScanStatus, setFilterScanStatus] = useState("");
  const [filterIsAlive, setFilterIsAlive] = useState(""); // "" | "true" | "false"
  const [filterHasFortigate, setFilterHasFortigate] = useState(false);
  const [teaserPreview, setTeaserPreview] = useState<LeadCandidate | null>(null);
  const [detailCandidate, setDetailCandidate] = useState<LeadCandidate | null>(null);
  const [detailEditOpen, setDetailEditOpen] = useState(false);
  const [detailEditFields, setDetailEditFields] = useState<{
    companyName: string; sector: string; subSector: string; city: string;
    ticker: string; bistIndexes: string; bistMarket: string; isPublicCompany: boolean;
    sourceList: string; tier: string; notes: string;
  }>({ companyName: "", sector: "", subSector: "", city: "", ticker: "", bistIndexes: "", bistMarket: "", isPublicCompany: false, sourceList: "", tier: "", notes: "" });
  const [detailEditSaving, setDetailEditSaving] = useState(false);
  const [fingerprintResult, setFingerprintResult] = useState<{ stack: TechStackItem[]; stackCount: number; maturity: { score: number; level: string } | null } | null>(null);
  const [filterNoContact, setFilterNoContact] = useState(false);
  const [isrNotesEdit, setIsrNotesEdit] = useState("");
  const [isrOpen, setIsrOpen] = useState(false);
  const [contactEditTarget, setContactEditTarget] = useState<LeadCandidate | null>(null);
  const [editEmail, setEditEmail] = useState("");
  const [editName, setEditName] = useState("");
  const [editTitle, setEditTitle] = useState("");
  // ─── BIST Retag ───────────────────────────────────────────────────────────
  const [bistRetagInput, setBistRetagInput] = useState("");
  const [bistRetagLoading, setBistRetagLoading] = useState(false);
  const [bistRetagResult, setBistRetagResult] = useState<{ updated: number; notFound: string[] } | null>(null);
  const [bistCveCompany, setBistCveCompany] = useState<BistTopRow | null>(null);
  const [bistDrillFilter, setBistDrillFilter] = useState<"all" | "bist30" | "bist100" | "bist500" | null>(null);

  // ─── CVE Raporu tab ───────────────────────────────────────────────────────
  const [cveMinCvss, setCveMinCvss] = useState("0.0");

  // ─── Sonuçlar tab arama ───────────────────────────────────────────────────
  const [resultsSearchInput, setResultsSearchInput] = useState("");
  const [resultsSearch, setResultsSearch] = useState("");
  const [isExporting, setIsExporting] = useState(false);
  const [isExportingQualified, setIsExportingQualified] = useState(false);

  async function handleExcelExport() {
    if (isExporting) return;
    setIsExporting(true);
    try {
      const params = new URLSearchParams();
      if (resultsSearch) params.set("search", resultsSearch);
      if (filterTier) params.set("tier", filterTier);
      if (filterHasContact) params.set("hasContact", "true");
      if (filterNotSent) params.set("notSent", "true");
      if (filterMunicipality) params.set("municipality", filterMunicipality);
      if (filterSector === "__empty__") params.set("sectorEmpty", "true");
      else if (filterSector) params.set("sector", filterSector);
      if (filterCity === "__empty__") params.set("cityEmpty", "true");
      else if (filterCity) params.set("city", filterCity);

      const res = await fetch(`${BASE}/lead-discovery/export?${params}`, { credentials: "include" });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: "Bilinmeyen hata" }));
        toast({ description: (err as { error?: string }).error ?? "Export başarısız", variant: "destructive" });
        return;
      }
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      const today = new Date().toISOString().slice(0, 10);
      a.href     = url;
      a.download = `cyberstep_domains_${today}.xlsx`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      const total = res.headers.get("X-Total-Count");
      toast({ description: `${total ?? ""} kayıt Excel dosyası indirildi.` });
    } catch {
      toast({ description: "Export sırasında hata oluştu.", variant: "destructive" });
    } finally {
      setIsExporting(false);
    }
  }

  async function handleQualifiedExcelExport() {
    if (isExportingQualified) return;
    setIsExportingQualified(true);
    try {
      const params = new URLSearchParams();
      if (qSearch)          params.set("search", qSearch);
      if (qTier)            params.set("tier", qTier);
      if (qContact === "has") params.set("hasContact", "true");
      if (qContact === "no")  params.set("noContact", "true");
      if (qTeaser === "sent")    params.set("teaserSent", "true");
      if (qTeaser === "has")     params.set("hasTeaser", "true");
      if (qTeaser === "notsent") params.set("notSent", "true");
      if (qMinScore > 0)    params.set("minScore", String(qMinScore));
      if (qCriticalPort)    params.set("criticalPort", "true");
      if (qMunicipality)    params.set("municipality", qMunicipality);
      if (qSector === "__empty__") params.set("sectorEmpty", "true");
      else if (qSector)     params.set("sector", qSector);
      if (qCity === "__empty__") params.set("cityEmpty", "true");
      else if (qCity)       params.set("city", qCity);
      if (qBistOnly)        params.set("bistOnly", "true");
      if (qBistIndex)       params.set("bistIndex", qBistIndex);

      const res = await fetch(`${BASE}/lead-discovery/export-qualified?${params}`, { credentials: "include" });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: "Bilinmeyen hata" }));
        toast({ description: (err as { error?: string }).error ?? "Export başarısız", variant: "destructive" });
        return;
      }
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      const today = new Date().toISOString().slice(0, 10);
      a.href     = url;
      a.download = `cyberstep_qualified_${today}.xlsx`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      const total = res.headers.get("X-Total-Count");
      toast({ description: `${total ?? ""} qualified lead Excel dosyası indirildi.` });
    } catch {
      toast({ description: "Export sırasında hata oluştu.", variant: "destructive" });
    } finally {
      setIsExportingQualified(false);
    }
  }

  // ── Lead Import Merkezi ────────────────────────────────────────────────────
  const [importTab, setImportTab] = useState("excel");
  const [manualInput, setManualInput] = useState("");
  const [manualLookupInput, setManualLookupInput] = useState("");
  const [manualLookupResult, setManualLookupResult] = useState<{ rows: LeadCandidate[]; total: number } | null>(null);
  const [manualLookupLoading, setManualLookupLoading] = useState(false);
  const [singleDomain, setSingleDomain] = useState("");
  type ExcelRow = { domain: string; companyName?: string; sector?: string; subSector?: string; sourceList?: string; listRank?: string; city?: string; ticker?: string; companyEmail?: string; bistIndexes?: string; bistMarket?: string; address?: string };
  const [excelParsed, setExcelParsed] = useState<ExcelRow[]>([]);
  const [excelFileName, setExcelFileName] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [cveSeverity, setCveSeverity] = useState("");
  const [cveOnlyExploit, setCveOnlyExploit] = useState(false);
  const [cveOnlyKev, setCveOnlyKev] = useState(false);
  const [cveExpanded, setCveExpanded] = useState<Set<string>>(new Set());

  // ─── Queries ─────────────────────────────────────────────────────────────
  const { data: stats } = useQuery<Stats>({
    queryKey: ["lead-discovery-stats"],
    queryFn: () => fetch(`${BASE}/lead-discovery/stats`).then((r) => r.json()),
    refetchInterval: 15_000,
  });

  const {
    data: enrichmentDash,
    isLoading: enrichmentLoading,
    refetch: enrichmentRefetch,
    isFetching: enrichmentFetching,
  } = useQuery<EnrichmentDashboard>({
    queryKey: ["enrichment-dashboard"],
    queryFn: async () => {
      const r = await fetch(`${BASE}/enrichment/dashboard`, { credentials: "include" });
      if (!r.ok) throw new Error(`Dashboard alınamadı: ${r.status}`);
      return r.json() as Promise<EnrichmentDashboard>;
    },
    staleTime: 3 * 60 * 1000,
  });

  type BistIndexStat = { total: number; with_cve: number; avg_ai_score: number; critical_cve_count: number };
  type BistSectorRow = { sector: string; total: number; with_cve: number; critical_cve_count: number; avg_open_ports: number; avg_ai_score: number; risk_level: string };
  type BistMarketRow = { market: string; total: number; avg_ai_score: number; with_critical_cve: number };
  type BistCveItem = { service: string; cveId: string; description: string; cvssScore: number };
  type BistTopRow = { ticker: string; company_name: string; domain: string; sector: string; market: string; ai_score: number; critical_cve_count: number; open_ports_count: number; risk_level: string; cve_list?: BistCveItem[] };
  type BistCveCo = { ticker: string; company_name: string; domain: string; sector: string; market: string; is_bist30: boolean; is_bist100: boolean; is_bist500: boolean; critical_cve_count: number; cve_list: BistCveItem[] };
  type BistCard = { id: string; theme: string; title: string; stats: { label: string; value: string }[] };
  type BistAnalysis = {
    generated_at: string;
    summary: { total_bist_companies: number; with_domain: number; with_domain_pct: number; in_cyberstep_db: number; in_cyberstep_db_pct: number; with_cve: number; with_cve_pct: number; with_open_ports: number; with_critical_cve: number; avg_open_ports: number; avg_ai_score: number };
    by_index: { bist30: BistIndexStat; bist100: BistIndexStat; bist500: BistIndexStat };
    by_sector: BistSectorRow[];
    by_market: BistMarketRow[];
    top_risk_companies: BistTopRow[];
    critical_cve_companies: BistCveCo[];
    linkedin_cards: BistCard[];
  };
  const { data: bistAnalysis, isLoading: bistLoading, refetch: bistRefetch, isFetching: bistFetching } = useQuery<BistAnalysis>({
    queryKey: ["bist-analysis"],
    queryFn: async () => {
      const r = await fetch(`${BASE}/bist-analysis`, { credentials: "include" });
      if (!r.ok) throw new Error(`BIST analizi alınamadı: ${r.status}`);
      return r.json() as Promise<BistAnalysis>;
    },
    staleTime: 10 * 60 * 1000,
  });

  const [isNormalizingCities, setIsNormalizingCities] = useState(false);
  async function handleNormalizeCities() {
    if (isNormalizingCities) return;
    setIsNormalizingCities(true);
    try {
      const r = await fetch(`${BASE}/enrichment/normalize-cities`, { method: "POST", credentials: "include" });
      const data = await r.json() as { updated: number; details: { from: string; to: string; count: number }[] };
      toast({ description: `${data.updated} kayıt normalize edildi.` });
      void enrichmentRefetch();
    } catch {
      toast({ description: "Normalize işlemi başarısız.", variant: "destructive" });
    } finally {
      setIsNormalizingCities(false);
    }
  }

  const { data: portRisk, isLoading: portRiskLoading, refetch: portRiskRefetch, isFetching: portRiskFetching } = useQuery<PortRiskData>({
    queryKey: ["lead-discovery-port-risk"],
    queryFn: async () => {
      const r = await fetch(`${BASE}/lead-discovery/port-risk`, { credentials: "include" });
      if (!r.ok) throw new Error(`Port risk alınamadı: ${r.status}`);
      return r.json() as Promise<PortRiskData>;
    },
    staleTime: 5 * 60 * 1000,
  });

  const [portRiskFilter, setPortRiskFilter] = useState<"all" | "mysql" | "ftp" | "rdp" | "vnc" | "mongo" | "redis">("all");

  const { data: cveReport, isLoading: cveLoading, isFetching: cveFetching, refetch: cveRefetch } = useQuery<CveReport>({
    queryKey: ["lead-discovery-cve-report", cveMinCvss, cveSeverity, cveOnlyExploit, cveOnlyKev],
    queryFn: async () => {
      const params = new URLSearchParams({ minCvss: cveMinCvss });
      if (cveSeverity) params.set("severity", cveSeverity);
      if (cveOnlyExploit) params.set("exploit", "1");
      if (cveOnlyKev) params.set("kev", "1");
      const r = await fetch(`${BASE}/lead-discovery/cve-report?${params}`, { credentials: "include", cache: "no-store" });
      if (!r.ok) throw new Error(`CVE raporu alınamadı: ${r.status}`);
      return r.json() as Promise<CveReport>;
    },
    refetchInterval: 30_000,
  });

  const { data: runs } = useQuery<DiscoveryRun[]>({
    queryKey: ["lead-discovery-runs"],
    queryFn: () => fetch(`${BASE}/lead-discovery/runs?limit=20`).then((r) => r.json()),
    refetchInterval: 10_000,
  });

  const { data: candidateTechStack } = useQuery<TechStackItem[]>({
    queryKey: ["candidate-tech-stack", detailCandidate?.id],
    queryFn: () => fetch(`${BASE}/lead-discovery/candidates/${detailCandidate!.id}/tech-stack`, { credentials: "include" }).then((r) => r.json()),
    enabled: !!detailCandidate,
  });

  const { data: candidateDomainScan } = useQuery<DomainScan | null>({
    queryKey: ["candidate-domain-scan", detailCandidate?.domain],
    queryFn: async () => {
      const r = await fetch(`${BASE}/domain-scans/by-domain/${encodeURIComponent(detailCandidate!.domain)}`, { credentials: "include" });
      if (r.status === 404) return null;
      return r.json();
    },
    enabled: !!detailCandidate,
  });

  const { data: subdomainSummary, refetch: refetchSubdomains } = useQuery<SubdomainSummary>({
    queryKey: ["scan-subdomains", candidateDomainScan?.id],
    queryFn: () => fetch(`/api/domain-scan/${candidateDomainScan!.id}/subdomains`, { credentials: "include" }).then((r) => r.json()),
    enabled: !!candidateDomainScan?.id,
    refetchInterval: (query) => (query.state.data?.processing && query.state.data?.summary.total === 0) ? 5000 : false,
  });

  const probeMutation = useMutation({
    mutationFn: () =>
      fetch(`/api/admin-panel/domain-scans/probe-subdomains`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: detailCandidate!.domain, scanId: candidateDomainScan?.id }),
      }).then((r) => r.json()),
    onSuccess: () => { void refetchSubdomains(); },
  });

  const { data: shodanQueries } = useQuery<ShodanQuery[]>({
    queryKey: ["shodan-queries"],
    queryFn: () => fetch(`${BASE}/lead-discovery/shodan/queries`).then((r) => r.json()),
  });

  const { data: qualifiedData, isLoading: qualifiedLoading } = useQuery<{
    rows: LeadCandidate[]; total: number;
  }>({
    queryKey: ["lead-qualified", qPage, qPageSize, qSearch, qTier, qSort, qContact, qTeaser, qMinScore, qCriticalPort, qMunicipality, qSector, qCity, qBistOnly, qBistIndex],
    queryFn: () => {
      const params = new URLSearchParams({ page: String(qPage), pageSize: String(qPageSize), sortBy: qSort });
      if (qSearch) params.set("search", qSearch);
      if (qTier) params.set("tier", qTier);
      if (qContact === "has") params.set("hasContact", "true");
      if (qContact === "no") params.set("noContact", "true");
      if (qTeaser === "has") params.set("hasTeaser", "true");
      if (qTeaser === "sent") params.set("teaserSent", "true");
      if (qTeaser === "notsent") params.set("notSent", "true");
      if (qMinScore > 0) params.set("minScore", String(qMinScore));
      if (qCriticalPort) params.set("criticalPort", "true");
      if (qMunicipality) params.set("municipality", qMunicipality);
      if (qSector === "__empty__") params.set("sectorEmpty", "true");
      else if (qSector) params.set("sector", qSector);
      if (qCity === "__empty__") params.set("cityEmpty", "true");
      else if (qCity) params.set("city", qCity);
      if (qBistOnly) params.set("bistOnly", "true");
      if (qBistIndex) params.set("bistIndex", qBistIndex);
      return fetch(`${BASE}/lead-discovery/qualified?${params}`).then((r) => r.json());
    },
    refetchInterval: 30_000,
  });

  const { data: candidatesData, isLoading: candidatesLoading } = useQuery<{
    rows: LeadCandidate[]; total: number;
  }>({
    queryKey: ["lead-candidates", page, filterQualified, filterHasContact, filterNotSent, filterTier, filterMunicipality, resultsSearch, filterSector, filterCity, filterBistOnly, filterBistIndex, filterSource, filterScanStatus, filterIsAlive, filterHasFortigate],
    queryFn: () => {
      const params = new URLSearchParams({ page: String(page), pageSize: "20" });
      if (filterHasContact) params.set("hasContact", "true");
      if (filterNotSent) params.set("notSent", "true");
      if (filterMunicipality) params.set("municipality", filterMunicipality);
      if (resultsSearch) params.set("search", resultsSearch);
      if (filterSector === "__empty__") params.set("sectorEmpty", "true");
      else if (filterSector) params.set("sector", filterSector);
      if (filterCity === "__empty__") params.set("cityEmpty", "true");
      else if (filterCity) params.set("city", filterCity);
      if (filterBistOnly) params.set("bistOnly", "true");
      if (filterBistIndex) params.set("bistIndex", filterBistIndex);
      if (filterSource) params.set("source", filterSource);
      if (filterScanStatus) params.set("scanStatus", filterScanStatus);
      if (filterIsAlive) params.set("isAlive", filterIsAlive);
      if (filterHasFortigate) params.set("hasFortigate", "true");
      if (filterQualified) {
        return fetch(`${BASE}/lead-discovery/qualified?${params}`).then((r) => r.json());
      }
      if (filterTier) params.set("tier", filterTier);
      return fetch(`${BASE}/lead-discovery/candidates?${params}`).then((r) => r.json());
    },
    refetchInterval: 15_000,
  });

  // ─── Mutations ────────────────────────────────────────────────────────────
  const startCrtsh = useMutation({
    mutationFn: async () => {
      const results = await Promise.all(
        crtshTlds.map((query) =>
          fetch(`${BASE}/lead-discovery/crtsh`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query: `%${query}`, daysBack, minCorporateScore: minScore, limit: domainLimit }),
          }).then((r) => r.json())
        )
      );
      return results;
    },
    onSuccess: () => {
      toast({ description: "crt.sh taraması başlatıldı. Arka planda çalışıyor." });
      qc.invalidateQueries({ queryKey: ["lead-discovery-runs"] });
    },
  });

  const startShodan = useMutation({
    mutationFn: async () => {
      const results = await Promise.all(
        selectedShodanQueries.map((queryIndex) =>
          fetch(`${BASE}/lead-discovery/shodan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ queryIndex, maxResults: 100 }),
          }).then(async (r) => {
            const j = await r.json() as { error?: string };
            if (!r.ok) throw new Error(j.error ?? "Shodan hatası");
            return j;
          })
        )
      );
      return results;
    },
    onSuccess: () => {
      toast({ description: "Shodan taraması başlatıldı." });
      qc.invalidateQueries({ queryKey: ["lead-discovery-runs"] });
    },
    onError: (e: Error) => {
      toast({ variant: "destructive", description: e.message });
    },
  });

  const startFull = useMutation({
    mutationFn: () =>
      fetch(`${BASE}/lead-discovery/full`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          useCrtsh: crtshTlds.length > 0,
          useShodan: selectedShodanQueries.length > 0,
          autoQualify: true,
          maxDomains: domainLimit,
          crtshQueries: crtshTlds.map((t) => `%${t}`),
          shodanQueryIndexes: selectedShodanQueries,
        }),
      }).then((r) => r.json()),
    onSuccess: () => {
      toast({ description: "Tam pipeline başlatıldı. 2-3 saat sürebilir." });
    },
  });

  const pdfImport = useMutation({
    mutationFn: async () => {
      const r = await fetch(`${BASE}/lead-discovery/bulk-import-pdf`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domains: pdfLeads }),
      });
      return r.json() as Promise<{ inserted: number; skipped: number; total: number }>;
    },
    onSuccess: (d) => {
      toast({ description: `PDF import tamamlandı: ${d.inserted} eklendi, ${d.skipped} zaten vardı.` });
      qc.invalidateQueries({ queryKey: ["lead-stats"] });
    },
    onError: () => toast({ description: "PDF import başarısız.", variant: "destructive" }),
  });

  type DomainAddResult = { inserted: number; skipped: number; total: number; results: { domain: string; status: "inserted" | "exists" }[] };

  type DomainAddEnrichedResult = {
    inserted: number; enriched: number; unchanged: number; skipped: number; total: number;
    results: Array<{ domain: string; status: "inserted" | "enriched" | "unchanged" | "exists" }>;
  };
  const batchImport = useMutation({
    mutationFn: async ({ rows, source }: { rows: ExcelRow[]; source: string }) => {
      const CHUNK = 150;
      const acc: DomainAddEnrichedResult = { inserted: 0, enriched: 0, unchanged: 0, skipped: 0, total: 0, results: [] };
      for (let i = 0; i < rows.length; i += CHUNK) {
        const chunk = rows.slice(i, i + CHUNK);
        const r = await fetch(`${BASE}/lead-discovery/domain-add`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ rows: chunk, source }),
        });
        if (!r.ok) throw new Error("İstek başarısız");
        const d = await r.json() as DomainAddEnrichedResult;
        acc.inserted += d.inserted;
        acc.enriched += d.enriched;
        acc.unchanged += d.unchanged;
        acc.skipped += d.skipped;
        acc.total += d.total;
        acc.results.push(...d.results);
      }
      return acc;
    },
    onSuccess: (d) => {
      const parts: string[] = [];
      if (d.inserted > 0) parts.push(`${d.inserted} yeni eklendi`);
      if (d.enriched > 0) parts.push(`${d.enriched} mevcut zenginleştirildi`);
      if (d.unchanged > 0) parts.push(`${d.unchanged} değişmedi`);
      toast({ description: `Import tamamlandı: ${parts.join(", ")}.` });
      qc.invalidateQueries({ queryKey: ["lead-stats"] });
    },
    onError: () => toast({ description: "Import başarısız.", variant: "destructive" }),
  });

  const singleAdd = useMutation({
    mutationFn: async (domain: string) => {
      const r = await fetch(`${BASE}/lead-discovery/domain-add`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domains: [domain], source: "manual_single" }),
      });
      if (!r.ok) throw new Error("İstek başarısız");
      return r.json() as Promise<DomainAddResult>;
    },
    onSuccess: (d) => {
      if (d.results[0]?.status === "inserted") {
        setSingleDomain("");
        qc.invalidateQueries({ queryKey: ["lead-stats"] });
      }
    },
    onError: () => toast({ description: "Domain eklenemedi.", variant: "destructive" }),
  });

  const handleExcelUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setExcelFileName(file.name);
    setExcelParsed([]);
    batchImport.reset();
    const reader = new FileReader();
    reader.onload = async (evt) => {
      try {
        const XLSX = await import("xlsx");
        const wb = XLSX.read(evt.target?.result, { type: "array" });
        const ws = wb.Sheets[wb.SheetNames[0]];

        // Sütun başlıklarıyla oku (ilk satır header)
        const rawRows = XLSX.utils.sheet_to_json<Record<string, string>>(ws, { defval: "" });

        // Esnek başlık eşleştirmesi — büyük/küçük harf + Türkçe karakter toleranslı
        const normalize = (s: string) =>
          s.toLowerCase()
            .replace(/ş/g, "s").replace(/ç/g, "c").replace(/ğ/g, "g")
            .replace(/ü/g, "u").replace(/ö/g, "o").replace(/ı/g, "i")
            .replace(/[^a-z0-9]/g, "");

        const COLUMN_MAP: Record<string, keyof ExcelRow> = {
          // domain
          "domain": "domain", "websitesi": "domain", "internetadresi": "domain",
          "websiteniz": "domain", "webadres": "domain", "url": "domain",
          "website": "domain", "webadresi": "domain", "internetsitesi": "domain",
          "site": "domain", "weblink": "domain", "link": "domain",
          // companyName
          "firmaadi": "companyName", "sirketadi": "companyName", "sirketunvani": "companyName",
          "unvan": "companyName", "firmaad": "companyName", "adi": "companyName",
          "kurumadi": "companyName", "companyname": "companyName",
          "ortaklikadi": "companyName", "sirketismi": "companyName", "isim": "companyName",
          // sector
          "anasektor": "sector", "sektor": "sector", "sector": "sector",
          "anakategori": "sector", "kategori": "sector", "sektorgrubu": "sector",
          // subSector
          "altsektor": "subSector", "altkategori": "subSector", "altsektoraciklama": "subSector",
          "aciklama": "subSector",
          // sourceList
          "listekaynagi": "sourceList", "kaynak": "sourceList", "liste": "sourceList",
          // listRank
          "sira": "listRank", "sirakod": "listRank",
          "kod": "listRank", "no": "listRank",
          // city
          "sehir": "city", "il": "city", "city": "city",
          // ticker (BIST) — KAP ve diğer BIST veri kaynaklarından gelen tüm olası isimler
          "ticker": "ticker", "bistkodu": "ticker", "borsakodu": "ticker", "hissekodu": "ticker",
          "sembol": "ticker", "bistsembol": "ticker", "hissesembol": "ticker",
          "sirketkodu": "ticker", "menkulsembol": "ticker", "enstrumankodu": "ticker",
          "symbol": "ticker", "stocksymbol": "ticker", "code": "ticker",
          // companyEmail
          "email": "companyEmail", "eposta": "companyEmail", "mail": "companyEmail",
          "sirketmail": "companyEmail", "kurumsaleposta": "companyEmail",
          // bistIndexes
          "indexes": "bistIndexes", "endeks": "bistIndexes", "endeksler": "bistIndexes",
          "bistendeks": "bistIndexes", "bistendeksleri": "bistIndexes",
          "endeksbilgisi": "bistIndexes", "hangiendeks": "bistIndexes",
          // bistMarket
          "market": "bistMarket", "pazar": "bistMarket", "borsapazari": "bistMarket",
          "borsapazar": "bistMarket", "islemgoru": "bistMarket", "borsa": "bistMarket",
          // address
          "adres": "address", "address": "address", "sirketadresi": "address",
        };

        // Her header sütununu eşleştir
        let headerMap: Record<string, keyof ExcelRow> | null = null;
        if (rawRows.length > 0) {
          const keys = Object.keys(rawRows[0]);
          const mapped: Record<string, keyof ExcelRow> = {};
          for (const k of keys) {
            const n = normalize(k);
            if (COLUMN_MAP[n]) mapped[k] = COLUMN_MAP[n];
          }
          if (Object.values(mapped).includes("domain")) headerMap = mapped;
        }

        const urlRe = /^(https?:\/\/)?(www\.)?[a-z0-9-]+(\.[a-z]{2,})+/i;
        const seen = new Set<string>();
        const results: ExcelRow[] = [];

        if (headerMap) {
          // Header-based mode: structured column extraction
          for (const row of rawRows) {
            const get = (field: keyof ExcelRow) => {
              const key = Object.entries(headerMap!).find(([, v]) => v === field)?.[0];
              return key ? String(row[key] ?? "").trim() : "";
            };
            const rawDomain = get("domain");
            if (!rawDomain || rawDomain.length < 4) continue;
            const domain = rawDomain.replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/.*$/, "").trim().toLowerCase();
            if (!domain || seen.has(domain)) continue;
            seen.add(domain);
            results.push({
              domain,
              companyName: get("companyName") || undefined,
              sector: get("sector") || undefined,
              subSector: get("subSector") || undefined,
              sourceList: get("sourceList") || undefined,
              listRank: get("listRank") || undefined,
              city: get("city") || undefined,
              ticker: get("ticker") || undefined,
              companyEmail: get("companyEmail") || undefined,
              bistIndexes: get("bistIndexes") || undefined,
              bistMarket: get("bistMarket") || undefined,
              address: get("address") || undefined,
            });
          }
        } else {
          // Fallback: header yoksa veya domain sütunu eşleşmediyse — ilk URL'yi al (eski davranış)
          const fallbackRows = XLSX.utils.sheet_to_json<Record<string, string>>(ws, { header: "A", defval: "" });
          for (const row of fallbackRows) {
            for (const val of Object.values(row)) {
              const v = String(val ?? "").trim();
              if (!v || v.length < 4) continue;
              if (urlRe.test(v)) {
                const domain = v.replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/.*$/, "").trim().toLowerCase();
                if (domain && !seen.has(domain)) { seen.add(domain); results.push({ domain }); }
                break;
              }
            }
          }
        }

        setExcelParsed(results);
        if (results.length === 0) toast({ description: "Hiç domain algılanamadı. URL içeren bir sütun olmalı.", variant: "destructive" });
      } catch {
        toast({ description: "Dosya okunamadı.", variant: "destructive" });
      }
    };
    reader.readAsArrayBuffer(file);
    e.target.value = "";
  };

  const startQualify = useMutation({
    mutationFn: () =>
      fetch(`${BASE}/lead-discovery/qualify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ limit: 20 }),
      }).then((r) => r.json()),
    onSuccess: () => {
      toast({ description: "Kalifikasyon başlatıldı." });
      qc.invalidateQueries({ queryKey: ["lead-candidates"] });
    },
  });

  const startPrescreen = useMutation({
    mutationFn: () =>
      fetch(`${BASE}/lead-discovery/prescreen`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ limit: 500 }),
      }).then((r) => r.json()),
    onSuccess: () => {
      toast({ description: "Ön-eleme başlatıldı. 500 aday işlenecek." });
      qc.invalidateQueries({ queryKey: ["lead-stats"] });
    },
  });

  const generateTeaser = useMutation({
    mutationFn: (id: number) =>
      fetch(`${BASE}/lead-discovery/candidates/${id}/teaser`, { method: "POST" }).then((r) => r.json()),
    onSuccess: () => {
      toast({ description: "Teaser üretimi başlatıldı." });
      qc.invalidateQueries({ queryKey: ["lead-candidates"] });
    },
  });

  const sendTeaser = useMutation({
    mutationFn: (id: number) =>
      fetch(`${BASE}/lead-discovery/candidates/${id}/send-teaser`, { method: "POST" }).then(async (r) => {
        const j = await r.json() as { error?: string };
        if (!r.ok) throw new Error(j.error ?? "Hata");
        return j;
      }),
    onSuccess: () => {
      toast({ description: "Teaser gönderildi olarak işaretlendi." });
      qc.invalidateQueries({ queryKey: ["lead-candidates"] });
      qc.invalidateQueries({ queryKey: ["lead-discovery-stats"] });
    },
    onError: (e: Error) => toast({ variant: "destructive", description: e.message }),
  });

  const saveContact = useMutation({
    mutationFn: ({ id, contactEmail, contactName, contactTitle }: { id: number; contactEmail: string; contactName: string; contactTitle: string }) =>
      fetch(`${BASE}/lead-discovery/candidates/${id}/contact`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ contactEmail, contactName, contactTitle }),
      }).then(async (r) => {
        const j = await r.json() as { error?: string };
        if (!r.ok) throw new Error(j.error ?? "Hata");
        return j;
      }),
    onSuccess: () => {
      toast({ description: "Kontak bilgisi kaydedildi." });
      setContactEditTarget(null);
      qc.invalidateQueries({ queryKey: ["lead-qualified"] });
      qc.invalidateQueries({ queryKey: ["lead-discovery-stats"] });
    },
    onError: (e: Error) => toast({ variant: "destructive", description: e.message }),
  });

  const reEnrich = useMutation({
    mutationFn: (id: number) =>
      fetch(`${BASE}/lead-discovery/candidates/${id}/re-enrich`, { method: "POST" }).then((r) => r.json()),
    onSuccess: () => {
      toast({ description: "Kontak arama başlatıldı (WHOIS + Web + MERSIS)." });
      setTimeout(() => qc.invalidateQueries({ queryKey: ["lead-qualified"] }), 15000);
    },
  });

  const webEnrich = useMutation({
    mutationFn: (id: number) =>
      fetch(`${BASE}/lead-discovery/candidates/${id}/web-enrich`, { method: "POST" }).then((r) => r.json()),
    onSuccess: () => {
      toast({ description: "Web enrichment başlatıldı (liveness + scraping)." });
      setTimeout(() => qc.invalidateQueries({ queryKey: ["lead-qualified"] }), 20000);
    },
    onError: (e: Error) => toast({ variant: "destructive", description: e.message }),
  });

  const batchWebEnrich = useMutation({
    mutationFn: (limit: number) =>
      fetch(`${BASE}/lead-discovery/web-enrich`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ limit }),
      }).then(async (r) => {
        const j = await r.json() as { message?: string; error?: string };
        if (!r.ok) throw new Error(j.error ?? "Hata");
        return j;
      }),
    onSuccess: (data) => toast({ description: (data as { message?: string }).message ?? "Web enrichment başlatıldı." }),
    onError: (e: Error) => toast({ variant: "destructive", description: e.message }),
  });

  const cveReenrich = useMutation({
    mutationFn: async () => {
      const r = await fetch("/api/admin-panel/cve/re-enrich-patches", { method: "POST", credentials: "include" });
      const j = await r.json() as { error?: string };
      if (!r.ok) throw new Error((j as { error?: string }).error ?? "Hata");
      return j;
    },
    onSuccess: () => {
      toast({ description: "Yama durumu NVD'den güncelleniyor — birkaç dakika içinde tamamlanır." });
      setTimeout(() => { void cveRefetch(); }, 5000);
    },
    onError: (e: Error) => toast({ variant: "destructive", description: e.message }),
  });

  const saveIsrNotes = useMutation({
    mutationFn: ({ id, notes }: { id: number; notes: string }) =>
      fetch(`${BASE}/lead-discovery/candidates/${id}/isr-notes`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ isrNotes: notes }),
      }).then(async (r) => {
        const j = await r.json() as { error?: string };
        if (!r.ok) throw new Error(j.error ?? "Hata");
        return j;
      }),
    onSuccess: () => {
      toast({ description: "ISR notları kaydedildi." });
      qc.invalidateQueries({ queryKey: ["lead-qualified"] });
    },
    onError: (e: Error) => toast({ variant: "destructive", description: e.message }),
  });

  function buildLinkedInUrl(c: LeadCandidate): string {
    const parts = c.domain.split(".");
    const slug = parts[0] ?? "";
    const company = c.companyName ?? (slug.charAt(0).toUpperCase() + slug.slice(1).toLowerCase());
    if (c.officerName) {
      return `https://www.linkedin.com/search/results/people/?keywords=${encodeURIComponent(`${c.officerName} ${company}`)}`;
    }
    return `https://www.linkedin.com/search/results/people/?keywords=${encodeURIComponent(company)}&titleKeyword=${encodeURIComponent("IT OR CTO OR CISO OR Genel Mudur")}`;
  }

  function buildSalesNavUrl(c: LeadCandidate): string {
    const parts = c.domain.split(".");
    const slug = parts[0] ?? "";
    const company = c.companyName ?? slug;
    return `https://www.linkedin.com/sales/search/people?query=(keywords:${encodeURIComponent(company)})`;
  }

  function exportQualifiedCsv(rows: LeadCandidate[]): void {
    const header = ["domain", "company_name", "officer_name", "officer_title", "contact_email", "risk_score", "contact_source", "linkedin_url"];
    const lines = rows.map((c) => [
      c.domain,
      c.companyName ?? "",
      c.officerName ?? "",
      c.officerTitle ?? "",
      c.contactEmail ?? "",
      String(c.riskScore ?? ""),
      c.contactSource ?? "",
      buildLinkedInUrl(c),
    ].map((v) => `"${v.replace(/"/g, '""')}"`).join(","));
    const csv = [header.join(","), ...lines].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cyberstep-leads-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const deleteCandidate = useMutation({
    mutationFn: (id: number) =>
      fetch(`${BASE}/lead-discovery/candidates/${id}`, { method: "DELETE" }).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["lead-candidates"] });
      qc.invalidateQueries({ queryKey: ["lead-discovery-stats"] });
    },
  });

  const promoteToIsr = useMutation({
    mutationFn: (c: LeadCandidate) =>
      fetch(`${BASE}/lead-discovery/candidates/${c.id}/promote-to-isr`, {
        method: "POST",
        credentials: "include",
      }).then(async (r) => {
        const j = await r.json() as { error?: string; alreadyPromoted?: boolean; isrCustomerId?: number };
        if (!r.ok) throw new Error(j.error ?? "Hata");
        return j;
      }),
    onSuccess: (data, vars) => {
      if (data.alreadyPromoted) {
        toast({ description: "Bu lead zaten ISR listesinde." });
      } else {
        toast({ description: `${vars.companyName ?? vars.domain} ISR müşteri listesine eklendi.` });
      }
      qc.invalidateQueries({ queryKey: ["qualified-leads"] });
    },
    onError: (e: Error) => toast({ variant: "destructive", description: e.message }),
  });

  const fingerprintLead = useMutation({
    mutationFn: (domain: string) =>
      fetch(`${BASE}/tech-stack/fingerprint`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      }).then(async (r) => {
        const j = await r.json() as { error?: string; stack?: TechStackItem[]; stackCount?: number; maturity?: { score: number; level: string } };
        if (!r.ok) throw new Error(j.error ?? "Hata");
        return j;
      }),
    onSuccess: (data) => {
      setFingerprintResult({
        stack: data.stack ?? [],
        stackCount: data.stackCount ?? 0,
        maturity: data.maturity ?? null,
      });
    },
    onError: (e: Error) => toast({ variant: "destructive", description: e.message }),
  });

  const TLD_OPTIONS = [".com.tr", ".net.tr", ".org.tr", ".edu.tr", ".bel.tr"];
  const DAYS_OPTIONS = [7, 14, 30, 60, 90];
  const SCORE_OPTIONS = [50, 60, 70, 80];
  const LIMIT_OPTIONS = [100, 200, 300, 500];

  return (
    <AdminLayout title="Lead Discovery">
      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-6">
        {[
          { label: "Toplam Aday", value: stats?.total ?? 0, color: "" },
          { label: "Nitelendirme Bekleyen", value: stats?.pendingTier2 ?? 0, color: "text-amber-600" },
          { label: "Nitelendirilen", value: stats?.qualified ?? 0, color: "text-green-600" },
          { label: "Kontak Bulunan", value: stats?.withContact ?? 0, color: "text-blue-600" },
          { label: "Teaser Gönderildi", value: stats?.teaserSent ?? 0, color: "text-purple-600" },
        ].map((s) => (
          <Card key={s.label}>
            <CardContent className="pt-4 pb-3">
              <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
              <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Tabs defaultValue="crtsh">
        <div className="overflow-x-auto mb-4">
          <TabsList className="w-max min-w-full">
            <TabsTrigger value="certstream">Certstream</TabsTrigger>
            <TabsTrigger value="crtsh">crt.sh</TabsTrigger>
            <TabsTrigger value="shodan">Shodan</TabsTrigger>
            <TabsTrigger value="ripe_dns">RIPE DNS</TabsTrigger>
            <TabsTrigger value="pipeline">Pipeline</TabsTrigger>
            <TabsTrigger value="qualified">
              Qualified
              {(stats?.qualified ?? 0) > 0 && (
                <span className="ml-1.5 inline-flex items-center justify-center rounded-full bg-green-100 text-green-700 text-[10px] font-bold w-4 h-4">
                  {stats!.qualified}
                </span>
              )}
            </TabsTrigger>
            <TabsTrigger value="isp-gruplari">ISP Grupları</TabsTrigger>
            <TabsTrigger value="results">Sonuclar</TabsTrigger>
            <TabsTrigger value="history">Gecmis</TabsTrigger>
            <TabsTrigger value="puanlama-rehberi">Puanlama Rehberi</TabsTrigger>
            <TabsTrigger value="cve-raporu">CVE Raporu</TabsTrigger>
            <TabsTrigger value="port-riski">Port Riski</TabsTrigger>
            <TabsTrigger value="zenginlestirme">Zenginleştirme</TabsTrigger>
            <TabsTrigger value="bist-analizi">BIST Analizi</TabsTrigger>
          </TabsList>
        </div>

        {/* ── CERTSTREAM TAB ───────────────────────────────────────────── */}
        <TabsContent value="certstream">
          <CertstreamWidget />
        </TabsContent>

        {/* ── crt.sh TAB ────────────────────────────────────────────────── */}
        <TabsContent value="crtsh">
          <Card>
            <CardHeader>
              <CardTitle>crt.sh SSL Sertifika Tarayici</CardTitle>
              <CardDescription>
                Ucretsiz, API key gerektirmez. Turkiye'deki kurumsal SSL sertifikalarini tarar.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              <div>
                <Label className="mb-2 block">TLD Secimi</Label>
                <div className="flex flex-wrap gap-3">
                  {TLD_OPTIONS.map((tld) => (
                    <label key={tld} className="flex items-center gap-2 cursor-pointer">
                      <Checkbox
                        checked={crtshTlds.includes(tld)}
                        onCheckedChange={(v) => {
                          if (v) setCrtshTlds((p) => [...p, tld]);
                          else setCrtshTlds((p) => p.filter((x) => x !== tld));
                        }}
                      />
                      <span className="text-sm font-mono">{tld}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <Label className="mb-1 block">Son Kac Gun</Label>
                  <Select value={String(daysBack)} onValueChange={(v) => setDaysBack(parseInt(v))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {DAYS_OPTIONS.map((d) => <SelectItem key={d} value={String(d)}>{d} gun</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label className="mb-1 block">Min Kurumsal Skor: {minScore}</Label>
                  <Select value={String(minScore)} onValueChange={(v) => setMinScore(parseInt(v))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {SCORE_OPTIONS.map((s) => <SelectItem key={s} value={String(s)}>{s}+ (login/portal={'>'}=80, ERP=95)</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label className="mb-1 block">Maks Domain</Label>
                  <Select value={String(domainLimit)} onValueChange={(v) => setDomainLimit(parseInt(v))}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {LIMIT_OPTIONS.map((l) => <SelectItem key={l} value={String(l)}>{l}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="bg-muted/40 rounded-md p-3 text-sm text-muted-foreground">
                <div className="font-medium mb-1 text-foreground">Subdomain skor rehberi</div>
                <div className="grid grid-cols-3 gap-1">
                  {[
                    ["erp, sap", "95"], ["crm, sso", "90"], ["portal, intranet", "85"],
                    ["login, vpn", "80"], ["pos, payment", "80-85"], ["api, exchange", "65-70"],
                    ["mail, backup", "60-65"], ["www", "10"],
                  ].map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-1">
                      <span className="font-mono text-xs">{k}</span>
                      <span className="text-xs">{v}</span>
                    </div>
                  ))}
                </div>
              </div>

              <Button
                onClick={() => startCrtsh.mutate()}
                disabled={startCrtsh.isPending || crtshTlds.length === 0}
              >
                {startCrtsh.isPending ? "Baslatiliyor..." : "crt.sh Taramasini Basalt"}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── SHODAN TAB ────────────────────────────────────────────────── */}
        <TabsContent value="shodan">
          <Card>
            <CardHeader>
              <CardTitle>Shodan Ucretsiz Tarayici</CardTitle>
              <CardDescription>
                Ucretsiz API key: account.shodan.io → Kayit → API Key (2 dakika).
                Limit: 100 sonuc/sorgu.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label className="mb-2 block">Hazir Sorgular</Label>
                <div className="space-y-2">
                  {(shodanQueries ?? []).map((q) => (
                    <label key={q.index} className="flex items-start gap-3 cursor-pointer p-2 rounded hover:bg-muted/40">
                      <Checkbox
                        checked={selectedShodanQueries.includes(q.index)}
                        onCheckedChange={(v) => {
                          if (v) setSelectedShodanQueries((p) => [...p, q.index]);
                          else setSelectedShodanQueries((p) => p.filter((x) => x !== q.index));
                        }}
                      />
                      <div>
                        <div className="text-sm font-medium">{q.label}</div>
                        <div className="text-xs text-muted-foreground font-mono mt-0.5">{q.q}</div>
                      </div>
                      <Badge variant="outline" className="ml-auto shrink-0">Oncelik {q.priority}</Badge>
                    </label>
                  ))}
                </div>
              </div>

              <Button
                onClick={() => startShodan.mutate()}
                disabled={startShodan.isPending || selectedShodanQueries.length === 0}
              >
                {startShodan.isPending ? "Baslatiliyor..." : `Shodan Taramasini Basalt (${selectedShodanQueries.length} sorgu)`}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── RIPE DNS TAB ─────────────────────────────────────────────── */}
        <TabsContent value="ripe_dns">
          <RipeDnsWidget />
        </TabsContent>

        {/* ── PIPELINE TAB ─────────────────────────────────────────────── */}
        <TabsContent value="pipeline">
          <div className="space-y-4">
            {/* Akış göstergesi */}
            <div className="flex items-center gap-1 text-xs text-muted-foreground overflow-x-auto pb-1">
              {["Ham Veri (crt.sh/Shodan/CT Bridge)", "Ön-eleme", "Nitelendirme (OSINT)", "Qualified Lead"].map((s, i, arr) => (
                <div key={s} className="flex items-center gap-1 shrink-0">
                  <span className="bg-muted rounded px-2 py-0.5 font-medium">{s}</span>
                  {i < arr.length - 1 && <span className="text-muted-foreground/50">→</span>}
                </div>
              ))}
            </div>

            {/* Tier kartları */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

              {/* TIER 3 — Ön-eleme */}
              <Card className="border-orange-200 dark:border-orange-900">
                <CardHeader className="pb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-400 rounded px-2 py-0.5">Aşama 1</span>
                    <CardTitle className="text-base">Ön-eleme</CardTitle>
                  </div>
                  <CardDescription className="text-xs">
                    crt.sh, Shodan ve CT Bridge'den gelen ham domain'lerin canlı olup olmadığı HTTP isteğiyle test edilir. Cevap vermeyen, 4xx/5xx dönen veya bağlantı reddeden domainler kuyruktan çıkarılır. Geçenler Aşama 2'ye alınır.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <div className="bg-muted/40 rounded px-3 py-2 flex justify-between">
                      <span className="text-muted-foreground">Kuyrukta</span>
                      <span className="font-bold text-orange-600">{(stats?.pendingTier3 ?? 0).toLocaleString("tr-TR")}</span>
                    </div>
                    <div className="bg-muted/40 rounded px-3 py-2 flex justify-between">
                      <span className="text-muted-foreground">İşlemde</span>
                      <span className="font-bold">{(stats?.prescreening ?? 0).toLocaleString("tr-TR")}</span>
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground bg-muted/30 rounded px-3 py-2 space-y-0.5">
                    <div>Otomatik: her 5 dakikada 500 aday</div>
                    <div>Eleme kriterleri: timeout, 404, 410, 5xx, bağlantı hatası</div>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full"
                    onClick={() => startPrescreen.mutate()}
                    disabled={startPrescreen.isPending}
                  >
                    {startPrescreen.isPending ? "Çalışıyor..." : "Ön-elemeyi Çalıştır (500 aday)"}
                  </Button>
                </CardContent>
              </Card>

              {/* TIER 2 — Kalifikasyon */}
              <Card className="border-blue-200 dark:border-blue-900">
                <CardHeader className="pb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-400 rounded px-2 py-0.5">Aşama 2</span>
                    <CardTitle className="text-base">Kalifikasyon</CardTitle>
                  </div>
                  <CardDescription className="text-xs">
                    Tam OSINT zinciri: DNS kayıtları, SSL sertifikası analizi, Shodan port/servis tespiti, VirusTotal itibar, HIBP veri ihlali, shadow IT tespiti ve CVE eşleştirmesi. Risk skoru hesaplanır — skor &lt; 60 olan adaylar nitelendirilerek lead olarak işaretlenir.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <div className="bg-muted/40 rounded px-3 py-2 flex justify-between">
                      <span className="text-muted-foreground">Kuyrukta</span>
                      <span className="font-bold text-blue-600">{(stats?.pendingTier2 ?? 0).toLocaleString("tr-TR")}</span>
                    </div>
                    <div className="bg-muted/40 rounded px-3 py-2 flex justify-between">
                      <span className="text-muted-foreground">Tarandı</span>
                      <span className="font-bold">{(stats?.scanned ?? 0).toLocaleString("tr-TR")}</span>
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground bg-muted/30 rounded px-3 py-2 space-y-0.5">
                    <div>Otomatik: her 20 dakikada 20 aday</div>
                    <div>Kota: Shodan 100/gün, VirusTotal 500/gün</div>
                    <div>Nitelendirme eşiği: risk skoru &lt; 60</div>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full"
                    onClick={() => startQualify.mutate()}
                    disabled={startQualify.isPending}
                  >
                    {startQualify.isPending ? "Çalışıyor..." : "Kalifikasyonu Çalıştır (20 aday)"}
                  </Button>
                </CardContent>
              </Card>

              {/* TIER 1 — Qualified */}
              <Card className="border-green-200 dark:border-green-900">
                <CardHeader className="pb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-400 rounded px-2 py-0.5">Aşama 3</span>
                    <CardTitle className="text-base">Qualified Lead</CardTitle>
                  </div>
                  <CardDescription className="text-xs">
                    Kalifikasyonu geçmiş adaylar. Altı farklı kaynaktan iletişim bilgisi toplanır; bulunan adaylar için Claude AI ile kişiselleştirilmiş teaser e-postası üretilir.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <div className="bg-muted/40 rounded px-3 py-2 flex justify-between">
                      <span className="text-muted-foreground">Toplam</span>
                      <span className="font-bold text-green-600">{(stats?.qualified ?? 0).toLocaleString("tr-TR")}</span>
                    </div>
                    <div className="bg-muted/40 rounded px-3 py-2 flex justify-between">
                      <span className="text-muted-foreground">Contact Bulundu</span>
                      <span className="font-bold">{(stats?.withContact ?? 0).toLocaleString("tr-TR")}</span>
                    </div>
                    <div className="bg-muted/40 rounded px-3 py-2 flex justify-between col-span-2">
                      <span className="text-muted-foreground">Teaser Gönderildi</span>
                      <span className="font-bold">{(stats?.teaserSent ?? 0).toLocaleString("tr-TR")}</span>
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground bg-muted/30 rounded px-3 py-2 space-y-1">
                    <div className="font-medium text-foreground/70 mb-1">Kontak kaynakları (öncelik sırasıyla)</div>
                    <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-blue-400 shrink-0" />Apollo API — e-posta + ad/unvan</div>
                    <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-blue-300 shrink-0" />Hunter.io — e-posta yedek</div>
                    <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-amber-400 shrink-0" />WHOIS kayıtları — domain sahibi e-posta</div>
                    <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-amber-300 shrink-0" />Web sitesi footer / iletişim sayfası</div>
                    <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0" />MERSİS — Ticaret Bakanlığı yetkili adı/unvanı</div>
                    <div className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-emerald-300 shrink-0" />KAP — borsaya kote şirket yönetici bilgisi</div>
                    <div className="mt-1 pt-1 border-t border-muted">Teaser: Claude claude-sonnet-4-6 ile üretilir</div>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full"
                    onClick={() => startFull.mutate()}
                    disabled={startFull.isPending}
                  >
                    {startFull.isPending ? "Çalışıyor..." : "Tam Pipeline Başlat"}
                  </Button>
                </CardContent>
              </Card>
            </div>

            {/* Tam pipeline butonu */}
            <Card>
              <CardContent className="pt-4 pb-4">
                <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                  <div className="flex-1">
                    <div className="text-sm font-medium">Tam Pipeline (crt.sh + Shodan → Kalifikasyon)</div>
                    <div className="text-xs text-muted-foreground mt-0.5">Yeni domain taraması yapar, ardından sıradaki 20 adayı qualify eder. Tahmini süre: 2-3 saat.</div>
                  </div>
                  <Button
                    onClick={() => startFull.mutate()}
                    disabled={startFull.isPending}
                    size="sm"
                  >
                    {startFull.isPending ? "Başlatılıyor..." : "Tam Pipeline Başlat"}
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Lead Import Merkezi */}
            <Card className="border-violet-200 dark:border-violet-900">
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold bg-violet-100 dark:bg-violet-900/40 text-violet-700 dark:text-violet-400 rounded px-2 py-0.5">Manuel</span>
                  <CardTitle className="text-base">Lead Import Merkezi</CardTitle>
                </div>
                <CardDescription className="text-xs">
                  Excel/CSV yükle, domain listesi yapıştır veya tek tek ekle. Mevcut domainler atlanır (idempotent). .bel.tr ve .gov.tr is_municipality=true olarak işaretlenir.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Tabs value={importTab} onValueChange={(v) => { setImportTab(v); batchImport.reset(); singleAdd.reset(); }}>
                  <TabsList className="grid grid-cols-3 h-8 mb-4">
                    <TabsTrigger value="excel" className="text-xs">Excel / CSV</TabsTrigger>
                    <TabsTrigger value="manual" className="text-xs">Manuel Giriş</TabsTrigger>
                    <TabsTrigger value="pdf" className="text-xs">PDF Listesi</TabsTrigger>
                  </TabsList>

                  {/* ── Excel / CSV ────────────────────────────────────────── */}
                  <TabsContent value="excel" className="mt-0">
                    <div className="space-y-3">
                      <div
                        className="border-2 border-dashed border-slate-700 hover:border-violet-500 rounded-lg p-5 text-center cursor-pointer transition-colors"
                        onClick={() => fileInputRef.current?.click()}
                      >
                        <input
                          ref={fileInputRef}
                          type="file"
                          accept=".xlsx,.xls,.csv"
                          className="hidden"
                          onChange={handleExcelUpload}
                        />
                        <div className="text-sm font-medium text-slate-300">
                          {excelFileName ? excelFileName : "Excel (.xlsx / .xls) veya CSV dosyası seç"}
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          {excelParsed.length > 0
                            ? `${excelParsed.length} domain algılandı`
                            : "URL içeren sütun otomatik algılanır — tıkla veya sürükle"}
                        </div>
                      </div>

                      {excelParsed.length > 0 && (
                        <div className="space-y-2">
                          <div className="text-xs text-muted-foreground font-mono bg-slate-900 rounded px-3 py-2 max-h-24 overflow-y-auto">
                            {excelParsed.slice(0, 8).map(d => d.companyName ? `${d.companyName} (${d.domain})` : d.domain).join(" · ")}
                            {excelParsed.length > 8 && <span className="text-slate-500"> · +{excelParsed.length - 8} daha</span>}
                          </div>
                          <div className="flex gap-2">
                            <Button
                              size="sm"
                              className="flex-1"
                              onClick={() => batchImport.mutate({ rows: excelParsed, source: "excel_import" })}
                              disabled={batchImport.isPending}
                            >
                              {batchImport.isPending ? "Import ediliyor..." : `${excelParsed.length} Kaydı Import Et`}
                            </Button>
                            <Button size="sm" variant="ghost" className="text-slate-400" onClick={() => { setExcelParsed([]); setExcelFileName(""); batchImport.reset(); }}>
                              Temizle
                            </Button>
                          </div>
                        </div>
                      )}

                      {batchImport.isSuccess && batchImport.data && (
                        <div className="text-xs bg-green-950/40 border border-green-800 rounded px-3 py-2 text-green-400 space-y-0.5">
                          {batchImport.data.inserted > 0 && <div><strong>{batchImport.data.inserted}</strong> yeni domain eklendi</div>}
                          {batchImport.data.enriched > 0 && <div><strong>{batchImport.data.enriched}</strong> mevcut kayıt zenginleştirildi</div>}
                          {batchImport.data.unchanged > 0 && <div className="text-green-600">{batchImport.data.unchanged} kayıt değişmedi (tüm alanlar zaten doluydu)</div>}
                        </div>
                      )}
                    </div>
                  </TabsContent>

                  {/* ── Manuel Giriş ───────────────────────────────────────── */}
                  <TabsContent value="manual" className="mt-0">
                    <div className="space-y-4">

                      {/* Domain Arama */}
                      <div>
                        <div className="text-xs font-medium mb-1.5 text-muted-foreground uppercase tracking-wide">Domain Ara</div>
                        <form
                          className="flex gap-2"
                          onSubmit={async (e) => {
                            e.preventDefault();
                            const q = manualLookupInput.trim();
                            if (!q) return;
                            setManualLookupLoading(true);
                            setManualLookupResult(null);
                            try {
                              const params = new URLSearchParams({ search: q, pageSize: "5" });
                              const r = await fetch(`${BASE}/lead-discovery/candidates?${params}`, { credentials: "include" });
                              const data = await r.json() as { rows: LeadCandidate[]; total: number };
                              setManualLookupResult(data);
                            } finally {
                              setManualLookupLoading(false);
                            }
                          }}
                        >
                          <div className="relative flex-1">
                            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
                            <Input
                              placeholder="örn: sirket.com.tr"
                              value={manualLookupInput}
                              onChange={(e) => { setManualLookupInput(e.target.value); if (!e.target.value.trim()) setManualLookupResult(null); }}
                              className="h-8 pl-7 text-sm"
                            />
                          </div>
                          <Button type="submit" size="sm" className="h-8 shrink-0" disabled={manualLookupLoading || !manualLookupInput.trim()}>
                            {manualLookupLoading ? "..." : "Ara"}
                          </Button>
                        </form>
                        {manualLookupResult !== null && (
                          <div className="mt-2 rounded border border-slate-700 divide-y divide-slate-800 text-xs overflow-hidden">
                            {manualLookupResult.rows.length === 0 ? (
                              <div className="px-3 py-2 text-muted-foreground">Sonuç bulunamadı.</div>
                            ) : (
                              <>
                                {manualLookupResult.rows.map((c) => (
                                  <div key={c.id} className="flex items-center gap-3 px-3 py-1.5 bg-slate-900/60">
                                    <span className="font-mono text-slate-200 flex-1 truncate">{c.domain}</span>
                                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${c.tier === "tier1" ? "bg-green-900/40 text-green-400 border-green-700" : c.tier === "tier2" ? "bg-blue-900/40 text-blue-400 border-blue-700" : "bg-orange-900/40 text-orange-400 border-orange-700"}`}>
                                      {c.tier === "tier1" ? "T1" : c.tier === "tier2" ? "T2" : c.tier === "tier3" ? "T3" : "—"}
                                    </span>
                                    {c.riskScore !== null && (
                                      <span className="text-slate-400">Risk: <strong className="text-slate-200">{c.riskScore}</strong></span>
                                    )}
                                    <span className="text-slate-500 shrink-0">{c.scanStatus}</span>
                                  </div>
                                ))}
                                {manualLookupResult.total > 5 && (
                                  <div className="px-3 py-1.5 text-slate-500 bg-slate-900/40">+{manualLookupResult.total - 5} daha — Sonuçlar tabında aratın.</div>
                                )}
                              </>
                            )}
                          </div>
                        )}
                      </div>

                      {/* Tek domain hızlı ekle */}
                      <div>
                        <div className="text-xs font-medium mb-1.5 text-muted-foreground uppercase tracking-wide">Tek Domain Ekle</div>
                        <div className="flex gap-2">
                          <Input
                            placeholder="örn: sirket.com veya https://www.sirket.com.tr"
                            value={singleDomain}
                            onChange={(e) => { setSingleDomain(e.target.value); singleAdd.reset(); }}
                            onKeyDown={(e) => { if (e.key === "Enter" && singleDomain.trim()) singleAdd.mutate(singleDomain.trim()); }}
                            className="flex-1 h-8 text-sm"
                          />
                          <Button
                            size="sm"
                            className="h-8 shrink-0"
                            onClick={() => singleAdd.mutate(singleDomain.trim())}
                            disabled={singleAdd.isPending || !singleDomain.trim()}
                          >
                            Ekle
                          </Button>
                        </div>
                        {singleAdd.isSuccess && singleAdd.data?.results[0] && (
                          <div className={`mt-1.5 text-xs rounded px-2 py-1 ${singleAdd.data.results[0].status === "inserted" ? "text-green-400 bg-green-950/40 border border-green-800" : "text-slate-400 bg-slate-800 border border-slate-700"}`}>
                            {singleAdd.data.results[0].status === "inserted"
                              ? `Eklendi: ${singleAdd.data.results[0].domain}`
                              : `Zaten mevcut: ${singleAdd.data.results[0].domain}`}
                          </div>
                        )}
                      </div>

                      {/* Toplu yapıştır */}
                      <div>
                        <div className="text-xs font-medium mb-1.5 text-muted-foreground uppercase tracking-wide">Toplu Yapıştır</div>
                        <textarea
                          rows={7}
                          value={manualInput}
                          onChange={(e) => { setManualInput(e.target.value); batchImport.reset(); }}
                          placeholder={"Her satıra bir domain:\nsirket1.com\nsirket2.com.tr\nhttps://www.sirket3.net\n..."}
                          className="w-full bg-slate-900 border border-slate-700 rounded-md px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-violet-500 font-mono text-xs resize-none"
                        />
                        {manualInput.trim() && (
                          <div className="flex items-center justify-between mt-2">
                            <span className="text-xs text-muted-foreground">
                              {manualInput.trim().split("\n").filter(l => l.trim()).length} domain
                            </span>
                            <div className="flex gap-2">
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-7 text-slate-400"
                                onClick={() => { setManualInput(""); batchImport.reset(); }}
                              >
                                Temizle
                              </Button>
                              <Button
                                size="sm"
                                className="h-7"
                                onClick={() =>
                                  batchImport.mutate({
                                    rows: manualInput.trim().split("\n").filter(l => l.trim()).map(d => ({ domain: d.trim() })),
                                    source: "manual_import",
                                  })
                                }
                                disabled={batchImport.isPending}
                              >
                                {batchImport.isPending ? "İşleniyor..." : "Hepsini Ekle"}
                              </Button>
                            </div>
                          </div>
                        )}
                        {batchImport.isSuccess && batchImport.data && (
                          <div className="mt-2 text-xs bg-green-950/40 border border-green-800 rounded px-3 py-2 text-green-400">
                            Tamamlandı: <strong>{batchImport.data.inserted}</strong> eklendi, {batchImport.data.skipped} zaten mevcuttu.
                          </div>
                        )}
                      </div>
                    </div>
                  </TabsContent>

                  {/* ── PDF Listesi ────────────────────────────────────────── */}
                  <TabsContent value="pdf" className="mt-0">
                    <div className="space-y-3">
                      <div className="text-xs text-muted-foreground space-y-0.5">
                        <div>Kaynak: <span className="font-medium text-foreground/70">pdf-leads-2026-06.json</span> ({pdfLeads.length} domain)</div>
                        <div>Tier: tier2 · Durum: pending · Kaynak kodu: pdf_import</div>
                        <div>Belediyeler (.bel.tr): is_municipality=true olarak işaretlenir</div>
                      </div>
                      <Button
                        onClick={() => pdfImport.mutate()}
                        disabled={pdfImport.isPending}
                        size="sm"
                        variant="outline"
                        className="border-violet-400 text-violet-700 dark:text-violet-400 hover:bg-violet-50 dark:hover:bg-violet-900/20"
                      >
                        {pdfImport.isPending ? "Import ediliyor..." : "PDF Listesini Import Et"}
                      </Button>
                      {pdfImport.isSuccess && (
                        <div className="text-xs bg-green-950/40 border border-green-800 rounded px-3 py-2 text-green-400">
                          Tamamlandı: <strong>{pdfImport.data.inserted}</strong> eklendi, {pdfImport.data.skipped} zaten mevcuttu.
                        </div>
                      )}
                    </div>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ── QUALIFIED TAB ────────────────────────────────────────────── */}
        <TabsContent value="qualified">
          <div className="space-y-3">
            {/* Stats bar */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {[
                { label: "Toplam Qualified", value: stats?.qualified ?? 0, color: "text-green-600" },
                { label: "Contact Bulundu", value: stats?.withContact ?? 0, color: "text-blue-600" },
                { label: "Teaser Gönderildi", value: stats?.teaserSent ?? 0, color: "text-purple-600" },
                { label: "Bu Sayfada", value: qualifiedData?.rows?.length ?? 0, color: "text-slate-400" },
              ].map((s) => (
                <div key={s.label} className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2">
                  <div className="text-[11px] text-slate-500">{s.label}</div>
                  <div className={`text-xl font-bold ${s.color}`}>{s.value.toLocaleString("tr-TR")}</div>
                </div>
              ))}
            </div>

            {/* Filter + search bar */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-3">
              {/* Search row */}
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="Domain ara (örn: finans, .net, holding…)"
                  value={qSearchInput}
                  onChange={(e) => setQSearchInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") { setQSearch(qSearchInput); setQPage(1); }
                  }}
                  className="flex-1 bg-slate-800 border border-slate-700 rounded-md px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-primary"
                />
                <Button size="sm" onClick={() => { setQSearch(qSearchInput); setQPage(1); }} className="shrink-0">
                  Ara
                </Button>
                {qSearch && (
                  <Button size="sm" variant="ghost" className="text-slate-400 shrink-0" onClick={() => { setQSearch(""); setQSearchInput(""); setQPage(1); }}>
                    Temizle
                  </Button>
                )}
              </div>

              {/* Filter chips row */}
              <div className="flex flex-wrap gap-2 items-center">
                {/* Tier */}
                <select
                  value={qTier}
                  onChange={(e) => { setQTier(e.target.value); setQPage(1); }}
                  className="bg-slate-800 border border-slate-700 rounded-md px-2 py-1 text-xs text-slate-300 focus:outline-none"
                >
                  <option value="">Tüm Tier'lar</option>
                  <option value="tier1">Tier 1 (En İyi)</option>
                  <option value="tier2">Tier 2</option>
                  <option value="tier3">Tier 3</option>
                </select>

                {/* Contact durumu */}
                <select
                  value={qContact}
                  onChange={(e) => { setQContact(e.target.value); setQPage(1); }}
                  className="bg-slate-800 border border-slate-700 rounded-md px-2 py-1 text-xs text-slate-300 focus:outline-none"
                >
                  <option value="">Tüm Contact</option>
                  <option value="has">Contact Var</option>
                  <option value="no">Contact Eksik</option>
                </select>

                {/* Teaser durumu */}
                <select
                  value={qTeaser}
                  onChange={(e) => { setQTeaser(e.target.value); setQPage(1); }}
                  className="bg-slate-800 border border-slate-700 rounded-md px-2 py-1 text-xs text-slate-300 focus:outline-none"
                >
                  <option value="">Tüm Teaser</option>
                  <option value="has">Teaser Hazır</option>
                  <option value="sent">Gönderildi</option>
                  <option value="notsent">Gönderilmedi</option>
                </select>

                {/* Min risk skoru */}
                <select
                  value={qMinScore}
                  onChange={(e) => { setQMinScore(parseInt(e.target.value)); setQPage(1); }}
                  className="bg-slate-800 border border-slate-700 rounded-md px-2 py-1 text-xs text-slate-300 focus:outline-none"
                >
                  <option value={0}>Min Risk: Hepsi</option>
                  <option value={30}>Min Risk: 30+</option>
                  <option value={50}>Min Risk: 50+</option>
                  <option value={70}>Min Risk: 70+</option>
                  <option value={85}>Min Risk: 85+</option>
                </select>

                {/* Sıralama */}
                <select
                  value={qSort}
                  onChange={(e) => { setQSort(e.target.value); setQPage(1); }}
                  className="bg-slate-800 border border-slate-700 rounded-md px-2 py-1 text-xs text-slate-300 focus:outline-none"
                >
                  <option value="risk_desc">Risk: Yüksek → Düşük</option>
                  <option value="risk_asc">Risk: Düşük → Yüksek</option>
                  <option value="added_desc">En Yeni Eklenen</option>
                  <option value="added_asc">En Eski Eklenen</option>
                  <option value="domain_asc">Domain A → Z</option>
                </select>

                {/* Sayfa boyutu */}
                <select
                  value={qPageSize}
                  onChange={(e) => { setQPageSize(parseInt(e.target.value)); setQPage(1); }}
                  className="bg-slate-800 border border-slate-700 rounded-md px-2 py-1 text-xs text-slate-300 focus:outline-none"
                >
                  <option value={20}>20 / sayfa</option>
                  <option value={50}>50 / sayfa</option>
                  <option value={100}>100 / sayfa</option>
                </select>

                {/* Kritik Port filtresi */}
                <button
                  onClick={() => { setQCriticalPort((v) => !v); setQPage(1); }}
                  className={`px-2 py-1 rounded-md text-xs border transition-colors ${qCriticalPort ? "bg-red-900/60 border-red-600 text-red-300" : "bg-slate-800 border-slate-700 text-slate-400 hover:border-red-600/50 hover:text-red-400"}`}
                >
                  Kritik Port Açık
                </button>

                {/* Belediye filtresi */}
                <button
                  onClick={() => {
                    setQMunicipality((v) => v === "" ? "only" : v === "only" ? "exclude" : "");
                    setQPage(1);
                  }}
                  className={`px-2 py-1 rounded-md text-xs border transition-colors ${
                    qMunicipality === "only"
                      ? "bg-blue-900/60 border-blue-500 text-blue-300"
                      : qMunicipality === "exclude"
                      ? "bg-slate-700/60 border-slate-500 text-slate-300 line-through"
                      : "bg-slate-800 border-slate-700 text-slate-400 hover:border-blue-500/50 hover:text-blue-400"
                  }`}
                  title={qMunicipality === "" ? "Tüm domainler (belediyeler dahil)" : qMunicipality === "only" ? "Sadece belediyeler (.bel.tr)" : "Belediyeler hariç"}
                >
                  {qMunicipality === "only" ? "Sadece Belediyeler" : qMunicipality === "exclude" ? "Belediyeler Hariç" : "Belediyeler"}
                </button>

                {/* Sektör filtresi */}
                <select
                  value={qSector}
                  onChange={(e) => { setQSector(e.target.value); setQPage(1); }}
                  className="bg-slate-800 border border-slate-700 rounded-md px-2 py-1 text-xs text-slate-300 focus:outline-none"
                >
                  <option value="">Sektör: Tümü</option>
                  <option value="__empty__">Sektör: Boş</option>
                  <option value="Finans">Finans</option>
                  <option value="Saglik">Saglik</option>
                  <option value="Perakende">Perakende</option>
                  <option value="Imalat">Imalat</option>
                  <option value="Bilisim">Bilisim</option>
                  <option value="Lojistik">Lojistik</option>
                  <option value="Insaat">Insaat</option>
                  <option value="Egitim">Egitim</option>
                  <option value="Turizm">Turizm</option>
                  <option value="Enerji">Enerji</option>
                </select>

                {/* Şehir filtresi */}
                <select
                  value={qCity}
                  onChange={(e) => { setQCity(e.target.value); setQPage(1); }}
                  className="bg-slate-800 border border-slate-700 rounded-md px-2 py-1 text-xs text-slate-300 focus:outline-none"
                >
                  <option value="">Sehir: Tümü</option>
                  <option value="__empty__">Sehir: Boş</option>
                  <option value="Istanbul">Istanbul</option>
                  <option value="Ankara">Ankara</option>
                  <option value="Izmir">Izmir</option>
                  <option value="Bursa">Bursa</option>
                  <option value="Antalya">Antalya</option>
                  <option value="Adana">Adana</option>
                  <option value="Gaziantep">Gaziantep</option>
                  <option value="Konya">Konya</option>
                  <option value="Kocaeli">Kocaeli</option>
                  <option value="Mersin">Mersin</option>
                </select>

                {/* BIST filtresi */}
                <select
                  value={qBistOnly ? (qBistIndex || "bist_all") : ""}
                  onChange={(e) => {
                    const v = e.target.value;
                    if (v === "") { setQBistOnly(false); setQBistIndex(""); }
                    else if (v === "bist_all") { setQBistOnly(true); setQBistIndex(""); }
                    else { setQBistOnly(true); setQBistIndex(v); }
                    setQPage(1);
                  }}
                  className="bg-slate-800 border border-slate-700 rounded-md px-2 py-1 text-xs text-slate-300 focus:outline-none"
                >
                  <option value="">BIST: Tümü</option>
                  <option value="bist_all">Halka Açık (BIST)</option>
                  <option value="bist30">BIST 30</option>
                  <option value="bist100">BIST 100</option>
                  <option value="bist500">BIST 500</option>
                </select>

                <div className="ml-auto flex flex-wrap gap-1.5">
                  <Button
                    size="sm"
                    variant="outline"
                    className="text-xs border-emerald-700/60 text-emerald-400 hover:bg-emerald-900/30 hover:text-emerald-300 disabled:opacity-50"
                    onClick={handleQualifiedExcelExport}
                    disabled={isExportingQualified}
                  >
                    <Download className="h-3.5 w-3.5 mr-1" />
                    {isExportingQualified ? "Hazırlanıyor..." : "Excel İndir"}
                  </Button>
                  <Button size="sm" variant="outline" className="text-xs border-slate-700 text-slate-400" onClick={() => batchWebEnrich.mutate(30)} disabled={batchWebEnrich.isPending}>
                    {batchWebEnrich.isPending ? "..." : "Toplu Web (30)"}
                  </Button>
                  <Button size="sm" variant="outline" className="text-xs border-slate-700 text-slate-400" onClick={() => startQualify.mutate()} disabled={startQualify.isPending}>
                    {startQualify.isPending ? "..." : "Kalifikasyon Çalıştır"}
                  </Button>
                </div>
              </div>

              {/* Active filter tags */}
              {(qSearch || qTier || qContact || qTeaser || qMinScore > 0 || qSector || qCity || qBistOnly) && (
                <div className="flex flex-wrap gap-1.5 pt-1 border-t border-slate-800">
                  <span className="text-[11px] text-slate-500 self-center">Aktif:</span>
                  {qSearch && <span className="text-[11px] bg-primary/20 text-primary px-2 py-0.5 rounded-full">"{qSearch}"</span>}
                  {qTier && <span className="text-[11px] bg-slate-700 text-slate-300 px-2 py-0.5 rounded-full">{qTier}</span>}
                  {qContact && <span className="text-[11px] bg-slate-700 text-slate-300 px-2 py-0.5 rounded-full">Contact: {qContact === "has" ? "Var" : "Eksik"}</span>}
                  {qTeaser && <span className="text-[11px] bg-slate-700 text-slate-300 px-2 py-0.5 rounded-full">Teaser: {qTeaser === "has" ? "Hazır" : qTeaser === "sent" ? "Gönderildi" : "Gönderilmedi"}</span>}
                  {qMinScore > 0 && <span className="text-[11px] bg-slate-700 text-slate-300 px-2 py-0.5 rounded-full">Risk ≥ {qMinScore}</span>}
                  {qSector && <span className="text-[11px] bg-purple-900/40 text-purple-300 px-2 py-0.5 rounded-full">Sektör: {qSector === "__empty__" ? "Boş" : qSector}</span>}
                  {qCity && <span className="text-[11px] bg-teal-900/40 text-teal-300 px-2 py-0.5 rounded-full">Şehir: {qCity === "__empty__" ? "Boş" : qCity}</span>}
                  {qBistOnly && <span className="text-[11px] bg-amber-900/40 text-amber-300 px-2 py-0.5 rounded-full">BIST{qBistIndex ? `: ${qBistIndex.toUpperCase()}` : ": Halka Açık"}</span>}
                  <button
                    className="text-[11px] text-red-400 hover:text-red-300 underline ml-1"
                    onClick={() => { setQSearch(""); setQSearchInput(""); setQTier(""); setQContact(""); setQTeaser(""); setQMinScore(0); setQSector(""); setQCity(""); setQBistOnly(false); setQBistIndex(""); setQPage(1); }}
                  >
                    Hepsini Temizle
                  </button>
                </div>
              )}
            </div>

            {/* Table */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              {qualifiedLoading ? (
                <div className="text-center py-12 text-slate-500 text-sm">Yükleniyor...</div>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow className="border-slate-800 hover:bg-transparent">
                        <TableHead className="text-slate-400 w-[220px]">Domain</TableHead>
                        <TableHead className="text-slate-400 w-12">Tier</TableHead>
                        <TableHead className="text-slate-400 text-right w-16">Risk</TableHead>
                        <TableHead className="text-slate-400 text-right w-14">BL</TableHead>
                        <TableHead className="text-slate-400 text-right w-14">SSL</TableHead>
                        <TableHead className="text-slate-400 text-right w-14">Mail</TableHead>
                        <TableHead className="text-slate-400 w-[130px]">Sektör / Şehir</TableHead>
                        <TableHead className="text-slate-400">Contact</TableHead>
                        <TableHead className="text-slate-400 w-28">Teaser</TableHead>
                        <TableHead className="text-slate-400 text-right w-[110px]">İşlemler</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {(qualifiedData?.rows ?? []).map((c) => (
                        <TableRow key={c.id} className="border-slate-800 hover:bg-slate-800/40">
                          {/* Domain */}
                          <TableCell className="py-2">
                            <div className="font-mono text-sm text-slate-200">{c.domain}</div>
                            {(c.scrapedCompanyName ?? c.companyName) && (
                              <div className="text-[11px] text-slate-500 truncate max-w-[200px]">{c.scrapedCompanyName ?? c.companyName}</div>
                            )}
                            <div className="flex items-center gap-1.5 mt-0.5 flex-wrap">
                              {c.source && <span className="text-[10px] text-slate-600">{c.source}</span>}
                              {c.webScrapedAt != null && (
                                c.isAlive
                                  ? <span className="text-[10px] px-1 py-0 rounded bg-green-900/40 text-green-400 border border-green-800/50">Canlı {c.responseTimeMs != null ? `${c.responseTimeMs}ms` : ""}</span>
                                  : <span className="text-[10px] px-1 py-0 rounded bg-red-900/40 text-red-400 border border-red-800/50">Erişilemiyor</span>
                              )}
                            </div>
                          </TableCell>

                          {/* Tier */}
                          <TableCell className="py-2">
                            {c.tier ? (
                              <span className={`text-[10px] font-bold border rounded px-1.5 py-0.5 ${
                                c.tier === "tier1" ? "bg-green-900/40 text-green-400 border-green-800" :
                                c.tier === "tier2" ? "bg-blue-900/40 text-blue-400 border-blue-800" :
                                "bg-orange-900/40 text-orange-400 border-orange-800"
                              }`}>
                                {c.tier === "tier1" ? "T1" : c.tier === "tier2" ? "T2" : "T3"}
                              </span>
                            ) : <span className="text-[10px] text-slate-600">—</span>}
                          </TableCell>

                          {/* Risk */}
                          <TableCell className="py-2 text-right">
                            {c.riskScore != null ? (
                              <div>
                                <span className={`font-bold text-sm ${c.riskScore >= 70 ? "text-red-400" : c.riskScore >= 40 ? "text-orange-400" : "text-slate-400"}`}>
                                  {c.riskScore}
                                </span>
                                {c.criticalFindings > 0 && (
                                  <div className="text-[10px] text-red-500">{c.criticalFindings}K</div>
                                )}
                              </div>
                            ) : <span className="text-slate-600">—</span>}
                          </TableCell>

                          {/* Blacklist */}
                          <TableCell className="py-2 text-right">
                            {c.blacklistScore !== null ? (
                              <span className={`text-[11px] font-bold border rounded px-1 py-0.5 ${
                                c.blacklistScore < 50 ? "bg-red-900/40 text-red-400 border-red-800" :
                                c.blacklistScore < 100 ? "bg-amber-900/40 text-amber-400 border-amber-800" :
                                "bg-green-900/40 text-green-400 border-green-800"
                              }`}>{c.blacklistScore}</span>
                            ) : <span className="text-slate-700 text-xs">—</span>}
                          </TableCell>

                          {/* SSL */}
                          <TableCell className="py-2 text-right">
                            {c.sslDaysRemaining !== null ? (
                              <span className={`text-[11px] font-bold border rounded px-1 py-0.5 ${
                                c.sslDaysRemaining <= 7 ? "bg-red-900/40 text-red-400 border-red-800" :
                                c.sslDaysRemaining <= 30 ? "bg-amber-900/40 text-amber-400 border-amber-800" :
                                "bg-green-900/40 text-green-400 border-green-800"
                              }`}>{c.sslDaysRemaining}g</span>
                            ) : <span className="text-slate-700 text-xs">—</span>}
                          </TableCell>

                          {/* Mail */}
                          <TableCell className="py-2 text-right">
                            {c.mailReputationScore !== null ? (
                              <span className={`text-[11px] font-bold border rounded px-1 py-0.5 ${
                                c.mailReputationScore < 50 ? "bg-red-900/40 text-red-400 border-red-800" :
                                c.mailReputationScore < 75 ? "bg-amber-900/40 text-amber-400 border-amber-800" :
                                "bg-green-900/40 text-green-400 border-green-800"
                              }`}>{c.mailReputationScore}</span>
                            ) : <span className="text-slate-700 text-xs">—</span>}
                          </TableCell>

                          {/* Sektör / Şehir */}
                          <TableCell className="py-2">
                            {c.sector ? (
                              <div className="text-[11px] text-purple-300 truncate max-w-[120px]">{c.sector}</div>
                            ) : (
                              <span className="text-[10px] text-slate-700">—</span>
                            )}
                            {c.city && (
                              <div className="text-[10px] text-teal-400 truncate max-w-[120px] mt-0.5">{c.city}</div>
                            )}
                          </TableCell>

                          {/* Contact */}
                          <TableCell className="py-2">
                            {c.contactEmail ? (
                              <div>
                                <div className="text-xs font-mono text-slate-300 truncate max-w-[180px]">{c.contactEmail}</div>
                                {c.contactName && <div className="text-[10px] text-slate-500">{c.contactName}{c.contactTitle ? ` · ${c.contactTitle}` : ""}</div>}
                              </div>
                            ) : c.officerName ? (
                              <div className="text-xs text-slate-400">{c.officerName}{c.officerTitle ? ` · ${c.officerTitle}` : ""}</div>
                            ) : (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-yellow-900/40 text-yellow-400 border border-yellow-800/50">Eksik</span>
                            )}
                          </TableCell>

                          {/* Teaser */}
                          <TableCell className="py-2">
                            {c.teaserSentAt ? (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-900/40 text-green-400 border border-green-800/50">Gönderildi</span>
                            ) : c.teaserSubject ? (
                              <button
                                className="text-[10px] px-1.5 py-0.5 rounded bg-blue-900/40 text-blue-400 border border-blue-800/50 hover:bg-blue-800/40"
                                onClick={() => setTeaserPreview(c)}
                              >
                                Hazır — Gör
                              </button>
                            ) : (
                              <span className="text-slate-600 text-[10px]">—</span>
                            )}
                          </TableCell>

                          {/* Actions — compact vertical stack */}
                          <TableCell className="py-1.5">
                            <div className="flex flex-col items-end gap-0.5">
                              <div className="flex gap-0.5">
                                <Button size="sm" variant="ghost" className="text-[10px] h-5 px-1.5 text-slate-400 hover:text-slate-200 whitespace-nowrap"
                                  onClick={() => { setFingerprintResult(null); setDetailCandidate(c); setIsrNotesEdit(c.isrNotes ?? ""); }}>
                                  Detay
                                </Button>
                                <Button size="sm" variant="ghost" className="text-[10px] h-5 px-1.5 text-slate-400 hover:text-slate-200 whitespace-nowrap"
                                  onClick={() => { setContactEditTarget(c); setEditEmail(c.contactEmail ?? ""); setEditName(c.contactName ?? ""); setEditTitle(c.contactTitle ?? ""); }}>
                                  Kontak
                                </Button>
                              </div>
                              <div className="flex gap-0.5">
                                {!c.contactEmail && (
                                  <Button size="sm" variant="ghost" className="text-[10px] h-5 px-1.5 text-slate-400 hover:text-slate-200 whitespace-nowrap"
                                    onClick={() => reEnrich.mutate(c.id)} disabled={reEnrich.isPending}>
                                    Kontak Ara
                                  </Button>
                                )}
                                <Button size="sm" variant="ghost" className="text-[10px] h-5 px-1.5 text-slate-400 hover:text-slate-200 whitespace-nowrap"
                                  onClick={() => generateTeaser.mutate(c.id)} disabled={generateTeaser.isPending}>
                                  {c.teaserSubject ? "Yeniden Tara" : "Teaser"}
                                </Button>
                                {c.teaserSubject && !c.teaserSentAt && c.contactEmail && (
                                  <Button size="sm" className="text-[10px] h-5 px-1.5 whitespace-nowrap"
                                    onClick={() => sendTeaser.mutate(c.id)} disabled={sendTeaser.isPending}>
                                    Gönder
                                  </Button>
                                )}
                              </div>
                              <a href={buildLinkedInUrl(c)} target="_blank" rel="noopener noreferrer"
                                className="inline-flex items-center text-[10px] h-5 px-1.5 rounded text-[#0A66C2] hover:bg-[#0A66C2]/10 whitespace-nowrap">
                                LinkedIn
                              </a>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                      {!(qualifiedData?.rows?.length) && (
                        <TableRow>
                          <TableCell colSpan={7} className="text-center text-slate-500 py-12 text-sm">
                            {qSearch || qTier || qContact || qTeaser || qMinScore > 0
                              ? "Filtreyle eşleşen lead bulunamadı. Filtreleri genişletin."
                              : "Henüz qualified lead yok. Pipeline veya kalifikasyonu çalıştırın."}
                          </TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                </div>
              )}

              {/* Pagination */}
              {(qualifiedData?.total ?? 0) > 0 && (
                <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800">
                  <span className="text-xs text-slate-500">
                    {((qPage - 1) * qPageSize) + 1}–{Math.min(qPage * qPageSize, qualifiedData?.total ?? 0)}
                    {" "}/{" "}
                    <span className="font-medium text-slate-300">{(qualifiedData?.total ?? 0).toLocaleString("tr-TR")}</span> sonuç
                  </span>
                  <div className="flex items-center gap-1.5">
                    <Button size="sm" variant="outline" className="border-slate-700 text-slate-400 h-7 px-2 text-xs"
                      onClick={() => setQPage(1)} disabled={qPage === 1}>
                      «
                    </Button>
                    <Button size="sm" variant="outline" className="border-slate-700 text-slate-400 h-7 px-2 text-xs"
                      onClick={() => setQPage((p) => Math.max(1, p - 1))} disabled={qPage === 1}>
                      Önceki
                    </Button>
                    {/* Page jump */}
                    <form onSubmit={(e) => {
                      e.preventDefault();
                      const n = parseInt(qPageInput);
                      const totalPages = Math.ceil((qualifiedData?.total ?? 0) / qPageSize);
                      if (n >= 1 && n <= totalPages) { setQPage(n); setQPageInput(""); }
                    }} className="flex items-center gap-1">
                      <span className="text-xs text-slate-500">Sayfa</span>
                      <input
                        type="number"
                        min={1}
                        max={Math.ceil((qualifiedData?.total ?? 0) / qPageSize)}
                        value={qPageInput}
                        onChange={(e) => setQPageInput(e.target.value)}
                        placeholder={String(qPage)}
                        className="w-14 bg-slate-800 border border-slate-700 rounded px-2 py-0.5 text-xs text-slate-200 text-center focus:outline-none"
                      />
                      <span className="text-xs text-slate-500">/ {Math.ceil((qualifiedData?.total ?? 0) / qPageSize)}</span>
                    </form>
                    <Button size="sm" variant="outline" className="border-slate-700 text-slate-400 h-7 px-2 text-xs"
                      onClick={() => setQPage((p) => p + 1)} disabled={qPage * qPageSize >= (qualifiedData?.total ?? 0)}>
                      Sonraki
                    </Button>
                    <Button size="sm" variant="outline" className="border-slate-700 text-slate-400 h-7 px-2 text-xs"
                      onClick={() => setQPage(Math.ceil((qualifiedData?.total ?? 0) / qPageSize))}
                      disabled={qPage * qPageSize >= (qualifiedData?.total ?? 0)}>
                      »
                    </Button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </TabsContent>

        {/* ── RESULTS TAB ──────────────────────────────────────────────── */}
        <TabsContent value="results">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex flex-col gap-3">
                {/* Başlık + Excel satırı */}
                <div className="flex items-center justify-between gap-2">
                  <div>
                    <CardTitle className="text-base">Lead Adayları</CardTitle>
                    <CardDescription className="text-xs">Toplam {candidatesData?.total ?? 0} kayıt</CardDescription>
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-8 px-3 text-xs border-emerald-700/60 text-emerald-400 hover:bg-emerald-900/30 hover:text-emerald-300 disabled:opacity-50 shrink-0"
                    onClick={handleExcelExport}
                    disabled={isExporting}
                  >
                    <Download className="h-3.5 w-3.5 mr-1.5" />
                    {isExporting ? "Hazırlanıyor..." : "Excel"}
                  </Button>
                </div>
                {/* Arama satırı */}
                <form
                  className="flex items-center gap-1.5 w-full"
                  onSubmit={(e) => { e.preventDefault(); setResultsSearch(resultsSearchInput.trim()); setPage(1); }}
                >
                  <div className="relative flex-1">
                    <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
                    <Input
                      placeholder="domain ara..."
                      value={resultsSearchInput}
                      onChange={(e) => {
                        setResultsSearchInput(e.target.value);
                        if (!e.target.value.trim()) { setResultsSearch(""); setPage(1); }
                      }}
                      className="h-8 pl-7 pr-7 text-sm w-full"
                    />
                    {resultsSearchInput && (
                      <button
                        type="button"
                        onClick={() => { setResultsSearchInput(""); setResultsSearch(""); setPage(1); }}
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                      >
                        <X className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                  <Button type="submit" size="sm" className="h-8 px-3 shrink-0">Ara</Button>
                </form>
                {/* Filtreler satırı */}
                <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                  <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                    <Checkbox
                      checked={filterQualified}
                      onCheckedChange={(v) => { setFilterQualified(!!v); setFilterTier(""); setPage(1); }}
                    />
                    Kalifikasyon geçenler
                  </label>
                  <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                    <Checkbox
                      checked={filterHasContact}
                      onCheckedChange={(v) => { setFilterHasContact(!!v); setPage(1); }}
                    />
                    İletişim var
                  </label>
                  <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                    <Checkbox
                      checked={filterNotSent}
                      onCheckedChange={(v) => { setFilterNotSent(!!v); setPage(1); }}
                    />
                    Gönderilmemiş
                  </label>
                  {!filterQualified && (
                    <select
                      className="text-xs border rounded px-2 py-1 bg-background text-foreground h-7"
                      value={filterTier}
                      onChange={(e) => { setFilterTier(e.target.value); setPage(1); }}
                    >
                      <option value="">Tüm Tier'lar</option>
                      <option value="tier3">Tier 3</option>
                      <option value="tier2">Tier 2</option>
                      <option value="tier1">Tier 1 — Qualified</option>
                    </select>
                  )}
                  <button
                    onClick={() => {
                      setFilterMunicipality((v) => v === "" ? "only" : v === "only" ? "exclude" : "");
                      setPage(1);
                    }}
                    className={`px-2 py-1 rounded-md text-xs border transition-colors ${
                      filterMunicipality === "only"
                        ? "bg-blue-900/60 border-blue-500 text-blue-300"
                        : filterMunicipality === "exclude"
                        ? "bg-slate-700/60 border-slate-500 text-slate-300 line-through"
                        : "bg-slate-800 border-slate-700 text-slate-400 hover:border-blue-500/50 hover:text-blue-400"
                    }`}
                    title={filterMunicipality === "" ? "Tüm domainler (belediyeler dahil)" : filterMunicipality === "only" ? "Sadece belediyeler (.bel.tr)" : "Belediyeler hariç"}
                  >
                    {filterMunicipality === "only" ? "Sadece Belediyeler" : filterMunicipality === "exclude" ? "Belediyeler Hariç" : "Belediyeler"}
                  </button>

                  {/* Sektör filtresi */}
                  <select
                    value={filterSector}
                    onChange={(e) => { setFilterSector(e.target.value); setPage(1); }}
                    className="text-xs border rounded px-2 py-1 bg-background text-foreground h-7"
                  >
                    <option value="">Sektör: Tümü</option>
                    <option value="__empty__">Sektör: Boş</option>
                    <option value="Finans">Finans</option>
                    <option value="Saglik">Saglik</option>
                    <option value="Perakende">Perakende</option>
                    <option value="Imalat">Imalat</option>
                    <option value="Bilisim">Bilisim</option>
                    <option value="Lojistik">Lojistik</option>
                    <option value="Insaat">Insaat</option>
                    <option value="Egitim">Egitim</option>
                    <option value="Turizm">Turizm</option>
                    <option value="Enerji">Enerji</option>
                  </select>

                  {/* Şehir filtresi */}
                  <select
                    value={filterCity}
                    onChange={(e) => { setFilterCity(e.target.value); setPage(1); }}
                    className="text-xs border rounded px-2 py-1 bg-background text-foreground h-7"
                  >
                    <option value="">Sehir: Tümü</option>
                    <option value="__empty__">Sehir: Boş</option>
                    <option value="Istanbul">Istanbul</option>
                    <option value="Ankara">Ankara</option>
                    <option value="Izmir">Izmir</option>
                    <option value="Bursa">Bursa</option>
                    <option value="Antalya">Antalya</option>
                    <option value="Adana">Adana</option>
                    <option value="Gaziantep">Gaziantep</option>
                    <option value="Konya">Konya</option>
                    <option value="Kocaeli">Kocaeli</option>
                    <option value="Mersin">Mersin</option>
                  </select>

                  {/* BIST filtresi */}
                  <select
                    value={filterBistOnly ? (filterBistIndex || "bist_all") : ""}
                    onChange={(e) => {
                      const v = e.target.value;
                      if (v === "") { setFilterBistOnly(false); setFilterBistIndex(""); }
                      else if (v === "bist_all") { setFilterBistOnly(true); setFilterBistIndex(""); }
                      else { setFilterBistOnly(true); setFilterBistIndex(v); }
                      setPage(1);
                    }}
                    className="text-xs border rounded px-2 py-1 bg-background text-foreground h-7"
                  >
                    <option value="">BIST: Tümü</option>
                    <option value="bist_all">Halka Açık (BIST)</option>
                    <option value="bist30">BIST 30</option>
                    <option value="bist100">BIST 100</option>
                    <option value="bist500">BIST 500</option>
                  </select>

                  {/* Kaynak filtresi */}
                  <select
                    value={filterSource}
                    onChange={(e) => { setFilterSource(e.target.value); setPage(1); }}
                    className="text-xs border rounded px-2 py-1 bg-background text-foreground h-7"
                  >
                    <option value="">Kaynak: Tümü</option>
                    <option value="certstream-bridge">Certstream</option>
                    <option value="shodan_free">Shodan</option>
                    <option value="ct_discovery">crt.sh</option>
                    <option value="ripe_dns_test">RIPE DNS</option>
                    <option value="excel_import">Excel Import</option>
                    <option value="manual_scan">Manuel</option>
                  </select>

                  {/* Tarama durumu filtresi */}
                  <select
                    value={filterScanStatus}
                    onChange={(e) => { setFilterScanStatus(e.target.value); setPage(1); }}
                    className="text-xs border rounded px-2 py-1 bg-background text-foreground h-7"
                  >
                    <option value="">Tarama: Tümü</option>
                    <option value="pending">Bekliyor</option>
                    <option value="scanned">Tarandı</option>
                    <option value="failed">Başarısız</option>
                    <option value="qualified">Nitelendirilen</option>
                    <option value="disqualified">Elenen</option>
                  </select>

                  {/* Site durumu filtresi */}
                  <select
                    value={filterIsAlive}
                    onChange={(e) => { setFilterIsAlive(e.target.value); setPage(1); }}
                    className="text-xs border rounded px-2 py-1 bg-background text-foreground h-7"
                  >
                    <option value="">Site: Tümü</option>
                    <option value="true">Aktif</option>
                    <option value="false">Pasif/Bilinmiyor</option>
                  </select>

                  {/* Fortinet filtresi */}
                  <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                    <Checkbox
                      checked={filterHasFortigate}
                      onCheckedChange={(v) => { setFilterHasFortigate(!!v); setPage(1); }}
                    />
                    Fortinet
                  </label>

                  {/* Aktif filtre sayısı + temizle */}
                  {(filterSource || filterScanStatus || filterIsAlive || filterHasFortigate || filterSector || filterCity || filterBistOnly) && (
                    <button
                      onClick={() => {
                        setFilterSource(""); setFilterScanStatus(""); setFilterIsAlive("");
                        setFilterHasFortigate(false); setFilterSector(""); setFilterCity("");
                        setFilterBistOnly(false); setFilterBistIndex(""); setPage(1);
                      }}
                      className="text-xs text-muted-foreground hover:text-foreground underline"
                    >
                      Filtreleri temizle
                    </button>
                  )}
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {candidatesLoading ? (
                <div className="text-center py-8 text-muted-foreground text-sm">Yukleniyor...</div>
              ) : (
                <>
                  <div className="overflow-x-auto -mx-1">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Domain / Şirket</TableHead>
                        <TableHead>Tier</TableHead>
                        <TableHead>Kaynak Detay</TableHead>
                        <TableHead className="text-right">Risk</TableHead>
                        <TableHead>Sektör / Şehir</TableHead>
                        <TableHead>Bulgular</TableHead>
                        <TableHead>İletişim</TableHead>
                        <TableHead>Teaser</TableHead>
                        <TableHead></TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {(candidatesData?.rows ?? []).map((c) => {
                        const sd = c.sourceData;
                        const tierLabel = c.tier === "tier1" ? "T1" : c.tier === "tier2" ? "T2" : c.tier === "tier3" ? "T3" : "—";
                        const tierCls = c.tier === "tier1"
                          ? "bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-400 border-green-300 dark:border-green-700"
                          : c.tier === "tier2"
                          ? "bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-400 border-blue-300 dark:border-blue-700"
                          : "bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-400 border-orange-300 dark:border-orange-700";
                        return (
                        <TableRow key={c.id}>
                          <TableCell>
                            <div className="font-medium text-sm">{c.domain}</div>
                            {c.companyName && <div className="text-xs text-muted-foreground truncate max-w-[160px]">{c.companyName}</div>}
                            <div className="flex gap-1 mt-0.5">
                              {!!c.hasFortigate && <span className="text-[10px] text-orange-600 font-medium">FortiGate</span>}
                              {c.isQualified && <span className="text-[10px] text-green-600 font-medium">Kalifikasyon</span>}
                            </div>
                          </TableCell>
                          <TableCell>
                            <span className={`text-[10px] font-bold border rounded px-1.5 py-0.5 ${tierCls}`}>
                              {tierLabel}
                            </span>
                            {c.tier && (
                              <div className="text-[9px] text-muted-foreground mt-0.5">
                                {c.tier === "tier1" ? "Qualified" : c.tier === "tier2" ? "OSINT" : "Ön-eleme"}
                              </div>
                            )}
                          </TableCell>
                          <TableCell>
                            <div className="space-y-0.5">
                              <Badge variant="outline" className="text-[10px] h-4">
                                {c.source === "crtsh" ? "crt.sh" : "Shodan"}
                              </Badge>
                              {sd?.ip && (
                                <div className="text-[10px] font-mono text-muted-foreground">
                                  {sd.ip}{sd.port ? `:${sd.port}` : ""}
                                </div>
                              )}
                              {sd?.product && (
                                <div className="text-[10px] text-blue-600 truncate max-w-[130px]">{sd.product}</div>
                              )}
                              {sd?.shodanQuery && (
                                <div className="text-[10px] text-muted-foreground italic truncate max-w-[130px]">{sd.shodanQuery}</div>
                              )}
                            </div>
                          </TableCell>
                          <TableCell className="text-right">
                            {c.riskScore != null ? (
                              <div className="text-right">
                                <span className={`font-bold text-sm ${c.riskScore >= 70 ? "text-red-600" : c.riskScore >= 40 ? "text-orange-500" : "text-gray-500"}`}>
                                  {c.riskScore}
                                </span>
                                {c.criticalFindings > 0 && (
                                  <div className="text-[10px] text-red-500">{c.criticalFindings} kritik</div>
                                )}
                              </div>
                            ) : "—"}
                          </TableCell>
                          <TableCell>
                            {c.sector ? (
                              <div className="text-[11px] text-purple-600 dark:text-purple-300 truncate max-w-[120px]">{c.sector}</div>
                            ) : (
                              <span className="text-[10px] text-muted-foreground/40">—</span>
                            )}
                            {c.city && (
                              <div className="text-[10px] text-teal-600 dark:text-teal-400 truncate max-w-[120px] mt-0.5">{c.city}</div>
                            )}
                          </TableCell>
                          <TableCell className="max-w-[180px]">
                            <FindingBadges highlights={c.findingHighlights} />
                          </TableCell>
                          <TableCell>
                            {c.contactEmail ? (
                              <div>
                                <div className="text-xs font-medium">{c.contactName ?? c.contactEmail}</div>
                                <div className="text-xs text-muted-foreground">{c.contactTitle}</div>
                              </div>
                            ) : (
                              <span className="text-xs text-muted-foreground">Yok</span>
                            )}
                          </TableCell>
                          <TableCell>
                            {c.teaserSentAt ? (
                              <Badge className="bg-green-100 text-green-700 text-xs">Gönderildi</Badge>
                            ) : c.teaserSubject ? (
                              <button
                                className="text-xs text-blue-600 underline hover:no-underline"
                                onClick={() => setTeaserPreview(c)}
                              >
                                Hazir (Önizle)
                              </button>
                            ) : (
                              <span className="text-xs text-muted-foreground">—</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <div className="flex flex-col gap-1">
                              <Button
                                size="sm"
                                variant="outline"
                                className="text-xs h-7 w-full"
                                onClick={() => { setFingerprintResult(null); setDetailCandidate(c); }}
                              >
                                Detay
                              </Button>
                              {c.isQualified && (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  className="text-xs h-7 w-full"
                                  onClick={() => generateTeaser.mutate(c.id)}
                                  disabled={generateTeaser.isPending}
                                >
                                  {c.teaserSubject ? "Yeniden Üret" : "Teaser"}
                                </Button>
                              )}
                              {!!c.teaserSubject && !c.teaserSentAt && c.contactEmail && (
                                <Button
                                  size="sm"
                                  className="text-xs h-7 w-full"
                                  onClick={() => sendTeaser.mutate(c.id)}
                                  disabled={sendTeaser.isPending}
                                >
                                  Gönder
                                </Button>
                              )}
                              {c.isQualified && (
                                c.isrPromotedAt ? (
                                  <span className="inline-flex items-center justify-center text-xs h-7 w-full rounded-md border border-green-200 bg-green-50 text-green-700 font-medium">
                                    ISR Listesinde
                                  </span>
                                ) : (
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    className="text-xs h-7 w-full text-purple-600 border-purple-200 hover:bg-purple-50"
                                    onClick={() => promoteToIsr.mutate(c)}
                                    disabled={promoteToIsr.isPending}
                                  >
                                    ISR Listesine Ekle
                                  </Button>
                                )
                              )}
                              <Button
                                size="sm"
                                variant="ghost"
                                className="text-xs h-7 w-full text-red-500 hover:text-red-700"
                                onClick={() => { if (confirm("Aday silinsin mi?")) deleteCandidate.mutate(c.id); }}
                              >
                                Sil
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                  </div>

                  {/* Pagination */}
                  {(candidatesData?.total ?? 0) > 20 && (
                    <div className="flex justify-between items-center mt-4">
                      <span className="text-sm text-muted-foreground">
                        {((page - 1) * 20) + 1}–{Math.min(page * 20, candidatesData?.total ?? 0)} / {candidatesData?.total ?? 0}
                      </span>
                      <div className="flex gap-2">
                        <Button size="sm" variant="outline" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}>
                          Önceki
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => setPage((p) => p + 1)} disabled={page * 20 >= (candidatesData?.total ?? 0)}>
                          Sonraki
                        </Button>
                      </div>
                    </div>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── HISTORY TAB ──────────────────────────────────────────────── */}
        <TabsContent value="history">
          <Card>
            <CardHeader>
              <CardTitle>Tarama Gecmisi</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto -mx-1">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Kaynak</TableHead>
                    <TableHead>Parametreler</TableHead>
                    <TableHead>Durum</TableHead>
                    <TableHead className="text-right">Bulunan</TableHead>
                    <TableHead className="text-right">Eklenen</TableHead>
                    <TableHead>Tarih</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(runs ?? []).map((r) => (
                    <TableRow key={r.id}>
                      <TableCell>
                        <Badge variant="outline">
                          {r.source === "crtsh" ? "crt.sh" : "Shodan"}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground font-mono max-w-[240px] truncate">
                        {r.runParams ? (
                          (r.runParams["query"] as string) ?? (r.runParams["label"] as string) ?? JSON.stringify(r.runParams)
                        ) : "—"}
                      </TableCell>
                      <TableCell>{runStatusBadge(r.status)}</TableCell>
                      <TableCell className="text-right">{r.totalFound}</TableCell>
                      <TableCell className="text-right">{r.totalAdded}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {new Date(r.startedAt).toLocaleString("tr-TR")}
                        {r.completedAt && (
                          <div className="text-[10px]">
                            {Math.round((new Date(r.completedAt).getTime() - new Date(r.startedAt).getTime()) / 1000)}s
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                  {!(runs?.length) && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-muted-foreground py-8 text-sm">
                        Henuz tarama yapilmadi. crt.sh veya Shodan taramasini basaltin.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── ISP GRUPLARI TAB ─────────────────────────────────────────── */}
        <TabsContent value="isp-gruplari">
          <IspGroupsView />
        </TabsContent>

        {/* ── PUANLAMA REHBERİ TAB ─────────────────────────────────────── */}
        <TabsContent value="puanlama-rehberi">
          <div className="space-y-4 text-sm">

            {/* Kalifikasyon kriteri */}
            <Card className="bg-slate-900 border-slate-700">
              <CardHeader className="pb-3">
                <CardTitle className="text-base text-slate-200">Kalifikasyon Kriteri</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="rounded-lg border border-green-800/40 bg-green-950/30 p-4">
                    <div className="text-green-400 font-semibold text-sm mb-1">Risk Skoru &lt; 60 → Qualified (Tier1)</div>
                    <div className="text-slate-400 text-xs">Domain, kontakt aramasına ve teaser oluşturulmasına dahil edilir.</div>
                  </div>
                  <div className="rounded-lg border border-red-800/40 bg-red-950/30 p-4">
                    <div className="text-red-400 font-semibold text-sm mb-1">Risk Skoru ≥ 60 → Reddedildi (Tier2 kalır)</div>
                    <div className="text-slate-400 text-xs">Domain taranmış olarak işaretlenir, qualified olmaz. Skor güvenlik bulgularının azlığını gösterir.</div>
                  </div>
                </div>
                <div className="mt-3 text-xs text-slate-500 bg-slate-800/40 rounded p-3">
                  Not: Düşük risk skoru = daha az güvenlik kontrolü = siber güvenlik ihtiyacı yüksek = iyi lead. Yüksek skor = güvenli sistem = hizmet ihtiyacı düşük.
                </div>
              </CardContent>
            </Card>

            {/* Temel domain risk skoru */}
            <Card className="bg-slate-900 border-slate-700">
              <CardHeader className="pb-3">
                <CardTitle className="text-base text-slate-200">Temel Domain Risk Skoru (0–100)</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-slate-700">
                        <th className="text-left py-2 pr-4 text-slate-400 font-medium">Bileşen</th>
                        <th className="text-right py-2 pr-4 text-slate-400 font-medium">Max</th>
                        <th className="text-left py-2 text-slate-400 font-medium">Puanlama Detayı</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-300 font-medium">SPF Kaydı</td>
                        <td className="py-2.5 pr-4 text-right text-blue-400 font-mono font-bold">20</td>
                        <td className="py-2.5 text-slate-400">
                          <span className="inline-block bg-green-900/40 text-green-400 px-1.5 py-0.5 rounded mr-1">hardfail → 20</span>
                          <span className="inline-block bg-yellow-900/40 text-yellow-400 px-1.5 py-0.5 rounded mr-1">softfail → 14</span>
                          <span className="inline-block bg-slate-700 text-slate-300 px-1.5 py-0.5 rounded mr-1">neutral → 10</span>
                          <span className="inline-block bg-red-900/40 text-red-400 px-1.5 py-0.5 rounded">yok → 0</span>
                        </td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-300 font-medium">DMARC Politikası</td>
                        <td className="py-2.5 pr-4 text-right text-blue-400 font-mono font-bold">25</td>
                        <td className="py-2.5 text-slate-400">
                          <span className="inline-block bg-green-900/40 text-green-400 px-1.5 py-0.5 rounded mr-1">reject → 25</span>
                          <span className="inline-block bg-yellow-900/40 text-yellow-400 px-1.5 py-0.5 rounded mr-1">quarantine → 20</span>
                          <span className="inline-block bg-slate-700 text-slate-300 px-1.5 py-0.5 rounded mr-1">none (izleme) → 10</span>
                          <span className="inline-block bg-red-900/40 text-red-400 px-1.5 py-0.5 rounded">yok → 0</span>
                        </td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-300 font-medium">DKIM İmzası</td>
                        <td className="py-2.5 pr-4 text-right text-blue-400 font-mono font-bold">20</td>
                        <td className="py-2.5 text-slate-400">
                          <span className="inline-block bg-green-900/40 text-green-400 px-1.5 py-0.5 rounded mr-1">tespit edildi → 20</span>
                          <span className="inline-block bg-slate-700 text-slate-300 px-1.5 py-0.5 rounded">tespit edilemedi → 8 (kısmi kredi)</span>
                        </td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-300 font-medium">MX Kaydı</td>
                        <td className="py-2.5 pr-4 text-right text-blue-400 font-mono font-bold">10</td>
                        <td className="py-2.5 text-slate-400">
                          <span className="inline-block bg-green-900/40 text-green-400 px-1.5 py-0.5 rounded mr-1">var → 10</span>
                          <span className="inline-block bg-red-900/40 text-red-400 px-1.5 py-0.5 rounded">yok → 0</span>
                        </td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-300 font-medium">SSL Sertifikası</td>
                        <td className="py-2.5 pr-4 text-right text-blue-400 font-mono font-bold">25</td>
                        <td className="py-2.5 text-slate-400 space-y-0.5">
                          <div>
                            <span className="inline-block bg-green-900/40 text-green-400 px-1.5 py-0.5 rounded mr-1">60+ gün → 25</span>
                            <span className="inline-block bg-green-900/30 text-green-300 px-1.5 py-0.5 rounded mr-1">30–59 gün → 20</span>
                            <span className="inline-block bg-yellow-900/40 text-yellow-400 px-1.5 py-0.5 rounded mr-1">14–29 gün → 15</span>
                            <span className="inline-block bg-orange-900/40 text-orange-400 px-1.5 py-0.5 rounded mr-1">7–13 gün → 8</span>
                            <span className="inline-block bg-red-900/40 text-red-400 px-1.5 py-0.5 rounded mr-1">1–6 gün → 2</span>
                            <span className="inline-block bg-red-900/60 text-red-300 px-1.5 py-0.5 rounded">süresi dolmuş / yok → 0</span>
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-red-400 font-medium">Port Cezası</td>
                        <td className="py-2.5 pr-4 text-right text-red-400 font-mono font-bold">−X</td>
                        <td className="py-2.5 text-slate-400">Yüksek riskli açık portlar için toplam skora eksi puan uygulanır.</td>
                      </tr>
                    </tbody>
                    <tfoot>
                      <tr className="border-t border-slate-600">
                        <td className="pt-2.5 pr-4 text-slate-200 font-semibold">Toplam</td>
                        <td className="pt-2.5 pr-4 text-right text-white font-mono font-bold">100</td>
                        <td className="pt-2.5 text-slate-500 text-xs">SPF + DMARC + DKIM + MX + SSL − Port Cezası</td>
                      </tr>
                    </tfoot>
                  </table>
                </div>
              </CardContent>
            </Card>

            {/* WAF/CDN güven skoru */}
            <Card className="bg-slate-900 border-slate-700">
              <CardHeader className="pb-3">
                <CardTitle className="text-base text-slate-200">WAF/CDN Güven Skoru (Tarama Güvenilirliği)</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-slate-400 text-xs mb-3">
                  WAF/CDN varlığı taramanın ne kadar güvenilir olduğunu etkiler. Gerçek sunucuya ulaşamıyorsak bulgular eksik olabilir.
                </p>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-slate-700">
                        <th className="text-left py-2 pr-4 text-slate-400 font-medium">Durum</th>
                        <th className="text-right py-2 pr-4 text-slate-400 font-medium">Güven %</th>
                        <th className="text-left py-2 text-slate-400 font-medium">Açıklama</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {[
                        { durum: "WAF yok, CDN yok", gven: 95, color: "text-green-400", aciklama: "Gerçek sunucuya doğrudan erişim — en güvenilir tarama sonucu." },
                        { durum: "Sadece CDN var (WAF yok)", gven: 85, color: "text-green-300", aciklama: "CDN arkasında ama WAF tespit edilmedi. Bazı portlar CDN'e ait olabilir." },
                        { durum: "WAF var (düşük güven)", gven: 75, color: "text-yellow-300", aciklama: "WAF tespit edildi ancak tek yöntemle — dolaylı tespit." },
                        { durum: "WAF var (orta güven)", gven: 78, color: "text-yellow-400", aciklama: "WAF orta kesinlikte tespit edildi (1 yöntem, yüksek skor)." },
                        { durum: "WAF var (yüksek güven)", gven: 72, color: "text-orange-400", aciklama: "WAF yüksek kesinlikte tespit edildi (2+ yöntem). CVE skorları düşürülür." },
                        { durum: "OSINT bypass riski yüksek", gven: 60, color: "text-orange-500", aciklama: "OSINT analizi WAF bypass ihtimalini yüksek buluyor. Risk azaltımı uygulanmaz." },
                        { durum: "WAF bypass mümkün", gven: 55, color: "text-red-400", aciklama: "Kaynak IP'ye doğrudan erişim mümkün — WAF koruması devre dışı sayılır." },
                      ].map((row) => (
                        <tr key={row.durum}>
                          <td className="py-2.5 pr-4 text-slate-300">{row.durum}</td>
                          <td className={`py-2.5 pr-4 text-right font-mono font-bold ${row.color}`}>%{row.gven}</td>
                          <td className="py-2.5 text-slate-400">{row.aciklama}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>

            {/* CVE risk ayarlaması */}
            <Card className="bg-slate-900 border-slate-700">
              <CardHeader className="pb-3">
                <CardTitle className="text-base text-slate-200">WAF Varlığında CVE Risk Ayarlaması</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-slate-400 text-xs mb-3">
                  WAF tespit edildiğinde Shodan/NVD CVE skorları pratik risk yansıtacak şekilde ayarlanır.
                </p>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-slate-700">
                        <th className="text-left py-2 pr-4 text-slate-400 font-medium">Durum</th>
                        <th className="text-left py-2 pr-4 text-slate-400 font-medium">Etki</th>
                        <th className="text-left py-2 text-slate-400 font-medium">Örnek</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-300">WAF yok</td>
                        <td className="py-2.5 pr-4 text-slate-400">CVE skorları değişmez</td>
                        <td className="py-2.5 text-slate-500">CVSS 9.8 → 9.8</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-300">WAF var + Bypass mümkün</td>
                        <td className="py-2.5 pr-4 text-orange-400">Risk azaltımı uygulanmaz</td>
                        <td className="py-2.5 text-slate-500">CVSS 9.8 → 9.8 (bypass var)</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-300">WAF var + CVSS ≥ 9.0 (Kritik)</td>
                        <td className="py-2.5 pr-4 text-green-400">%40 azaltma (× 0.60)</td>
                        <td className="py-2.5 text-slate-500">CVSS 9.8 → 5.9</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-300">WAF var + CVSS ≥ 7.0 (Yüksek)</td>
                        <td className="py-2.5 pr-4 text-green-400">%35 azaltma (× 0.65)</td>
                        <td className="py-2.5 text-slate-500">CVSS 8.2 → 5.3</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-300">WAF var + CVSS &lt; 7.0</td>
                        <td className="py-2.5 pr-4 text-slate-400">Sadece not eklenir</td>
                        <td className="py-2.5 text-slate-500">CVSS 5.5 → 5.5 (not: WAF hafifletir)</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-300">SSL / TLS / SMTP servisleri</td>
                        <td className="py-2.5 pr-4 text-slate-400">WAF'tan bağımsız — değişmez</td>
                        <td className="py-2.5 text-slate-500">E-posta, sertifika açıkları etkilenmez</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>

            {/* AI Lead Skoru */}
            <Card className="bg-slate-900 border-slate-700">
              <CardHeader className="pb-3">
                <CardTitle className="text-base text-slate-200">AI Lead Skoru (0–100)</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-slate-400 text-xs mb-3">
                  Tarama verisi Claude AI ile değerlendirilir; satış öncelik sıralaması için kullanılır. Domain risk skoru ile bağımsız çalışır.
                </p>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-slate-700">
                        <th className="text-left py-2 pr-4 text-slate-400 font-medium">Faktör</th>
                        <th className="text-right py-2 pr-4 text-slate-400 font-medium">Max Puan</th>
                        <th className="text-left py-2 text-slate-400 font-medium">Değerlendirilen</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {[
                        { faktor: "risk_score", max: 20, aciklama: "Domain risk skoru yüksekse siber güvenlik ihtiyacı fazladır" },
                        { faktor: "critical_count", max: 20, aciklama: "Kritik bulgu sayısı" },
                        { faktor: "urgency_signal", max: 20, aciklama: "Aktif saldırı, bilinen açıklar, CISA KEV listesi" },
                        { faktor: "conversion_potential", max: 25, aciklama: "Dönüşüm potansiyeli (sektör, büyüklük, erişilebilirlik)" },
                        { faktor: "company_size_signal", max: 15, aciklama: "Şirket büyüklüğü sinyali (çalışan sayısı, ASN)" },
                      ].map((row) => (
                        <tr key={row.faktor}>
                          <td className="py-2.5 pr-4 font-mono text-purple-400">{row.faktor}</td>
                          <td className="py-2.5 pr-4 text-right text-blue-400 font-mono font-bold">{row.max}</td>
                          <td className="py-2.5 text-slate-400">{row.aciklama}</td>
                        </tr>
                      ))}
                      <tr className="border-t border-slate-600">
                        <td className="pt-2.5 pr-4 text-slate-200 font-semibold">Toplam</td>
                        <td className="pt-2.5 pr-4 text-right text-white font-mono font-bold">100</td>
                        <td className="pt-2.5 text-slate-500 text-xs">AI skoru düşük ya da hesaplanamadıysa 30 puan (varsayılan) atanır</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>

            {/* WAF tespit yöntemleri */}
            <Card className="bg-slate-900 border-slate-700">
              <CardHeader className="pb-3">
                <CardTitle className="text-base text-slate-200">WAF Tespit Yöntemleri ve Güven Seviyeleri</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <div className="text-slate-400 text-xs font-medium mb-2 uppercase tracking-wide">Tespit Yöntemleri</div>
                    <div className="space-y-1.5 text-xs">
                      {[
                        { yontem: "header_signature", aciklama: "HTTP response header / cookie / body imza eşleşmesi" },
                        { yontem: "dns_ptr_ip_range", aciklama: "DNS PTR kaydı veya Cloudflare IP CIDR aralığı" },
                        { yontem: "tls_cert", aciklama: "TLS sertifika issuer (Cloudflare, Sucuri)" },
                        { yontem: "indirect_cdn", aciklama: "Dolaylı CDN header sinyali (x-cache, via, x-amz-cf-id vb.)" },
                      ].map((r) => (
                        <div key={r.yontem} className="flex gap-2">
                          <span className="font-mono text-purple-400 shrink-0">{r.yontem}</span>
                          <span className="text-slate-500">— {r.aciklama}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-400 text-xs font-medium mb-2 uppercase tracking-wide">Güven Seviyesi Kuralı</div>
                    <div className="space-y-1.5 text-xs text-slate-400">
                      <div><span className="text-green-400 font-medium">Yüksek (high):</span> 2+ yöntem veya tek yöntem + skor ≥ 60</div>
                      <div><span className="text-yellow-400 font-medium">Orta (medium):</span> Tek yöntem + skor 35–59</div>
                      <div><span className="text-slate-400 font-medium">Düşük (low):</span> Tek yöntem + skor &lt; 35</div>
                    </div>
                    <div className="mt-3">
                      <div className="text-slate-400 text-xs font-medium mb-2 uppercase tracking-wide">Desteklenen WAF/CDN</div>
                      <div className="flex flex-wrap gap-1">
                        {["Cloudflare", "F5 BIG-IP", "Akamai", "Imperva", "Sucuri", "AWS WAF", "Fortinet FortiWeb", "Fastly", "Azure CDN", "AWS CloudFront"].map((w) => (
                          <span key={w} className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded border border-slate-700">{w}</span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* WAF Post-Qualification Enrichment */}
            <Card className="bg-slate-900 border-slate-700">
              <CardHeader className="pb-3">
                <CardTitle className="text-base text-slate-200">WAF Post-Qualification Enrichment</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-slate-400 text-xs">
                  Kalifikasyondan geçen lead'ler için WAF tespiti ayrı bir cron ile çalışır — kalifikasyon anında değil, sonrasında.
                  Her 30 dakikada bir en fazla 50 satır işlenir. Timeout ile gerçek sonuç birbirinden kesinlikle ayrılır.
                </p>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-slate-700">
                        <th className="text-left py-2 pr-4 text-slate-400 font-medium">Durum</th>
                        <th className="text-left py-2 pr-4 text-slate-400 font-medium">waf_enrichment_status</th>
                        <th className="text-left py-2 text-slate-400 font-medium">Anlam</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      <tr>
                        <td className="py-2.5 pr-4 text-slate-300">Bekliyor</td>
                        <td className="py-2.5 pr-4 font-mono text-slate-500">null</td>
                        <td className="py-2.5 text-slate-400">Henüz işlenmedi veya timeout — bir sonraki run dener</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-green-400">Tamamlandı</td>
                        <td className="py-2.5 pr-4 font-mono text-green-400">enriched</td>
                        <td className="py-2.5 text-slate-400">Gerçek WAF sonucu alındı, waf_enriched_at set edildi</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 pr-4 text-orange-400">Kalıcı timeout</td>
                        <td className="py-2.5 pr-4 font-mono text-orange-400">unknown_timeout</td>
                        <td className="py-2.5 text-slate-400">3 denemede de timeout — bir sonraki cron run bu satırı atlar</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                <div className="rounded-lg border border-amber-800/40 bg-amber-950/20 p-3 text-xs text-amber-300 space-y-1">
                  <div className="font-semibold">Kritik ayrım: timeout ≠ "WAF yok"</div>
                  <div className="text-amber-400/80">
                    <span className="font-mono">waf_enriched_at</span> yalnızca gerçek bir sonuç alındığında set edilir.
                    Timeout olduğunda null kalır — bu, WAF olmadığı anlamına gelmez.
                    3 timeout sonrası satır <span className="font-mono">unknown_timeout</span> olarak işaretlenir ve artık seçilmez.
                  </div>
                </div>
                <div className="text-xs text-slate-500 bg-slate-800/40 rounded p-2.5">
                  Cron: her 30 dakika — Limit: 50 satır/run — Eşzamanlılık: 3 — Toplam 886 lead için tahmini süre: ~9 saat
                </div>
              </CardContent>
            </Card>

            {/* Teaser anlık görüntü politikası */}
            <Card className="bg-slate-900 border-slate-700">
              <CardHeader className="pb-3">
                <CardTitle className="text-base text-slate-200">Teaser Anlık Görüntü Politikası</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-slate-400 text-xs">
                  Teaser raporu, kalifikasyon anındaki tarama verileriyle bir kez üretilir.
                  WAF enrichment tamamlandığında teaser yenilenmez — bu bilinçli bir tasarım kararıdır.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="rounded-lg border border-blue-800/40 bg-blue-950/20 p-3 text-xs space-y-1">
                    <div className="text-blue-300 font-semibold">Hız &gt; Kesinlik</div>
                    <div className="text-slate-400">
                      Teaser, kalifikasyon olur olmaz üretilebilir. WAF enrichment kuyruğunu beklersek bazı lead'ler 9 saat gecikmeli teaser alır — bu, snapshot modelinin seçilme sebebidir.
                    </div>
                  </div>
                  <div className="rounded-lg border border-green-800/40 bg-green-950/20 p-3 text-xs space-y-1">
                    <div className="text-green-300 font-semibold">Yön Güvenli</div>
                    <div className="text-slate-400">
                      WAF enrichment sonradan WAF bulursa bulgular azalır, artmaz — teaser her zaman gerçekte olduğundan daha kötümser kalır, asla daha iyimser değil. Satış mesajı geçerliliğini korur.
                    </div>
                  </div>
                </div>
                <div className="rounded-lg border border-slate-700 bg-slate-800/40 p-3 text-xs text-slate-400">
                  Her teaser'ın <span className="font-mono text-slate-300">urgency_note</span> alanına sabit bir dipnot eklenir:
                  <span className="block mt-1 italic text-slate-500">"Bu ön taramadır; bulgular tarama anındaki verileri yansıtmaktadır."</span>
                  Bu ekleme AI çıktısından bağımsız — hata durumunda dahi garantilidir.
                </div>
              </CardContent>
            </Card>

          </div>
        </TabsContent>

        {/* ── CVE RAPORU TAB ───────────────────────────────────────────── */}
        <TabsContent value="cve-raporu">
          <div className="space-y-4">
            {/* Filtreler */}
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex flex-wrap items-center gap-3">
                  <div className="flex items-center gap-2">
                    <Label className="text-xs shrink-0">Min CVSS</Label>
                    <Select value={cveMinCvss} onValueChange={v => { setCveMinCvss(v); setCveExpanded(new Set()); }}>
                      <SelectTrigger className="h-8 w-24 text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {["0.0","4.0","5.0","6.0","7.0","8.0","9.0","9.5","10.0"].map(v => (
                          <SelectItem key={v} value={v} className="text-xs">{v === "0.0" ? "Tümü" : `${v}+`}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="flex items-center gap-2">
                    <Label className="text-xs shrink-0">Severity</Label>
                    <Select value={cveSeverity || "__all__"} onValueChange={v => { setCveSeverity(v === "__all__" ? "" : v); setCveExpanded(new Set()); }}>
                      <SelectTrigger className="h-8 w-28 text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="__all__" className="text-xs">Tümü</SelectItem>
                        <SelectItem value="critical" className="text-xs">Critical</SelectItem>
                        <SelectItem value="high" className="text-xs">High</SelectItem>
                        <SelectItem value="medium" className="text-xs">Medium</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <label className="flex items-center gap-1.5 cursor-pointer select-none">
                    <Checkbox checked={cveOnlyExploit} onCheckedChange={v => { setCveOnlyExploit(!!v); setCveExpanded(new Set()); }} className="h-4 w-4" />
                    <span className="text-xs">Exploit var</span>
                  </label>
                  <label className="flex items-center gap-1.5 cursor-pointer select-none">
                    <Checkbox checked={cveOnlyKev} onCheckedChange={v => { setCveOnlyKev(!!v); setCveExpanded(new Set()); }} className="h-4 w-4" />
                    <span className="text-xs">CISA KEV</span>
                  </label>
                  <div className="ml-auto flex items-center gap-2">
                    <button
                      onClick={() => { cveReenrich.mutate(); }}
                      disabled={cveReenrich.isPending}
                      className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-input bg-background hover:bg-accent font-medium disabled:opacity-50"
                      title="NVD'den patch_available=false CVE'lerin yama durumunu sorgular (CISA KEV öncelikli, en fazla 50 CVE)"
                    >
                      <ShieldAlert className={`h-3.5 w-3.5 ${cveReenrich.isPending ? "animate-pulse" : ""}`} />
                      {cveReenrich.isPending ? "Sorgulanıyor..." : "Yamayı NVD'den Güncelle"}
                    </button>
                    <button
                      onClick={async () => {
                        const result = await cveRefetch();
                        if (result.status === "success") {
                          toast({ description: `CVE raporu yenilendi — ${result.data?.total ?? 0} CVE.` });
                        } else if (result.status === "error") {
                          toast({ description: "Yenileme başarısız.", variant: "destructive" });
                        }
                      }}
                      disabled={cveFetching}
                      className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-input bg-background hover:bg-accent font-medium disabled:opacity-50"
                      title="DB'deki güncel veriyi ekrana yansıtır"
                    >
                      <RefreshCw className={`h-3.5 w-3.5 ${cveFetching ? "animate-spin" : ""}`} />
                      {cveFetching ? "Yükleniyor..." : "Veriyi Yenile"}
                    </button>
                    <a
                      href={`${BASE}/lead-discovery/cve-report/export?minCvss=${cveMinCvss}${cveSeverity ? `&severity=${cveSeverity}` : ""}${cveOnlyExploit ? "&exploit=1" : ""}${cveOnlyKev ? "&kev=1" : ""}`}
                      download
                      className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-input bg-background hover:bg-accent font-medium"
                    >
                      <Download className="h-3.5 w-3.5" />
                      CSV indir
                    </a>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Özet istatistikler */}
            {cveReport && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { label: "Eşleşen CVE", value: cveReport.total, icon: <ShieldAlert className="h-4 w-4 text-red-500" /> },
                  { label: "Etkilenen Domain", value: new Set(cveReport.cves.flatMap(c => c.domains.map(d => d.domain))).size, icon: <AlertTriangle className="h-4 w-4 text-orange-500" /> },
                  { label: "Yama Yok", value: cveReport.cves.filter(c => c.patchAvailable === false).length, icon: <AlertTriangle className="h-4 w-4 text-red-600" /> },
                  { label: "CISA KEV", value: cveReport.cves.filter(c => c.cisaKev).length, icon: <ShieldAlert className="h-4 w-4 text-purple-600" /> },
                ].map(s => (
                  <Card key={s.label}>
                    <CardContent className="pt-3 pb-3 flex items-center gap-2">
                      {s.icon}
                      <div>
                        <div className="text-lg font-bold leading-none">{s.value}</div>
                        <div className="text-[11px] text-muted-foreground mt-0.5">{s.label}</div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}

            {/* CVE tablosu */}
            <Card>
              <CardContent className="p-0">
                {cveLoading ? (
                  <div className="py-12 text-center text-sm text-muted-foreground">Yükleniyor...</div>
                ) : !cveReport || cveReport.cves.length === 0 ? (
                  <div className="py-12 text-center text-sm text-muted-foreground">Bu filtrede CVE bulunamadı.</div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-8"></TableHead>
                        <TableHead className="text-xs">CVE ID</TableHead>
                        <TableHead className="text-xs text-right">CVSS</TableHead>
                        <TableHead className="text-xs">Severity</TableHead>
                        <TableHead className="text-xs">Baslik</TableHead>
                        <TableHead className="text-xs text-center">Exploit</TableHead>
                        <TableHead className="text-xs text-center">KEV</TableHead>
                        <TableHead className="text-xs text-center">Yama</TableHead>
                        <TableHead className="text-xs text-right">Domain</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {cveReport.cves.map(cve => {
                        const isOpen = cveExpanded.has(cve.cveId);
                        const severityColor =
                          cve.severity === "critical" ? "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400" :
                          cve.severity === "high" ? "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400" :
                          "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400";
                        return (
                          <>
                            <TableRow
                              key={cve.cveId}
                              className="cursor-pointer hover:bg-muted/50"
                              onClick={() => setCveExpanded(prev => {
                                const next = new Set(prev);
                                if (next.has(cve.cveId)) next.delete(cve.cveId); else next.add(cve.cveId);
                                return next;
                              })}
                            >
                              <TableCell className="py-2 pr-0">
                                {isOpen ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />}
                              </TableCell>
                              <TableCell className="py-2 font-mono text-xs font-semibold">
                                <a
                                  href={`https://www.cve.org/CVERecord?id=${cve.cveId}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="hover:underline text-cyan-400 hover:text-cyan-300"
                                  onClick={e => e.stopPropagation()}
                                >
                                  {cve.cveId}
                                </a>
                              </TableCell>
                              <TableCell className="py-2 text-right text-xs font-bold">
                                <span className={cve.cvssScore != null && cve.cvssScore >= 9 ? "text-red-600" : "text-orange-600"}>
                                  {cve.cvssScore?.toFixed(1) ?? "—"}
                                </span>
                              </TableCell>
                              <TableCell className="py-2">
                                <Badge className={`text-[10px] px-1.5 py-0 ${severityColor}`} variant="outline">
                                  {cve.severity ?? "—"}
                                </Badge>
                              </TableCell>
                              <TableCell className="py-2 text-xs max-w-xs">
                                <span className="line-clamp-1">{cve.title ?? "—"}</span>
                              </TableCell>
                              <TableCell className="py-2 text-center text-xs">
                                {cve.exploitPublic ? <span className="text-red-600 font-bold">Evet</span> : <span className="text-muted-foreground">—</span>}
                              </TableCell>
                              <TableCell className="py-2 text-center text-xs">
                                {cve.cisaKev ? <span className="text-purple-600 font-bold">KEV</span> : <span className="text-muted-foreground">—</span>}
                              </TableCell>
                              <TableCell className="py-2 text-center text-xs">
                                {cve.patchAvailable === false ? <span className="text-red-500 font-semibold">Yok</span> : cve.patchAvailable ? <span className="text-green-600">Var</span> : <span className="text-muted-foreground">—</span>}
                              </TableCell>
                              <TableCell className="py-2 text-right text-xs font-semibold">{cve.affectedDomainCount}</TableCell>
                            </TableRow>
                            {isOpen && (
                              <TableRow key={`${cve.cveId}-detail`} className="bg-muted/30">
                                <TableCell colSpan={9} className="py-0 px-4 pb-3">
                                  <div className="pt-2 text-xs space-y-1">
                                    <div className="font-semibold mb-1.5 text-muted-foreground uppercase tracking-wide text-[10px]">
                                      Etkilenen Domainler ({cve.domains.length})
                                    </div>
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1">
                                      {cve.domains.map((d, i) => (
                                        <div key={i} className="flex items-center justify-between gap-2 rounded border px-2 py-1 bg-background">
                                          <span className="font-mono text-[11px] truncate max-w-[160px]">{d.domain}</span>
                                          <div className="flex items-center gap-1.5 shrink-0 flex-wrap justify-end">
                                            {d.matchedProduct && (
                                              <span className="text-[10px] text-muted-foreground truncate max-w-[120px]">{d.matchedProduct}{d.matchedVersion ? ` ${d.matchedVersion}` : ""}</span>
                                            )}
                                            {d.confidence != null && (
                                              <Badge variant="outline" className="text-[9px] px-1 py-0">{d.confidence}%</Badge>
                                            )}
                                            {d.wafDetected === true ? (
                                              <Badge variant="outline" className="text-[9px] px-1 py-0 text-blue-600 border-blue-400">
                                                WAF{d.wafProvider ? `: ${d.wafProvider}` : ""}
                                              </Badge>
                                            ) : d.wafDetected === false ? (
                                              <Badge variant="outline" className="text-[9px] px-1 py-0 text-slate-400">WAF yok</Badge>
                                            ) : null}
                                            {d.isPatched ? (
                                              <Badge variant="outline" className="text-[9px] px-1 py-0 text-green-600">Yamalı</Badge>
                                            ) : (
                                              <Badge variant="outline" className="text-[9px] px-1 py-0 text-red-600">Açık</Badge>
                                            )}
                                          </div>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                </TableCell>
                              </TableRow>
                            )}
                          </>
                        );
                      })}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ── ISP GRUPLARI TAB ─────────────────────────────────────────── */}
        <TabsContent value="isp-gruplari">
          <IspGroupsView />
        </TabsContent>

        {/* ── PORT RİSKİ TAB ───────────────────────────────────────────── */}
        <TabsContent value="port-riski">
          <div className="space-y-4">
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="text-xs text-muted-foreground">Endeksteki domainlerde Shodan tarafından tespit edilen açık riskli portlar</span>
                  <div className="ml-auto flex items-center gap-2">
                    <button
                      onClick={() => { void portRiskRefetch(); }}
                      disabled={portRiskFetching}
                      className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-input bg-background hover:bg-accent font-medium disabled:opacity-50"
                    >
                      <RefreshCw className={`h-3.5 w-3.5 ${portRiskFetching ? "animate-spin" : ""}`} />
                      {portRiskFetching ? "Yükleniyor..." : "Yenile"}
                    </button>
                  </div>
                </div>
              </CardContent>
            </Card>

            {portRiskLoading ? (
              <div className="py-12 text-center text-sm text-muted-foreground">Yükleniyor...</div>
            ) : !portRisk ? null : (
              <>
                {/* Özet kartlar */}
                <div className="grid grid-cols-3 sm:grid-cols-6 gap-3">
                  {([
                    { key: "mysql", label: "MySQL 3306", color: "text-red-600", desc: "Veritabanı doğrudan internette" },
                    { key: "ftp",   label: "FTP 21",     color: "text-orange-600", desc: "Şifresiz dosya aktarımı" },
                    { key: "rdp",   label: "RDP 3389",   color: "text-red-700", desc: "Uzak masaüstü erişimi" },
                    { key: "vnc",   label: "VNC 5900",   color: "text-orange-700", desc: "Uzak ekran erişimi" },
                    { key: "mongo", label: "MongoDB 27017", color: "text-yellow-700", desc: "NoSQL veritabanı" },
                    { key: "redis", label: "Redis 6379", color: "text-yellow-600", desc: "Cache sunucusu" },
                  ] as const).map(({ key, label, color, desc }) => (
                    <button
                      key={key}
                      onClick={() => setPortRiskFilter(f => f === key ? "all" : key)}
                      className={`text-left rounded-lg border p-3 transition-colors ${portRiskFilter === key ? "bg-primary/10 border-primary/40" : "bg-background hover:bg-accent"}`}
                    >
                      <div className={`text-xl font-bold leading-none ${color}`}>{portRisk.summary[key]}</div>
                      <div className="text-[11px] font-medium mt-0.5">{label}</div>
                      <div className="text-[10px] text-muted-foreground mt-0.5">{desc}</div>
                    </button>
                  ))}
                </div>

                {/* Domain tablosu */}
                <Card>
                  <CardContent className="p-0">
                    {portRisk.domains.filter(d => {
                      if (portRiskFilter === "all") return true;
                      return d[`${portRiskFilter}_open` as keyof PortRiskDomain] === true;
                    }).length === 0 ? (
                      <div className="py-12 text-center text-sm text-muted-foreground">Bu filtreye uygun kayıt yok</div>
                    ) : (
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="text-xs">Domain</TableHead>
                            <TableHead className="text-xs">Puan</TableHead>
                            <TableHead className="text-xs">Sektör</TableHead>
                            <TableHead className="text-xs">Şehir</TableHead>
                            <TableHead className="text-xs">Açık Portlar</TableHead>
                            <TableHead className="text-xs">WAF</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {portRisk.domains
                            .filter(d => {
                              if (portRiskFilter === "all") return true;
                              return d[`${portRiskFilter}_open` as keyof PortRiskDomain] === true;
                            })
                            .map(d => (
                              <TableRow key={d.domain}>
                                <TableCell className="font-mono text-xs py-2">
                                  <a href={`https://${d.domain}`} target="_blank" rel="noopener noreferrer" className="hover:underline text-primary">
                                    {d.domain}
                                  </a>
                                </TableCell>
                                <TableCell className="text-xs py-2">
                                  <span className={d.overall_score < 40 ? "text-red-600 font-bold" : d.overall_score < 60 ? "text-orange-600 font-semibold" : "text-muted-foreground"}>
                                    {d.overall_score}
                                  </span>
                                </TableCell>
                                <TableCell className="text-xs py-2 text-muted-foreground">{d.sector ?? "—"}</TableCell>
                                <TableCell className="text-xs py-2 text-muted-foreground">{d.city ?? "—"}</TableCell>
                                <TableCell className="py-2">
                                  <div className="flex flex-wrap gap-1">
                                    {d.mysql_open && <Badge variant="outline" className="text-[9px] px-1 py-0 text-red-600 border-red-300">MySQL 3306</Badge>}
                                    {d.ftp_open   && <Badge variant="outline" className="text-[9px] px-1 py-0 text-orange-600 border-orange-300">FTP 21</Badge>}
                                    {d.rdp_open   && <Badge variant="outline" className="text-[9px] px-1 py-0 text-red-700 border-red-400">RDP 3389</Badge>}
                                    {d.vnc_open   && <Badge variant="outline" className="text-[9px] px-1 py-0 text-orange-700 border-orange-400">VNC 5900</Badge>}
                                    {d.mongo_open && <Badge variant="outline" className="text-[9px] px-1 py-0 text-yellow-700 border-yellow-400">MongoDB 27017</Badge>}
                                    {d.redis_open && <Badge variant="outline" className="text-[9px] px-1 py-0 text-yellow-600 border-yellow-300">Redis 6379</Badge>}
                                  </div>
                                </TableCell>
                                <TableCell className="py-2">
                                  {d.waf_detected === true ? (
                                    <Badge variant="outline" className="text-[9px] px-1 py-0 text-blue-600 border-blue-400">
                                      WAF{d.waf_provider ? `: ${d.waf_provider}` : ""}
                                    </Badge>
                                  ) : (
                                    <span className="text-[10px] text-muted-foreground">—</span>
                                  )}
                                </TableCell>
                              </TableRow>
                            ))}
                        </TableBody>
                      </Table>
                    )}
                  </CardContent>
                </Card>
              </>
            )}
          </div>
        </TabsContent>

        {/* ── ZENGİNLEŞTİRME TAB ──────────────────────────────────────────── */}
        <TabsContent value="zenginlestirme">
          <div className="space-y-4">
            {/* Üst araç çubuğu */}
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="text-xs text-muted-foreground">Web scraper ile sektör/şehir/iletişim zenginleştirme durumu</span>
                  <div className="ml-auto flex items-center gap-2">
                    {(enrichmentDash?.normalize_issues?.length ?? 0) > 0 && (
                      <Button
                        size="sm" variant="outline"
                        className="text-xs border-amber-600/50 text-amber-500 hover:bg-amber-900/20"
                        onClick={() => void handleNormalizeCities()}
                        disabled={isNormalizingCities}
                      >
                        {isNormalizingCities ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <AlertTriangle className="h-3 w-3 mr-1" />}
                        {isNormalizingCities ? "Düzeltiliyor..." : `${enrichmentDash!.normalize_issues.length} şehir adı düzelt`}
                      </Button>
                    )}
                    <button
                      onClick={() => { void enrichmentRefetch(); }}
                      disabled={enrichmentFetching}
                      className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-input bg-background hover:bg-accent font-medium disabled:opacity-50"
                    >
                      <RefreshCw className={`h-3.5 w-3.5 ${enrichmentFetching ? "animate-spin" : ""}`} />
                      {enrichmentFetching ? "Yükleniyor..." : "Yenile"}
                    </button>
                  </div>
                </div>
              </CardContent>
            </Card>

            {enrichmentLoading ? (
              <div className="py-12 text-center text-sm text-muted-foreground">Yükleniyor...</div>
            ) : !enrichmentDash ? null : (
              <>
                {/* İlerleme kartları */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {[
                    { label: "Toplam Domain", value: enrichmentDash.progress.total.toLocaleString("tr"), sub: `${(enrichmentDash.progress.alive_total ?? 0).toLocaleString("tr")} canlı`, color: "text-slate-300" },
                    { label: "Sektör Dolu", value: enrichmentDash.progress.sector_filled.toLocaleString("tr"), sub: `%${Math.round(enrichmentDash.progress.sector_filled / enrichmentDash.progress.total * 100)}`, color: "text-emerald-400" },
                    { label: "Şehir Dolu", value: enrichmentDash.progress.city_filled.toLocaleString("tr"), sub: `%${Math.round(enrichmentDash.progress.city_filled / enrichmentDash.progress.total * 100)}`, color: "text-blue-400" },
                    { label: "Her İkisi Dolu", value: enrichmentDash.progress.both_filled.toLocaleString("tr"), sub: `%${Math.round(enrichmentDash.progress.both_filled / enrichmentDash.progress.total * 100)}`, color: "text-cyan-400" },
                  ].map(c => (
                    <Card key={c.label}>
                      <CardContent className="pt-4 pb-3">
                        <div className={`text-2xl font-bold leading-none ${c.color}`}>{c.value}</div>
                        <div className="text-xs font-medium mt-1">{c.label}</div>
                        <div className="text-[11px] text-muted-foreground mt-0.5">{c.sub}</div>
                      </CardContent>
                    </Card>
                  ))}
                </div>

                {/* Web Scraper metrikleri */}
                <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider px-0.5">Web Scraper</div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {(() => {
                    const alive = enrichmentDash.progress.alive_total || 1;
                    return [
                      { label: "Canlı Domain", value: (enrichmentDash.progress.alive_total ?? 0).toLocaleString("tr"), sub: `${Math.round((enrichmentDash.progress.alive_total ?? 0) / enrichmentDash.progress.total * 100)}% is_alive=true`, color: "text-slate-300" },
                      { label: "Scraped", value: (enrichmentDash.progress.web_scrape_done ?? 0).toLocaleString("tr"), sub: `${Math.round((enrichmentDash.progress.web_scrape_done ?? 0) / alive * 100)}% tamamlandı`, color: "text-emerald-400" },
                      { label: "Bekleyen (Canlı)", value: (enrichmentDash.progress.scrape_pending ?? 0).toLocaleString("tr"), sub: "is_alive=TRUE, scrape yok/failed", color: "text-yellow-400" },
                      { label: "No Data", value: (enrichmentDash.progress.web_scrape_no_data ?? 0).toLocaleString("tr"), sub: "site cevap verdi, veri yok", color: "text-slate-500" },
                    ];
                  })().map(c => (
                    <Card key={c.label}>
                      <CardContent className="pt-4 pb-3">
                        <div className={`text-2xl font-bold leading-none ${c.color}`}>{c.value}</div>
                        <div className="text-xs font-medium mt-1">{c.label}</div>
                        <div className="text-[11px] text-muted-foreground mt-0.5">{c.sub}</div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {[
                    { label: "E-posta Dolu", value: (enrichmentDash.progress.email_filled ?? 0).toLocaleString("tr"), sub: `${Math.round((enrichmentDash.progress.email_filled ?? 0) / (enrichmentDash.progress.alive_total || 1) * 100)}% canlı kapsama`, color: "text-cyan-400" },
                    { label: "Telefon Dolu", value: (enrichmentDash.progress.phone_filled ?? 0).toLocaleString("tr"), sub: `${Math.round((enrichmentDash.progress.phone_filled ?? 0) / (enrichmentDash.progress.alive_total || 1) * 100)}% canlı kapsama`, color: "text-violet-400" },
                  ].map(c => (
                    <Card key={c.label}>
                      <CardContent className="pt-4 pb-3">
                        <div className={`text-2xl font-bold leading-none ${c.color}`}>{c.value}</div>
                        <div className="text-xs font-medium mt-1">{c.label}</div>
                        <div className="text-[11px] text-muted-foreground mt-0.5">{c.sub}</div>
                      </CardContent>
                    </Card>
                  ))}
                </div>

                {/* Enrichment status dağılımı */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {[
                    { label: "Enriched", value: enrichmentDash.progress.enriched, icon: <CheckCircle2 className="h-4 w-4 text-emerald-400" /> },
                    { label: "Pending", value: enrichmentDash.progress.pending, icon: <Clock className="h-4 w-4 text-yellow-400" /> },
                    { label: "No Match", value: enrichmentDash.progress.no_match, icon: <XCircle className="h-4 w-4 text-slate-500" /> },
                    { label: "Failed", value: enrichmentDash.progress.failed, icon: <XCircle className="h-4 w-4 text-red-500" /> },
                  ].map(c => (
                    <Card key={c.label}>
                      <CardContent className="pt-4 pb-3 flex items-center gap-3">
                        {c.icon}
                        <div>
                          <div className="text-xl font-bold leading-none">{c.value.toLocaleString("tr")}</div>
                          <div className="text-[11px] text-muted-foreground mt-0.5">{c.label}</div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>

                {/* Son cron zamanları */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <Card>
                    <CardHeader className="pb-1 pt-4 px-4">
                      <CardTitle className="text-sm">Son Web Scrape Çalışması</CardTitle>
                    </CardHeader>
                    <CardContent className="px-4 pb-4">
                      <div className="text-sm font-mono text-slate-300">
                        {enrichmentDash.progress.last_web_scrape_run
                          ? new Date(enrichmentDash.progress.last_web_scrape_run).toLocaleString("tr-TR", { timeZone: "Europe/Istanbul" })
                          : "—"}
                      </div>
                      <div className="text-xs text-muted-foreground mt-1">Her gece 02:30 İstanbul • web scraper ile sektör/şehir/iletişim</div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader className="pb-1 pt-4 px-4">
                      <CardTitle className="text-sm">Son Sektör Enrichment</CardTitle>
                    </CardHeader>
                    <CardContent className="px-4 pb-4">
                      <div className="text-sm font-mono text-slate-300">
                        {enrichmentDash.progress.last_sector_run
                          ? new Date(enrichmentDash.progress.last_sector_run).toLocaleString("tr-TR", { timeZone: "Europe/Istanbul" })
                          : "—"}
                      </div>
                      <div className="text-xs text-muted-foreground mt-1">Her 6 saatte bir • keyword eşleştirme</div>
                    </CardContent>
                  </Card>
                </div>

                {/* Normalize sorunları */}
                {enrichmentDash.normalize_issues.length > 0 && (
                  <Card className="border-amber-600/40 bg-amber-950/20">
                    <CardHeader className="pb-2 pt-4 px-4">
                      <CardTitle className="text-sm text-amber-400 flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4" />
                        Normalize Edilmemiş Şehir Adları ({enrichmentDash.normalize_issues.reduce((s, r) => s + r.count, 0)} kayıt)
                      </CardTitle>
                      <CardDescription className="text-xs">
                        Bu değerler "Istanbul", "Izmir" gibi ASCII varyantlar — düzelt butonu ile canonical forma çevrilir.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="px-4 pb-4">
                      <div className="flex flex-wrap gap-2">
                        {enrichmentDash.normalize_issues.slice(0, 20).map(r => (
                          <Badge key={r.city} variant="outline" className="border-amber-600/40 text-amber-300 text-xs">
                            {r.city} ({r.count})
                          </Badge>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                )}

                {/* Sektör dağılımı */}
                <Card>
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Sektör Dağılımı</CardTitle>
                    <CardDescription className="text-xs">{enrichmentDash.sector_dist.reduce((s, r) => s + r.count, 0).toLocaleString("tr")} kayıt etiketli</CardDescription>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    {enrichmentDash.sector_dist.length === 0 ? (
                      <div className="text-xs text-muted-foreground py-4 text-center">Henüz sektör verisi yok</div>
                    ) : (
                      <ResponsiveContainer width="100%" height={260}>
                        <BarChart data={enrichmentDash.sector_dist.slice(0, 15)} layout="vertical" margin={{ left: 10, right: 20, top: 0, bottom: 0 }}>
                          <XAxis type="number" tick={{ fontSize: 10 }} />
                          <YAxis type="category" dataKey="sector" width={140} tick={{ fontSize: 10 }} />
                          <Tooltip formatter={(v: number) => v.toLocaleString("tr")} />
                          <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                            {enrichmentDash.sector_dist.slice(0, 15).map((_, i) => (
                              <Cell key={i} fill={`hsl(${200 + i * 12}, 70%, 55%)`} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>

                {/* Şehir dağılımı */}
                <Card>
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Şehir Dağılımı</CardTitle>
                    <CardDescription className="text-xs">{enrichmentDash.city_dist.reduce((s, r) => s + r.count, 0).toLocaleString("tr")} kayıt etiketli</CardDescription>
                  </CardHeader>
                  <CardContent className="px-4 pb-4">
                    {enrichmentDash.city_dist.length === 0 ? (
                      <div className="text-xs text-muted-foreground py-4 text-center">Henüz şehir verisi yok</div>
                    ) : (
                      <ResponsiveContainer width="100%" height={220}>
                        <BarChart data={enrichmentDash.city_dist.slice(0, 15)} margin={{ left: 10, right: 20, top: 0, bottom: 0 }}>
                          <XAxis dataKey="city" tick={{ fontSize: 10 }} interval={0} angle={-30} textAnchor="end" height={50} />
                          <YAxis tick={{ fontSize: 10 }} />
                          <Tooltip formatter={(v: number) => v.toLocaleString("tr")} />
                          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                            {enrichmentDash.city_dist.slice(0, 15).map((_, i) => (
                              <Cell key={i} fill={`hsl(${160 + i * 15}, 60%, 50%)`} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>

                {/* Cron geçmişi */}
                <Card>
                  <CardHeader className="pb-2 pt-4 px-4">
                    <CardTitle className="text-sm">Enrichment Cron Geçmişi</CardTitle>
                  </CardHeader>
                  <CardContent className="p-0">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="text-xs pl-4">Cron</TableHead>
                          <TableHead className="text-xs">Durum</TableHead>
                          <TableHead className="text-xs">Başlangıç</TableHead>
                          <TableHead className="text-xs">Süre</TableHead>
                          <TableHead className="text-xs">İşlenen</TableHead>
                          <TableHead className="text-xs pr-4">Hata</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {enrichmentDash.cron_history.map((r, i) => (
                          <TableRow key={i}>
                            <TableCell className="font-mono text-xs py-2 pl-4">{r.job_name}</TableCell>
                            <TableCell className="text-xs py-2">
                              <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${
                                r.status === "ok" ? "border-emerald-600/50 text-emerald-400" :
                                r.status === "error" ? "border-red-600/50 text-red-400" :
                                "border-yellow-600/50 text-yellow-400"
                              }`}>
                                {r.status}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-xs py-2 text-muted-foreground">
                              {new Date(r.started_at).toLocaleString("tr-TR", { timeZone: "Europe/Istanbul", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}
                            </TableCell>
                            <TableCell className="text-xs py-2 text-muted-foreground">
                              {r.duration_ms ? `${Math.round(r.duration_ms / 1000)} sn` : "—"}
                            </TableCell>
                            <TableCell className="text-xs py-2">{r.processed_count ?? "—"}</TableCell>
                            <TableCell className="text-xs py-2 pr-4 max-w-[200px] truncate text-red-400" title={r.error_message ?? ""}>
                              {r.error_message ? r.error_message.slice(0, 60) + (r.error_message.length > 60 ? "…" : "") : "—"}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              </>
            )}
          </div>
        </TabsContent>

        {/* ── BIST ANALİZİ TAB ─────────────────────────────────────────────── */}
        <TabsContent value="bist-analizi">
          <div className="space-y-4">
            {/* Araç çubuğu */}
            <Card>
              <CardContent className="pt-4 pb-3">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="text-xs text-muted-foreground">
                    Halka açık BIST şirketlerinin siber risk profili (is_public_company = true satırları)
                  </span>
                  <div className="ml-auto flex items-center gap-2">
                    {bistAnalysis && (
                      <span className="text-xs text-muted-foreground">
                        {new Date(bistAnalysis.generated_at).toLocaleString("tr-TR")} tarihli
                      </span>
                    )}
                    <button
                      onClick={() => { void bistRefetch(); }}
                      disabled={bistFetching}
                      className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-input bg-background hover:bg-accent font-medium disabled:opacity-50"
                    >
                      <RefreshCw className={`h-3.5 w-3.5 ${bistFetching ? "animate-spin" : ""}`} />
                      {bistFetching ? "Yükleniyor..." : "Yenile"}
                    </button>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* BIST Etiketleme Aracı */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">BIST Etiketleme</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-xs text-muted-foreground">
                  Mevcut domain kayıtlarını BIST verileriyle etiketler — yeni kayıt eklemez, sadece var olanları günceller.
                  Aynı Excel dosyasını buradan yükleyerek ticker/endeks bilgilerini otomatik eşleştirebilirsiniz.
                </p>

                {/* Excel Upload */}
                <div
                  className="border-2 border-dashed border-input rounded-lg p-4 text-center cursor-pointer hover:border-primary/50 hover:bg-muted/30 transition-colors"
                  onClick={() => document.getElementById("bist-retag-file")?.click()}
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={async (e) => {
                    e.preventDefault();
                    const file = e.dataTransfer.files[0];
                    if (!file) return;
                    setBistRetagLoading(true);
                    setBistRetagResult(null);
                    try {
                      const XLSX = await import("xlsx");
                      const buf = await file.arrayBuffer();
                      const wb = XLSX.read(buf, { type: "array" });
                      const ws = wb.Sheets[wb.SheetNames[0]];
                      const rawRows = XLSX.utils.sheet_to_json<Record<string, string>>(ws, { defval: "" });
                      const norm = (s: string) => s.toLowerCase()
                        .replace(/ş/g, "s").replace(/ç/g, "c").replace(/ğ/g, "g")
                        .replace(/ü/g, "u").replace(/ö/g, "o").replace(/ı/g, "i")
                        .replace(/[^a-z0-9]/g, "");
                      const COL: Record<string, "domain"|"ticker"|"bistIndexes"|"bistMarket"> = {
                        "domain":"domain","websitesi":"domain","website":"domain","webadresi":"domain",
                        "internetadresi":"domain","webadres":"domain","url":"domain","site":"domain","link":"domain",
                        "ticker":"ticker","bistkodu":"ticker","borsakodu":"ticker","hissekodu":"ticker",
                        "sembol":"ticker","bistsembol":"ticker","hissesembol":"ticker","sirketkodu":"ticker",
                        "menkulsembol":"ticker","symbol":"ticker","code":"ticker",
                        "endeks":"bistIndexes","endeksler":"bistIndexes","bistendeks":"bistIndexes",
                        "indexes":"bistIndexes","endeksbilgisi":"bistIndexes",
                        "pazar":"bistMarket","market":"bistMarket","borsapazari":"bistMarket","borsa":"bistMarket",
                      };
                      const keys = rawRows.length > 0 ? Object.keys(rawRows[0]) : [];
                      const hmap: Record<string, "domain"|"ticker"|"bistIndexes"|"bistMarket"> = {};
                      for (const k of keys) { const n = norm(k); if (COL[n]) hmap[k] = COL[n]; }
                      const hasDomain = Object.values(hmap).includes("domain");
                      const get = (row: Record<string,string>, field: string) => {
                        const key = Object.entries(hmap).find(([,v]) => v === field)?.[0];
                        return key ? String(row[key] ?? "").trim() : "";
                      };
                      const normDomain = (d: string) =>
                        d.replace(/^https?:\/\//,"").replace(/^www\./,"").replace(/\/.*/,"").trim().toLowerCase();
                      const rows: {domain:string;ticker:string;bistIndexes:string;bistMarket:string}[] = [];
                      if (hasDomain) {
                        for (const row of rawRows) {
                          const d = normDomain(get(row,"domain"));
                          if (d.length < 4) continue;
                          rows.push({ domain: d, ticker: get(row,"ticker"), bistIndexes: get(row,"bistIndexes"), bistMarket: get(row,"bistMarket") });
                        }
                      }
                      if (rows.length === 0) {
                        toast({ description: `Domain kolonu bulunamadı. Desteklenen isimler: domain, website, web sitesi, url, site, link`, variant: "destructive" });
                        return;
                      }
                      const r = await fetch(`${BASE}/lead-discovery/bist-retag`, {
                        method: "POST", headers: { "Content-Type": "application/json" },
                        credentials: "include", body: JSON.stringify({ rows }),
                      });
                      const data = await r.json() as { updated: number; notFound: string[] };
                      setBistRetagResult(data);
                      if (data.updated > 0) void bistRefetch();
                    } catch (err) {
                      toast({ description: "Excel okunamadı", variant: "destructive" });
                    } finally {
                      setBistRetagLoading(false);
                    }
                  }}
                >
                  <input
                    id="bist-retag-file"
                    type="file"
                    accept=".xlsx,.xls,.csv"
                    className="hidden"
                    onChange={async (e) => {
                      const file = e.target.files?.[0];
                      if (!file) return;
                      e.target.value = "";
                      setBistRetagLoading(true);
                      setBistRetagResult(null);
                      try {
                        const XLSX = await import("xlsx");
                        const buf = await file.arrayBuffer();
                        const wb = XLSX.read(buf, { type: "array" });
                        const ws = wb.Sheets[wb.SheetNames[0]];
                        const rawRows = XLSX.utils.sheet_to_json<Record<string, string>>(ws, { defval: "" });
                        const norm = (s: string) => s.toLowerCase()
                          .replace(/ş/g, "s").replace(/ç/g, "c").replace(/ğ/g, "g")
                          .replace(/ü/g, "u").replace(/ö/g, "o").replace(/ı/g, "i")
                          .replace(/[^a-z0-9]/g, "");
                        const COL: Record<string, "domain"|"ticker"|"bistIndexes"|"bistMarket"> = {
                          "domain":"domain","websitesi":"domain","website":"domain","webadresi":"domain",
                          "internetadresi":"domain","webadres":"domain","url":"domain","site":"domain","link":"domain",
                          "ticker":"ticker","bistkodu":"ticker","borsakodu":"ticker","hissekodu":"ticker",
                          "sembol":"ticker","bistsembol":"ticker","hissesembol":"ticker","sirketkodu":"ticker",
                          "menkulsembol":"ticker","symbol":"ticker","code":"ticker",
                          "endeks":"bistIndexes","endeksler":"bistIndexes","bistendeks":"bistIndexes",
                          "indexes":"bistIndexes","endeksbilgisi":"bistIndexes",
                          "pazar":"bistMarket","market":"bistMarket","borsapazari":"bistMarket","borsa":"bistMarket",
                        };
                        const keys = rawRows.length > 0 ? Object.keys(rawRows[0]) : [];
                        const hmap: Record<string, "domain"|"ticker"|"bistIndexes"|"bistMarket"> = {};
                        for (const k of keys) { const n = norm(k); if (COL[n]) hmap[k] = COL[n]; }
                        const hasDomain = Object.values(hmap).includes("domain");
                        const get = (row: Record<string,string>, field: string) => {
                          const key = Object.entries(hmap).find(([,v]) => v === field)?.[0];
                          return key ? String(row[key] ?? "").trim() : "";
                        };
                        const normDomain = (d: string) =>
                          d.replace(/^https?:\/\//,"").replace(/^www\./,"").replace(/\/.*/,"").trim().toLowerCase();
                        const rows: {domain:string;ticker:string;bistIndexes:string;bistMarket:string}[] = [];
                        if (hasDomain) {
                          for (const row of rawRows) {
                            const d = normDomain(get(row,"domain"));
                            if (d.length < 4) continue;
                            rows.push({ domain: d, ticker: get(row,"ticker"), bistIndexes: get(row,"bistIndexes"), bistMarket: get(row,"bistMarket") });
                          }
                        }
                        if (rows.length === 0) {
                          toast({ description: `Domain kolonu bulunamadı. Desteklenen isimler: domain, website, web sitesi, url, site, link`, variant: "destructive" });
                          return;
                        }
                        const r = await fetch(`${BASE}/lead-discovery/bist-retag`, {
                          method: "POST", headers: { "Content-Type": "application/json" },
                          credentials: "include", body: JSON.stringify({ rows }),
                        });
                        const data = await r.json() as { updated: number; notFound: string[] };
                        setBistRetagResult(data);
                        if (data.updated > 0) void bistRefetch();
                      } catch {
                        toast({ description: "Excel okunamadı", variant: "destructive" });
                      } finally {
                        setBistRetagLoading(false);
                      }
                    }}
                  />
                  {bistRetagLoading ? (
                    <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground py-2">
                      <Loader2 className="h-4 w-4 animate-spin" /> Etiketleniyor...
                    </div>
                  ) : (
                    <div className="text-sm text-muted-foreground py-2">
                      <Upload className="h-5 w-5 mx-auto mb-1 text-muted-foreground/60" />
                      BIST Excel dosyanızı buraya sürükleyin veya tıklayın
                      <div className="text-xs mt-1 text-muted-foreground/60">
                        Domain kolonu: <span className="font-mono">domain / website / web sitesi / url</span>
                        &nbsp;·&nbsp; Ticker: <span className="font-mono">ticker / hisse kodu / sembol / borsa kodu</span>
                      </div>
                    </div>
                  )}
                </div>

                {bistRetagResult && (
                  <div className={`text-sm rounded-md px-3 py-2 ${bistRetagResult.updated > 0 ? "bg-green-950/40 border border-green-800/40 text-green-400" : "bg-slate-800 text-muted-foreground"}`}>
                    <span className="font-medium">{bistRetagResult.updated} kayıt güncellendi</span>
                    {bistRetagResult.notFound.length > 0 && (
                      <span className="text-muted-foreground ml-2 text-xs">
                        · {bistRetagResult.notFound.length} domain sistemde bulunamadı (önce Lead Import ile ekleyin)
                      </span>
                    )}
                  </div>
                )}

                {/* CSV manuel giriş — alternatif */}
                <details className="text-xs text-muted-foreground">
                  <summary className="cursor-pointer hover:text-foreground">Manuel CSV girişi (alternatif)</summary>
                  <div className="mt-2 space-y-2">
                    <p>Her satır: <code className="bg-muted px-1 rounded">domain,ticker,bistEndeks,bistPazar</code></p>
                    <textarea
                      value={bistRetagInput}
                      onChange={(e) => setBistRetagInput(e.target.value)}
                      placeholder={"akbank.com,AKBNK,BIST 30,Yıldız\ngaranti.com.tr,GARAN,BIST 30,Yıldız"}
                      rows={5}
                      className="w-full font-mono bg-muted border border-input rounded-md p-2 resize-y focus:outline-none"
                    />
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={bistRetagLoading || !bistRetagInput.trim()}
                      onClick={async () => {
                        setBistRetagLoading(true);
                        setBistRetagResult(null);
                        try {
                          const lines = bistRetagInput.trim().split("\n").filter(Boolean);
                          const rows = lines.map(line => {
                            const parts = line.split(",").map(s => s.trim());
                            return { domain: parts[0] ?? "", ticker: parts[1] ?? "", bistIndexes: parts[2] ?? "", bistMarket: parts[3] ?? "" };
                          }).filter(r => r.domain);
                          const r = await fetch(`${BASE}/lead-discovery/bist-retag`, {
                            method: "POST", headers: { "Content-Type": "application/json" },
                            credentials: "include", body: JSON.stringify({ rows }),
                          });
                          const data = await r.json() as { updated: number; notFound: string[] };
                          setBistRetagResult(data);
                          if (data.updated > 0) void bistRefetch();
                        } catch {
                          toast({ description: "BIST etiketleme hatası", variant: "destructive" });
                        } finally {
                          setBistRetagLoading(false);
                        }
                      }}
                    >
                      {bistRetagLoading ? "Etiketleniyor..." : "Etiketle"}
                    </Button>
                  </div>
                </details>
              </CardContent>
            </Card>

            {bistLoading ? (
              <div className="flex items-center justify-center py-16 text-muted-foreground text-sm gap-2">
                <Loader2 className="h-5 w-5 animate-spin" /> BIST analizi yükleniyor...
              </div>
            ) : !bistAnalysis ? (
              <div className="text-center py-16 text-muted-foreground text-sm">Veri alınamadı.</div>
            ) : (
              <>
                {/* Özet kartları */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {[
                    { label: "Toplam BIST Şirketi", value: bistAnalysis.summary.total_bist_companies, sub: null, drill: null as null | "all" },
                    { label: "Domain Bulunan", value: bistAnalysis.summary.with_domain, sub: `%${bistAnalysis.summary.with_domain_pct}`, drill: null },
                    { label: "CVE Tespit Edilen", value: bistAnalysis.summary.with_cve, sub: `%${bistAnalysis.summary.with_cve_pct}`, drill: null },
                    { label: "Kritik CVE Bulunan", value: bistAnalysis.summary.with_critical_cve, sub: null, drill: "all" as const },
                  ].map(card => (
                    <Card
                      key={card.label}
                      className={card.drill ? "cursor-pointer hover:border-primary/50 transition-colors" : ""}
                      onClick={() => card.drill ? setBistDrillFilter(card.drill) : undefined}
                    >
                      <CardContent className="pt-4 pb-3">
                        <div className="text-xs text-muted-foreground mb-1">{card.label}</div>
                        <div className={`text-2xl font-bold ${card.drill && card.value > 0 ? "text-destructive" : ""}`}>{card.value}</div>
                        {card.sub && <div className="text-xs text-muted-foreground mt-0.5">{card.sub} oranında</div>}
                        {card.drill && card.value > 0 && <div className="text-[10px] text-primary mt-1">Detay için tıkla</div>}
                      </CardContent>
                    </Card>
                  ))}
                </div>

                {/* Endeks özeti */}
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">Endeks Bazlı Risk Özeti</CardTitle>
                  </CardHeader>
                  <CardContent className="p-0">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Endeks</TableHead>
                          <TableHead className="text-right">Şirket</TableHead>
                          <TableHead className="text-right">CVE Tespit</TableHead>
                          <TableHead className="text-right">Kritik CVE</TableHead>
                          <TableHead className="text-right">Ort. Skor</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {(["bist30", "bist100", "bist500"] as const).map(key => {
                          const row = bistAnalysis.by_index[key];
                          const label = key === "bist30" ? "BIST 30" : key === "bist100" ? "BIST 100" : "BIST 500";
                          return (
                            <TableRow key={key}>
                              <TableCell className="font-medium">{label}</TableCell>
                              <TableCell className="text-right">{row.total}</TableCell>
                              <TableCell className="text-right">{row.with_cve}</TableCell>
                              <TableCell className="text-right">
                                {row.critical_cve_count > 0 ? (
                                  <button
                                    className="cursor-pointer hover:opacity-80 transition-opacity"
                                    onClick={() => setBistDrillFilter(key)}
                                    title="CVE detaylarını gör"
                                  >
                                    <Badge variant="destructive">{row.critical_cve_count}</Badge>
                                  </button>
                                ) : "—"}
                              </TableCell>
                              <TableCell className="text-right">{row.avg_ai_score > 0 ? row.avg_ai_score.toFixed(1) : "—"}</TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  {/* Sektör risk tablosu */}
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Sektöre Göre Risk Dağılımı</CardTitle>
                      <CardDescription className="text-xs">Düşük ort. skor = yüksek risk</CardDescription>
                    </CardHeader>
                    <CardContent className="p-0">
                      <ScrollArea className="h-72">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Sektör</TableHead>
                              <TableHead className="text-right">Şirket</TableHead>
                              <TableHead className="text-right">Kritik CVE</TableHead>
                              <TableHead>Risk</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {bistAnalysis.by_sector.map(s => (
                              <TableRow key={s.sector}>
                                <TableCell className="text-xs">{s.sector}</TableCell>
                                <TableCell className="text-right text-xs">{s.total}</TableCell>
                                <TableCell className="text-right text-xs">{s.critical_cve_count > 0 ? s.critical_cve_count : "—"}</TableCell>
                                <TableCell>
                                  <Badge className={s.risk_level === "Yüksek" ? "bg-red-600/20 text-red-400 border-red-600/30" : s.risk_level === "Orta" ? "bg-amber-600/20 text-amber-400 border-amber-600/30" : "bg-green-600/20 text-green-400 border-green-600/30"}>
                                    {s.risk_level}
                                  </Badge>
                                </TableCell>
                              </TableRow>
                            ))}
                            {bistAnalysis.by_sector.length === 0 && (
                              <TableRow><TableCell colSpan={4} className="text-center text-xs text-muted-foreground py-8">Henüz veri yok — BIST CSV import edin</TableCell></TableRow>
                            )}
                          </TableBody>
                        </Table>
                      </ScrollArea>
                    </CardContent>
                  </Card>

                  {/* Pazar tablosu */}
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Pazara Göre Dağılım</CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                      <ScrollArea className="h-72">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Pazar</TableHead>
                              <TableHead className="text-right">Şirket</TableHead>
                              <TableHead className="text-right">Kritik CVE</TableHead>
                              <TableHead className="text-right">Ort. Skor</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {bistAnalysis.by_market.map(m => (
                              <TableRow key={m.market}>
                                <TableCell className="text-xs">{m.market}</TableCell>
                                <TableCell className="text-right text-xs">{m.total}</TableCell>
                                <TableCell className="text-right text-xs">{m.with_critical_cve > 0 ? <Badge variant="destructive">{m.with_critical_cve}</Badge> : "—"}</TableCell>
                                <TableCell className="text-right text-xs">{m.avg_ai_score > 0 ? m.avg_ai_score.toFixed(1) : "—"}</TableCell>
                              </TableRow>
                            ))}
                            {bistAnalysis.by_market.length === 0 && (
                              <TableRow><TableCell colSpan={4} className="text-center text-xs text-muted-foreground py-8">Henüz veri yok</TableCell></TableRow>
                            )}
                          </TableBody>
                        </Table>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                </div>

                {/* En riskli şirketler */}
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">En Riskli BIST Şirketleri (ilk 20, düşük skor = yüksek risk)</CardTitle>
                  </CardHeader>
                  <CardContent className="p-0">
                    <ScrollArea className="h-80">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Ticker</TableHead>
                            <TableHead>Şirket</TableHead>
                            <TableHead>Domain</TableHead>
                            <TableHead>Sektör</TableHead>
                            <TableHead>Pazar</TableHead>
                            <TableHead className="text-right">Skor</TableHead>
                            <TableHead className="text-right">Kritik CVE</TableHead>
                            <TableHead className="text-right">Açık Port</TableHead>
                            <TableHead>Risk</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {bistAnalysis.top_risk_companies.map((c, i) => (
                            <TableRow key={i}>
                              <TableCell className="font-mono text-xs font-medium">{c.ticker || "—"}</TableCell>
                              <TableCell className="text-xs">{c.company_name || "—"}</TableCell>
                              <TableCell className="text-xs text-muted-foreground">{c.domain}</TableCell>
                              <TableCell className="text-xs">{c.sector || "—"}</TableCell>
                              <TableCell className="text-xs">{c.market || "—"}</TableCell>
                              <TableCell className="text-right text-xs font-medium">{c.ai_score}</TableCell>
                              <TableCell className="text-right text-xs">
                                {c.critical_cve_count > 0 ? (
                                  <button
                                    className="cursor-pointer hover:opacity-80 transition-opacity"
                                    onClick={() => setBistCveCompany(c)}
                                    title="CVE detaylarını gör"
                                  >
                                    <Badge variant="destructive">{c.critical_cve_count}</Badge>
                                  </button>
                                ) : "—"}
                              </TableCell>
                              <TableCell className="text-right text-xs">{c.open_ports_count > 0 ? c.open_ports_count : "—"}</TableCell>
                              <TableCell>
                                <Badge className={c.risk_level === "Yüksek" ? "bg-red-600/20 text-red-400 border-red-600/30" : c.risk_level === "Orta" ? "bg-amber-600/20 text-amber-400 border-amber-600/30" : "bg-green-600/20 text-green-400 border-green-600/30"}>
                                  {c.risk_level}
                                </Badge>
                              </TableCell>
                            </TableRow>
                          ))}
                          {bistAnalysis.top_risk_companies.length === 0 && (
                            <TableRow><TableCell colSpan={9} className="text-center text-xs text-muted-foreground py-8">Tarama tamamlanmış BIST şirketi bulunamadı</TableCell></TableRow>
                          )}
                        </TableBody>
                      </Table>
                    </ScrollArea>
                  </CardContent>
                </Card>

                {/* LinkedIn içerik kartları */}
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">LinkedIn / Sosyal Medya Içerik Kartları</CardTitle>
                    <CardDescription className="text-xs">Kopyala butonuna basarak metni panoya alın</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                      {bistAnalysis.linkedin_cards.map(card => (
                        <div key={card.id} className="border rounded-lg p-4 space-y-3 bg-muted/20">
                          <div className="text-xs font-semibold text-primary">{card.title}</div>
                          {card.stats.length > 0 && (
                            <div className="space-y-1.5">
                              {card.stats.map((s, i) => (
                                <div key={i} className="flex justify-between text-xs">
                                  <span className="text-muted-foreground">{s.label}</span>
                                  <span className="font-medium">{s.value}</span>
                                </div>
                              ))}
                            </div>
                          )}
                          <button
                            className="w-full text-xs border border-input rounded px-2 py-1 hover:bg-accent"
                            onClick={() => {
                              const text = `${card.title}\n\n${card.stats.map(s => `• ${s.label}: ${s.value}`).join("\n")}\n\n— CyberStep.io`;
                              void navigator.clipboard.writeText(text);
                            }}
                          >
                            Kopyala
                          </button>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </>
            )}
          </div>
        </TabsContent>
      </Tabs>

      {/* BIST CVE Drilldown Dialog — hangi şirketlerde kritik CVE var */}
      {!!bistDrillFilter && bistAnalysis && (
        <Dialog open={!!bistDrillFilter} onOpenChange={() => setBistDrillFilter(null)}>
          <DialogContent className="max-w-2xl w-[95vw] max-h-[85dvh] overflow-hidden flex flex-col">
            <DialogHeader className="shrink-0">
              <DialogTitle className="text-sm">
                {bistDrillFilter === "all" ? "Tüm BIST" : bistDrillFilter === "bist30" ? "BIST 30" : bistDrillFilter === "bist100" ? "BIST 100" : "BIST 500"}
                {" "}— Kritik CVE Bulunan Şirketler
              </DialogTitle>
              <p className="text-xs text-muted-foreground">Her şirkete tıklayarak CVE listesini genişletin</p>
            </DialogHeader>
            <div className="overflow-y-auto flex-1">
              {(() => {
                const companies = (bistAnalysis.critical_cve_companies ?? []).filter(c =>
                  bistDrillFilter === "all" ? true :
                  bistDrillFilter === "bist30" ? c.is_bist30 :
                  bistDrillFilter === "bist100" ? c.is_bist100 : c.is_bist500
                );
                if (companies.length === 0) return (
                  <p className="text-xs text-muted-foreground py-8 text-center">Bu filtre için kritik CVE bulunan şirket yok</p>
                );
                return (
                  <div className="space-y-2">
                    {companies.map((co, idx) => (
                      <BistDrillRow key={idx} co={co} />
                    ))}
                  </div>
                );
              })()}
            </div>
            <div className="shrink-0 pt-2 border-t flex justify-end">
              <button className="text-xs border border-input rounded px-3 py-1.5 hover:bg-accent" onClick={() => setBistDrillFilter(null)}>Kapat</button>
            </div>
          </DialogContent>
        </Dialog>
      )}

      {/* BIST CVE Detay Dialog */}
      {!!bistCveCompany && (
        <Dialog open={!!bistCveCompany} onOpenChange={() => setBistCveCompany(null)}>
          <DialogContent className="max-w-lg w-[95vw] max-h-[80dvh] overflow-hidden flex flex-col">
            <DialogHeader className="shrink-0">
              <DialogTitle className="text-sm flex items-center gap-2">
                <span className="font-mono font-bold">{bistCveCompany.ticker || bistCveCompany.company_name}</span>
                <span className="text-muted-foreground font-normal">— Kritik CVE Listesi</span>
              </DialogTitle>
              <p className="text-xs text-muted-foreground">{bistCveCompany.domain}</p>
            </DialogHeader>
            <div className="overflow-y-auto flex-1 -mx-1 px-1">
              {(!bistCveCompany.cve_list || bistCveCompany.cve_list.length === 0) ? (
                <p className="text-xs text-muted-foreground py-6 text-center">CVE verisi bulunamadı (CVSS ≥ 9.0)</p>
              ) : (
                <div className="space-y-2">
                  {bistCveCompany.cve_list.map(cve => (
                    <div key={cve.cveId} className="border rounded-lg p-3 bg-muted/20 space-y-1.5">
                      <div className="flex items-start justify-between gap-2">
                        <a
                          href={`https://www.cve.org/CVERecord?id=${cve.cveId}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-mono text-xs font-bold text-cyan-400 hover:underline shrink-0"
                        >
                          {cve.cveId}
                        </a>
                        <span className="text-xs font-bold text-red-400 shrink-0">CVSS {cve.cvssScore?.toFixed(1)}</span>
                      </div>
                      {cve.service && (
                        <div className="text-[10px] text-muted-foreground">Servis: <span className="text-foreground/70">{cve.service}</span></div>
                      )}
                      {cve.description && (
                        <p className="text-xs text-muted-foreground line-clamp-3">{cve.description}</p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="shrink-0 pt-2 border-t flex justify-end">
              <button
                className="text-xs border border-input rounded px-3 py-1.5 hover:bg-accent"
                onClick={() => setBistCveCompany(null)}
              >
                Kapat
              </button>
            </div>
          </DialogContent>
        </Dialog>
      )}

      {/* Lead Detail Dialog */}
      {!!detailCandidate && (
        <Dialog open={!!detailCandidate} onOpenChange={() => { setDetailCandidate(null); setFingerprintResult(null); setDetailEditOpen(false); }}>
          <DialogContent className="max-w-xl w-[95vw] max-h-[90dvh] overflow-hidden flex flex-col p-0">
            <DialogHeader className="px-4 pt-4 pb-2 shrink-0 border-b">
              <DialogTitle className="font-mono text-base flex items-center gap-2">
                {detailCandidate.domain}
                <a
                  href={`https://${detailCandidate.domain}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-xs font-sans font-normal text-blue-600 hover:underline"
                  onClick={e => e.stopPropagation()}
                >
                  Siteyi Aç ↗
                </a>
                <button
                  className={`ml-auto text-xs px-2 py-0.5 rounded border transition-colors font-sans font-normal ${detailEditOpen ? "bg-primary text-primary-foreground border-primary" : "border-input hover:bg-accent"}`}
                  onClick={() => {
                    if (!detailEditOpen) {
                      setDetailEditFields({
                        companyName:    detailCandidate.companyName    ?? "",
                        sector:         detailCandidate.sector         ?? "",
                        subSector:      detailCandidate.subSector      ?? "",
                        city:           detailCandidate.city           ?? "",
                        ticker:         detailCandidate.ticker         ?? "",
                        bistIndexes:    detailCandidate.bistIndexes    ?? "",
                        bistMarket:     detailCandidate.bistMarket     ?? "",
                        isPublicCompany: detailCandidate.isPublicCompany ?? false,
                        sourceList:     detailCandidate.sourceList     ?? "",
                        tier:           detailCandidate.tier           ?? "",
                        notes:          detailCandidate.notes          ?? "",
                      });
                    }
                    setDetailEditOpen(v => !v);
                  }}
                >
                  {detailEditOpen ? "Kapat" : "Düzenle"}
                </button>
              </DialogTitle>
            </DialogHeader>
            <div className="space-y-4 text-sm overflow-y-auto flex-1 min-h-0 overscroll-contain px-4 py-4">

              {/* Manuel Düzenleme Formu */}
              {detailEditOpen && (
                <div className="border border-primary/30 rounded-lg p-4 space-y-3 bg-primary/5">
                  <div className="text-xs font-semibold text-primary uppercase tracking-wide">Manuel Güncelleme</div>
                  <div className="grid grid-cols-2 gap-x-3 gap-y-2">
                    {/* Şirket Adı */}
                    <div className="col-span-2">
                      <label className="text-xs text-muted-foreground block mb-0.5">Şirket Adı</label>
                      <input
                        className="w-full h-7 text-xs rounded border border-input bg-background px-2 focus:outline-none focus:ring-1 focus:ring-primary"
                        value={detailEditFields.companyName}
                        onChange={e => setDetailEditFields(f => ({ ...f, companyName: e.target.value }))}
                        placeholder="Şirket adı"
                      />
                    </div>
                    {/* Sektör */}
                    <div>
                      <label className="text-xs text-muted-foreground block mb-0.5">Sektör</label>
                      <select
                        className="w-full h-7 text-xs rounded border border-input bg-background px-2 focus:outline-none focus:ring-1 focus:ring-primary"
                        value={detailEditFields.sector}
                        onChange={e => setDetailEditFields(f => ({ ...f, sector: e.target.value }))}
                      >
                        <option value="">—</option>
                        <option>Finans</option><option>Saglik</option><option>Perakende</option>
                        <option>Imalat</option><option>Bilisim</option><option>Lojistik</option>
                        <option>Insaat</option><option>Egitim</option><option>Turizm</option>
                        <option>Enerji</option><option>Tarım</option><option>Medya</option>
                        <option>Telekomünikasyon</option><option>Otomotiv</option><option>Kamu</option>
                      </select>
                    </div>
                    {/* Alt Sektör */}
                    <div>
                      <label className="text-xs text-muted-foreground block mb-0.5">Alt Sektör</label>
                      <input
                        className="w-full h-7 text-xs rounded border border-input bg-background px-2 focus:outline-none focus:ring-1 focus:ring-primary"
                        value={detailEditFields.subSector}
                        onChange={e => setDetailEditFields(f => ({ ...f, subSector: e.target.value }))}
                        placeholder="Alt sektör"
                      />
                    </div>
                    {/* Şehir */}
                    <div>
                      <label className="text-xs text-muted-foreground block mb-0.5">Şehir</label>
                      <select
                        className="w-full h-7 text-xs rounded border border-input bg-background px-2 focus:outline-none focus:ring-1 focus:ring-primary"
                        value={detailEditFields.city}
                        onChange={e => setDetailEditFields(f => ({ ...f, city: e.target.value }))}
                      >
                        <option value="">—</option>
                        <option>Istanbul</option><option>Ankara</option><option>Izmir</option>
                        <option>Bursa</option><option>Antalya</option><option>Adana</option>
                        <option>Gaziantep</option><option>Konya</option><option>Kocaeli</option>
                        <option>Mersin</option><option>Diyarbakır</option><option>Eskişehir</option>
                        <option>Samsun</option><option>Trabzon</option><option>Manisa</option>
                      </select>
                    </div>
                    {/* Tier */}
                    <div>
                      <label className="text-xs text-muted-foreground block mb-0.5">Tier</label>
                      <select
                        className="w-full h-7 text-xs rounded border border-input bg-background px-2 focus:outline-none focus:ring-1 focus:ring-primary"
                        value={detailEditFields.tier}
                        onChange={e => setDetailEditFields(f => ({ ...f, tier: e.target.value }))}
                      >
                        <option value="">—</option>
                        <option value="tier1">Tier 1 — Qualified</option>
                        <option value="tier2">Tier 2</option>
                        <option value="tier3">Tier 3</option>
                      </select>
                    </div>
                    {/* BIST Bölümü */}
                    <div className="col-span-2 pt-1 border-t border-input">
                      <label className="flex items-center gap-2 text-xs cursor-pointer mb-2">
                        <input
                          type="checkbox"
                          checked={detailEditFields.isPublicCompany}
                          onChange={e => setDetailEditFields(f => ({ ...f, isPublicCompany: e.target.checked }))}
                          className="rounded"
                        />
                        <span className="text-muted-foreground">Halka Açık Şirket (BIST)</span>
                      </label>
                    </div>
                    {/* Ticker */}
                    <div>
                      <label className="text-xs text-muted-foreground block mb-0.5">BIST Ticker</label>
                      <input
                        className="w-full h-7 text-xs rounded border border-input bg-background px-2 font-mono focus:outline-none focus:ring-1 focus:ring-primary"
                        value={detailEditFields.ticker}
                        onChange={e => setDetailEditFields(f => ({ ...f, ticker: e.target.value.toUpperCase() }))}
                        placeholder="Örn: GARAN"
                      />
                    </div>
                    {/* BIST Endeks */}
                    <div>
                      <label className="text-xs text-muted-foreground block mb-0.5">BIST Endeks</label>
                      <select
                        className="w-full h-7 text-xs rounded border border-input bg-background px-2 focus:outline-none focus:ring-1 focus:ring-primary"
                        value={detailEditFields.bistIndexes}
                        onChange={e => setDetailEditFields(f => ({ ...f, bistIndexes: e.target.value }))}
                      >
                        <option value="">—</option>
                        <option value="BIST 30">BIST 30</option>
                        <option value="BIST 100">BIST 100</option>
                        <option value="BIST 500">BIST 500</option>
                        <option value="BIST 30, BIST 100">BIST 30 + 100</option>
                        <option value="BIST 30, BIST 100, BIST 500">BIST 30 + 100 + 500</option>
                      </select>
                    </div>
                    {/* BIST Pazar */}
                    <div>
                      <label className="text-xs text-muted-foreground block mb-0.5">BIST Pazar</label>
                      <select
                        className="w-full h-7 text-xs rounded border border-input bg-background px-2 focus:outline-none focus:ring-1 focus:ring-primary"
                        value={detailEditFields.bistMarket}
                        onChange={e => setDetailEditFields(f => ({ ...f, bistMarket: e.target.value }))}
                      >
                        <option value="">—</option>
                        <option value="Yıldız Pazar">Yıldız Pazar</option>
                        <option value="Ana Pazar">Ana Pazar</option>
                        <option value="Alt Pazar">Alt Pazar</option>
                        <option value="Yakın İzleme Pazarı">Yakın İzleme Pazarı</option>
                      </select>
                    </div>
                    {/* Liste Kaynağı */}
                    <div>
                      <label className="text-xs text-muted-foreground block mb-0.5">Liste Kaynağı</label>
                      <input
                        className="w-full h-7 text-xs rounded border border-input bg-background px-2 focus:outline-none focus:ring-1 focus:ring-primary"
                        value={detailEditFields.sourceList}
                        onChange={e => setDetailEditFields(f => ({ ...f, sourceList: e.target.value }))}
                        placeholder="KAP, Forbes500..."
                      />
                    </div>
                    {/* Notlar */}
                    <div className="col-span-2">
                      <label className="text-xs text-muted-foreground block mb-0.5">Notlar</label>
                      <textarea
                        rows={2}
                        className="w-full text-xs rounded border border-input bg-background px-2 py-1 resize-none focus:outline-none focus:ring-1 focus:ring-primary"
                        value={detailEditFields.notes}
                        onChange={e => setDetailEditFields(f => ({ ...f, notes: e.target.value }))}
                        placeholder="Dahili not..."
                      />
                    </div>
                  </div>
                  <div className="flex items-center gap-2 pt-1">
                    <Button
                      size="sm"
                      disabled={detailEditSaving}
                      onClick={async () => {
                        setDetailEditSaving(true);
                        try {
                          const r = await fetch(`${BASE}/lead-discovery/candidates/${detailCandidate.id}`, {
                            method: "PATCH",
                            headers: { "Content-Type": "application/json" },
                            credentials: "include",
                            body: JSON.stringify(detailEditFields),
                          });
                          if (!r.ok) throw new Error("Güncelleme başarısız");
                          const { candidate } = await r.json() as { candidate: LeadCandidate };
                          setDetailCandidate(candidate);
                          setDetailEditOpen(false);
                          toast({ description: "Kayıt güncellendi" });
                          void qc.invalidateQueries({ queryKey: ["lead-candidates"] });
                        } catch {
                          toast({ description: "Güncelleme sırasında hata oluştu", variant: "destructive" });
                        } finally {
                          setDetailEditSaving(false);
                        }
                      }}
                    >
                      {detailEditSaving ? <><Loader2 className="h-3 w-3 mr-1 animate-spin" />Kaydediliyor...</> : "Kaydet"}
                    </Button>
                    <button
                      className="text-xs text-muted-foreground hover:text-foreground"
                      onClick={() => setDetailEditOpen(false)}
                    >
                      Vazgeç
                    </button>
                  </div>
                </div>
              )}

              {/* Şirket bilgisi */}
              {detailCandidate.companyName && (
                <div>
                  <div className="text-xs text-muted-foreground mb-0.5">Şirket</div>
                  <div className="font-medium">{detailCandidate.companyName}</div>
                </div>
              )}

              {/* Kaynak tespit detayı */}
              {detailCandidate.sourceData && (
                <div className="bg-slate-50 border rounded-md p-3 space-y-2">
                  <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                    {detailCandidate.source === "crtsh" ? "crt.sh Tespit Detayı" : "Shodan Tespit Detayı"}
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    {/* Shodan alanları */}
                    {detailCandidate.sourceData.ip && (
                      <div>
                        <span className="text-muted-foreground">IP Adresi: </span>
                        <span className="font-mono font-medium">{detailCandidate.sourceData.ip}</span>
                      </div>
                    )}
                    {detailCandidate.sourceData.port && (
                      <div>
                        <span className="text-muted-foreground">Açık Port: </span>
                        <span className="font-mono font-medium text-orange-600">{detailCandidate.sourceData.port}</span>
                      </div>
                    )}
                    {detailCandidate.sourceData.product && (
                      <div>
                        <span className="text-muted-foreground">Ürün/Yazılım: </span>
                        <span className="font-medium">{detailCandidate.sourceData.product}</span>
                      </div>
                    )}
                    {detailCandidate.sourceData.org && (
                      <div className="col-span-2">
                        <span className="text-muted-foreground">Organizasyon: </span>
                        <span>{detailCandidate.sourceData.org}</span>
                      </div>
                    )}
                    {detailCandidate.sourceData.httpTitle && (
                      <div className="col-span-2">
                        <span className="text-muted-foreground">HTTP Başlığı: </span>
                        <span className="italic">{detailCandidate.sourceData.httpTitle}</span>
                      </div>
                    )}
                    {detailCandidate.sourceData.shodanQuery && (
                      <div className="col-span-2">
                        <span className="text-muted-foreground">Tetikleyen Shodan Sorgusu: </span>
                        <span className="font-mono text-blue-600">{detailCandidate.sourceData.shodanQuery}</span>
                      </div>
                    )}
                    {/* crt.sh alanları */}
                    {detailCandidate.sourceData.registeredDomain && (
                      <div className="col-span-2">
                        <span className="text-muted-foreground">Kayıtlı Domain: </span>
                        <span className="font-mono font-medium">{detailCandidate.sourceData.registeredDomain}</span>
                      </div>
                    )}
                    {detailCandidate.sourceData.tld && (
                      <div>
                        <span className="text-muted-foreground">TLD: </span>
                        <span className="font-mono">{detailCandidate.sourceData.tld}</span>
                      </div>
                    )}
                    {detailCandidate.sourceData.subdomains && (detailCandidate.sourceData.subdomains as string[]).length > 0 && (
                      <div className="col-span-2">
                        <span className="text-muted-foreground">Alt Domainler: </span>
                        <span className="font-mono text-xs">{(detailCandidate.sourceData.subdomains as string[]).slice(0, 8).join(", ")}</span>
                      </div>
                    )}
                    {detailCandidate.sourceData.issuer && (
                      <div className="col-span-2">
                        <span className="text-muted-foreground">Sertifika Veren: </span>
                        <span>{detailCandidate.sourceData.issuer}</span>
                      </div>
                    )}
                    {detailCandidate.sourceData.notBefore && (
                      <div>
                        <span className="text-muted-foreground">Sertifika Tarihi: </span>
                        <span>{new Date(detailCandidate.sourceData.notBefore as string).toLocaleDateString("tr-TR")}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Web Scraper Verileri */}
              {detailCandidate.webScrapedAt && (
                <div className="border border-slate-700/60 rounded-lg p-3 space-y-2.5 bg-slate-900/40">
                  <div className="flex items-center justify-between">
                    <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                      Web Scraper
                      {detailCandidate.webScrapeStatus === "scraped"
                        ? <span className="ml-1.5 normal-case font-normal text-green-400">Toplandı</span>
                        : detailCandidate.webScrapeStatus === "no_data"
                        ? <span className="ml-1.5 normal-case font-normal text-slate-500">Veri Yok</span>
                        : null}
                    </div>
                    <span className="text-[10px] text-slate-500">
                      {new Date(detailCandidate.webScrapedAt).toLocaleDateString("tr-TR")}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    {/* İletişim */}
                    {(detailCandidate.webScrapeEmail ?? detailCandidate.scrapedPhone ?? detailCandidate.scrapedAddress) && (
                      <>
                        {detailCandidate.webScrapeEmail && (
                          <div className="col-span-2">
                            <span className="text-muted-foreground">E-posta: </span>
                            <a href={`mailto:${detailCandidate.webScrapeEmail}`} className="text-blue-400 hover:underline font-mono">
                              {detailCandidate.webScrapeEmail}
                            </a>
                          </div>
                        )}
                        {detailCandidate.scrapedPhone && (
                          <div>
                            <span className="text-muted-foreground">Telefon: </span>
                            <span className="font-medium">{detailCandidate.scrapedPhone}</span>
                          </div>
                        )}
                        {detailCandidate.scrapedAddress && (
                          <div className="col-span-2">
                            <span className="text-muted-foreground">Adres: </span>
                            <span>{detailCandidate.scrapedAddress}</span>
                          </div>
                        )}
                      </>
                    )}

                    {/* Şirket Profili */}
                    {detailCandidate.companyFoundedYear && (
                      <div>
                        <span className="text-muted-foreground">Kuruluş: </span>
                        <span className="font-medium">{detailCandidate.companyFoundedYear}</span>
                      </div>
                    )}

                    {/* Özellik Rozetleri */}
                    <div className="col-span-2 flex flex-wrap gap-1.5 pt-0.5">
                      {detailCandidate.isB2b && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-900/40 text-blue-300 border border-blue-800/50">B2B</span>
                      )}
                      {detailCandidate.hasEcommerce && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-900/40 text-amber-300 border border-amber-800/50">E-ticaret</span>
                      )}
                      {detailCandidate.hasKvkkPage && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-900/40 text-green-300 border border-green-800/50">KVKK Sayfası</span>
                      )}
                      {detailCandidate.hasCareersPage && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-900/40 text-purple-300 border border-purple-800/50">Kariyer Sayfası</span>
                      )}
                      {detailCandidate.cmsDetected && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700/60 text-slate-300 border border-slate-600/50 uppercase">
                          {detailCandidate.cmsDetected}
                        </span>
                      )}
                    </div>

                    {/* Sosyal Medya */}
                    {(detailCandidate.socialLinkedinUrl ?? detailCandidate.socialInstagramUrl) && (
                      <div className="col-span-2 flex flex-wrap gap-3">
                        {detailCandidate.socialLinkedinUrl && (
                          <a href={detailCandidate.socialLinkedinUrl} target="_blank" rel="noopener noreferrer"
                             className="text-blue-400 hover:underline text-[11px]">
                            LinkedIn ↗
                          </a>
                        )}
                        {detailCandidate.socialInstagramUrl && (
                          <a href={detailCandidate.socialInstagramUrl} target="_blank" rel="noopener noreferrer"
                             className="text-pink-400 hover:underline text-[11px]">
                            Instagram ↗
                          </a>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Subdomain Probe — başlık + tetikle butonu */}
              {candidateDomainScan && (
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                    Alt Alan Adı Keşfi
                    {subdomainSummary && subdomainSummary.summary.total > 0 && (
                      <span className="ml-1.5 normal-case font-normal">({subdomainSummary.summary.total} subdomain)</span>
                    )}
                  </span>
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-6 text-xs px-2"
                    disabled={probeMutation.isPending}
                    onClick={() => probeMutation.mutate()}
                  >
                    {probeMutation.isPending ? (
                      <><Loader2 className="h-3 w-3 mr-1 animate-spin" />Probe...</>
                    ) : (
                      "Probe Et"
                    )}
                  </Button>
                </div>
              )}

              {/* Varlık Sınıflandırması */}
              {subdomainSummary && subdomainSummary.summary.total > 0 && (
                <div className="bg-slate-50 border rounded-md p-3 space-y-2">
                  <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Varlık Sınıflandırması</div>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                    {(["web_app", "api", "redirect", "error_4xx", "error_5xx", "unreachable"] as const).filter((k) => (subdomainSummary.summary as Record<string, number>)[k] > 0).map((k) => (
                      <div key={k} className="flex justify-between">
                        <span className="text-muted-foreground">{CLASSIFICATION_LABELS[k]}:</span>
                        <span className="font-medium">{(subdomainSummary.summary as Record<string, number>)[k]}</span>
                      </div>
                    ))}
                    <div className="col-span-2 border-t pt-1 mt-1 flex justify-between">
                      <span className="text-muted-foreground">Toplam Alt Domain:</span>
                      <span className="font-semibold">{subdomainSummary.summary.total}</span>
                    </div>
                  </div>
                </div>
              )}
              {subdomainSummary?.processing && subdomainSummary.summary.total === 0 && (
                <div className="text-xs text-muted-foreground text-center py-2 border rounded-md bg-slate-50">
                  Alt domain analizi yapılıyor...
                </div>
              )}
              {probeMutation.isSuccess && (probeMutation.data as { subdomainsFound?: number })?.subdomainsFound === 0 && subdomainSummary?.summary.total === 0 && (
                <div className="text-xs text-muted-foreground border rounded-md bg-slate-50 px-3 py-2">
                  Sertifika şeffaflık kayıtlarında bu domain için alt alan adı bulunamadı (crt.sh: 0 kayıt).
                </div>
              )}
              {probeMutation.isError && (
                <div className="text-xs text-red-600 border border-red-200 rounded-md bg-red-50 px-3 py-1.5">
                  Probe sırasında hata oluştu. Tekrar deneyin.
                </div>
              )}

              {/* Öncelikli İnceleme Önerileri */}
              {(subdomainSummary?.topPriority?.length ?? 0) > 0 && (
                <div className="bg-slate-50 border rounded-md p-3 space-y-2">
                  <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Öncelikli Inceleme Önerileri</div>
                  <div className="space-y-2">
                    {subdomainSummary!.topPriority.map((item) => (
                      <div key={item.domain} className="flex items-start gap-2 text-xs">
                        <div className="flex-1 min-w-0">
                          <div className="font-mono font-medium truncate">{item.domain}</div>
                          <div className="text-muted-foreground text-[11px]">{item.priorityReason}</div>
                        </div>
                        <span className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] font-semibold ${item.priorityScore >= 30 ? "bg-red-100 text-red-700" : item.priorityScore >= 20 ? "bg-orange-100 text-orange-700" : "bg-slate-100 text-slate-600"}`}>
                          {item.priorityScore}p
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Risk skoru + CVE breakdown */}
              <div className="flex items-start gap-4 flex-wrap">
                <div>
                  <div className="text-xs text-muted-foreground">Risk Skoru</div>
                  <div className={`text-2xl font-bold ${(detailCandidate.riskScore ?? 0) >= 70 ? "text-red-600" : (detailCandidate.riskScore ?? 0) >= 40 ? "text-orange-500" : "text-gray-500"}`}>
                    {detailCandidate.riskScore ?? "—"}<span className="text-sm font-normal text-muted-foreground">/100</span>
                  </div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground">Kritik Bulgu</div>
                  <div className="text-2xl font-bold text-red-600">{detailCandidate.criticalFindings}</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground">Kaynak</div>
                  <Badge variant="outline">{detailCandidate.source === "crtsh" ? "crt.sh" : "Shodan"}</Badge>
                </div>
                {candidateDomainScan && (() => {
                  const b = getWafBadge(candidateDomainScan.confidenceScore, candidateDomainScan.wafDetected);
                  return (
                    <div>
                      <div className="text-xs text-muted-foreground">Tarama Güveni</div>
                      <span
                        title={b.color === "blue" ? "WAF veya CDN engeli tespit edilmedi — tarama verileri tam olarak alındı. Bu badge güvenlik durumunu değil, tarama kalitesini gösterir." : undefined}
                        className={`px-2 py-0.5 text-xs rounded-full border cursor-default ${b.color === "blue" ? "bg-blue-50 text-blue-700 border-blue-200" : "bg-amber-50 text-amber-800 border-amber-300"}`}
                      >
                        {b.label}
                      </span>
                    </div>
                  );
                })()}
              </div>

              {/* CVE breakdown */}
              {detailCandidate.sourceData?.cveBreakdown && detailCandidate.sourceData.cveBreakdown.total > 0 && (
                <div>
                  <div className="text-xs text-muted-foreground mb-1.5">CVE Dağılımı ({detailCandidate.sourceData.cveBreakdown.total} toplam)</div>
                  <div className="flex flex-wrap gap-2 text-xs">
                    {detailCandidate.sourceData.cveBreakdown.critical > 0 && (
                      <span className="px-2 py-0.5 rounded-full bg-red-100 text-red-700 font-semibold border border-red-200">
                        {detailCandidate.sourceData.cveBreakdown.critical} Kritik
                      </span>
                    )}
                    {detailCandidate.sourceData.cveBreakdown.high > 0 && (
                      <span className="px-2 py-0.5 rounded-full bg-orange-100 text-orange-700 font-semibold border border-orange-200">
                        {detailCandidate.sourceData.cveBreakdown.high} Yüksek
                      </span>
                    )}
                    {detailCandidate.sourceData.cveBreakdown.medium > 0 && (
                      <span className="px-2 py-0.5 rounded-full bg-yellow-100 text-yellow-700 border border-yellow-200">
                        {detailCandidate.sourceData.cveBreakdown.medium} Orta
                      </span>
                    )}
                    {detailCandidate.sourceData.cveBreakdown.informational > 0 && (
                      <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200">
                        {detailCandidate.sourceData.cveBreakdown.informational} Bilgi
                      </span>
                    )}
                    {detailCandidate.sourceData.cveBreakdown.cisaKev > 0 && (
                      <span className="px-2 py-0.5 rounded-full bg-purple-100 text-purple-700 font-semibold border border-purple-200">
                        {detailCandidate.sourceData.cveBreakdown.cisaKev} CISA KEV
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* Bulgular */}
              {(detailCandidate.findingHighlights?.length ?? 0) > 0 && (
                <div>
                  <div className="text-xs text-muted-foreground mb-1.5">Güvenlik Bulguları</div>
                  <div className="space-y-1.5">
                    {(detailCandidate.findingHighlights ?? []).map((h) => {
                      const isCve = h.startsWith("CVE-");
                      const desc = CVE_DESCS[h];
                      return (
                        <div key={h} className="flex items-start gap-2 p-2 rounded bg-red-50 border border-red-100">
                          <span className="text-red-600 mt-0.5">•</span>
                          <div>
                            {isCve ? (
                              <a href={`https://nvd.nist.gov/vuln/detail/${h}`} target="_blank" rel="noopener noreferrer"
                                className="font-mono text-red-700 font-medium hover:underline text-xs">{h}</a>
                            ) : (
                              <span className="font-medium text-red-700 text-xs">{h}</span>
                            )}
                            {desc && <div className="text-xs text-red-600/80 mt-0.5">{desc}</div>}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Tech Stack */}
              {(candidateTechStack?.length ?? 0) > 0 && (() => {
                const portItems = candidateTechStack!.filter(t => t.category === "open_port");
                const otherItems = candidateTechStack!.filter(t => t.category !== "open_port");
                const isHighRisk = (r: string | null) => r === "critical" || r === "high" || r === "Yüksek";
                return (
                  <div className="space-y-2">
                    {portItems.length > 0 && (
                      <div>
                        <div className="text-xs text-muted-foreground mb-1">Açık Portlar</div>
                        <div className="space-y-1">
                          {portItems.sort((a, b) => (isHighRisk(b.securityRisk) ? 1 : 0) - (isHighRisk(a.securityRisk) ? 1 : 0)).map((t, i) => {
                            const resolved = resolvePortNote(t.product, t.securityNote, t.securityRisk);
                            return (
                            <div key={i} className="flex items-center gap-2 text-xs rounded bg-slate-50 border border-slate-200 px-2 py-1">
                              <span className="flex-1 font-mono font-medium truncate">{t.product ?? t.vendor}</span>
                              {resolved.note && <span className="text-muted-foreground text-[10px] truncate max-w-[140px]">{resolved.note}</span>}
                              <span className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                                resolved.risk === "critical" ? "bg-red-100 text-red-700 border border-red-200" :
                                resolved.risk === "high" ? "bg-orange-100 text-orange-700" :
                                resolved.risk === "medium" ? "bg-yellow-100 text-yellow-700" :
                                "bg-slate-100 text-slate-500"
                              }`}>{resolved.risk ?? "low"}</span>
                            </div>
                            );
                          })}
                        </div>
                      </div>
                    )}
                    {otherItems.length > 0 && (
                      <div>
                        <div className="text-xs text-muted-foreground mb-1">Teknoloji Yığını</div>
                        <div className="space-y-1">
                          {[...otherItems]
                            .sort((a, b) => (isHighRisk(b.securityRisk) ? 1 : 0) - (isHighRisk(a.securityRisk) ? 1 : 0))
                            .map((t, i) => (
                              <div key={i} className="flex items-center gap-2 text-xs">
                                <span className="flex-1 font-medium truncate">{(t.vendor && t.vendor !== "none") ? t.vendor : (t.product ?? (SIGNAL_LABELS[t.category] ?? t.category))}</span>
                                <span className="text-muted-foreground text-[10px]">{SIGNAL_LABELS[t.category] ?? t.category.replace(/_/g, " ")}</span>
                                {t.salesSignal && (
                                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                                    t.salesSignal === "fortinet_customer" ? "bg-red-100 text-red-700" :
                                    t.salesSignal === "cms_wordpress" ? "bg-orange-100 text-orange-700" :
                                    t.salesSignal === "cdn_user" ? "bg-blue-100 text-blue-700" :
                                    t.salesSignal === "microsoft_shop" ? "bg-purple-100 text-purple-700" :
                                    "bg-slate-100 text-slate-600"
                                  }`}>{SIGNAL_LABELS[t.salesSignal] ?? t.salesSignal.replace(/_/g, " ")}</span>
                                )}
                                {isHighRisk(t.securityRisk) && (
                                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-50 text-red-600 border border-red-200">risk</span>
                                )}
                              </div>
                            ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Tech Fingerprint Sonuçları */}
              {fingerprintLead.isPending && (
                <div className="bg-cyan-50 border border-cyan-200 rounded-md p-3 text-xs text-cyan-700 animate-pulse">
                  Tech fingerprint taraması çalışıyor...
                </div>
              )}
              {fingerprintResult && (
                <div className="border border-cyan-200 bg-cyan-50/50 rounded-md p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="text-xs font-semibold text-cyan-800 uppercase tracking-wide">Tech Fingerprint Sonuçları</div>
                    <div className="flex gap-3 text-xs">
                      <span className="text-muted-foreground">{fingerprintResult.stackCount} teknoloji</span>
                      {fingerprintResult.maturity && (
                        <span className={`font-semibold ${
                          fingerprintResult.maturity.score >= 70 ? "text-green-700" :
                          fingerprintResult.maturity.score >= 40 ? "text-yellow-700" : "text-red-700"
                        }`}>{fingerprintResult.maturity.level} ({fingerprintResult.maturity.score}/100)</span>
                      )}
                    </div>
                  </div>
                  {fingerprintResult.stack.length === 0 ? (
                    <p className="text-xs text-muted-foreground">Teknoloji tespit edilemedi.</p>
                  ) : (
                    <div className="space-y-1">
                      {[...fingerprintResult.stack]
                        .sort((a, b) => {
                          const hr = (r: string | null) => r === "critical" || r === "high" || r === "Yüksek";
                          return (hr(b.securityRisk) ? 1 : 0) - (hr(a.securityRisk) ? 1 : 0);
                        })
                        .map((t, i) => (
                          <div key={i} className="flex items-center gap-2 text-xs">
                            <span className="flex-1 font-medium truncate">{t.category === "open_port" ? (t.product ?? t.vendor) : ((t.vendor && t.vendor !== "none") ? t.vendor : (t.product ?? (SIGNAL_LABELS[t.category] ?? t.category)))}</span>
                            <span className="text-muted-foreground text-[10px]">{SIGNAL_LABELS[t.category] ?? t.category.replace(/_/g, " ")}</span>
                            {t.salesSignal && (
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                                t.salesSignal === "fortinet_customer" ? "bg-red-100 text-red-700" :
                                t.salesSignal === "cms_wordpress" ? "bg-orange-100 text-orange-700" :
                                t.salesSignal === "cdn_user" ? "bg-blue-100 text-blue-700" :
                                t.salesSignal === "microsoft_shop" ? "bg-purple-100 text-purple-700" :
                                "bg-slate-100 text-slate-600"
                              }`}>{SIGNAL_LABELS[t.salesSignal] ?? t.salesSignal.replace(/_/g, " ")}</span>
                            )}
                            {(t.securityRisk === "critical" || t.securityRisk === "high" || t.securityRisk === "Yüksek") && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-50 text-red-600 border border-red-200">{t.securityRisk === "critical" ? "kritik" : "risk"}</span>
                            )}
                          </div>
                        ))}
                    </div>
                  )}
                </div>
              )}

              {/* Domain Tarama Sonuçları */}
              {candidateDomainScan && (
                <div className="border border-slate-200 rounded-md overflow-hidden">
                  <div className="bg-slate-100 px-3 py-2 flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-700 uppercase tracking-wide">Domain Tarama Sonuçları</span>
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-bold ${candidateDomainScan.overallScore >= 70 ? "text-green-700" : candidateDomainScan.overallScore >= 40 ? "text-yellow-700" : "text-red-700"}`}>
                        {candidateDomainScan.overallScore}/100
                      </span>
                      {candidateDomainScan.sslLabsGrade && (
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          candidateDomainScan.sslLabsGrade.startsWith("A") ? "bg-green-100 text-green-700" :
                          candidateDomainScan.sslLabsGrade.startsWith("B") ? "bg-yellow-100 text-yellow-700" :
                          "bg-red-100 text-red-700"
                        }`}>SSL: {candidateDomainScan.sslLabsGrade}</span>
                      )}
                      <span className="text-[10px] text-muted-foreground">
                        {new Date(candidateDomainScan.createdAt).toLocaleDateString("tr-TR")}
                      </span>
                    </div>
                  </div>
                  <div className="p-3 space-y-3 text-xs">

                    {/* E-posta Güvenliği */}
                    <div>
                      <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1.5">E-posta Güvenliği</div>
                      <div className="grid grid-cols-2 gap-1.5">
                        {[
                          { label: "SPF", pass: candidateDomainScan.spfPass, detail: candidateDomainScan.spfRecord },
                          { label: "DMARC", pass: candidateDomainScan.dmarcPass, detail: candidateDomainScan.dmarcRecord },
                          { label: "DKIM", pass: candidateDomainScan.dkimPass, detail: candidateDomainScan.dkimSelectors?.length > 0 ? `selector: ${candidateDomainScan.dkimSelectors.join(", ")}` : null },
                          { label: "MX", pass: candidateDomainScan.mxPass, detail: candidateDomainScan.mxRecords?.[0]?.exchange ?? null },
                        ].map(({ label, pass, detail }) => (
                          <div key={label} className="flex items-start gap-1.5">
                            <span className={`mt-0.5 shrink-0 w-3.5 h-3.5 rounded-full flex items-center justify-center text-[9px] font-bold ${pass ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"}`}>
                              {pass ? "✓" : "✗"}
                            </span>
                            <div>
                              <span className="font-semibold">{label}</span>
                              {detail && <div className="text-muted-foreground font-mono text-[10px] truncate max-w-[160px]" title={detail}>{detail}</div>}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* SSL */}
                    <div>
                      <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1.5">SSL Sertifikası</div>
                      <div className="flex flex-wrap gap-3">
                        <div className="flex items-center gap-1">
                          <span className={`w-3.5 h-3.5 rounded-full flex items-center justify-center text-[9px] font-bold shrink-0 ${candidateDomainScan.sslPass ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"}`}>
                            {candidateDomainScan.sslPass ? "✓" : "✗"}
                          </span>
                          <span>{candidateDomainScan.sslPass ? "Geçerli" : "Geçersiz/Eksik"}</span>
                        </div>
                        {candidateDomainScan.sslDaysUntilExpiry !== null && (
                          <span className={candidateDomainScan.sslDaysUntilExpiry < 30 ? "text-orange-600 font-semibold" : "text-muted-foreground"}>
                            {candidateDomainScan.sslDaysUntilExpiry} gün kaldı
                          </span>
                        )}
                        {candidateDomainScan.sslIssuer && (
                          <span className="text-muted-foreground">{candidateDomainScan.sslIssuer}</span>
                        )}
                      </div>
                    </div>

                    {/* HTTP Başlıkları */}
                    {candidateDomainScan.httpHeadersDetails && (
                      <div>
                        <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1.5">HTTP Güvenlik Başlıkları</div>
                        <div className="flex flex-wrap gap-1.5">
                          {[
                            { label: "HSTS", pass: candidateDomainScan.httpHeadersDetails.hsts },
                            { label: "X-Frame", pass: candidateDomainScan.httpHeadersDetails.xFrameOptions },
                            { label: "X-Content-Type", pass: candidateDomainScan.httpHeadersDetails.xContentTypeOptions },
                            { label: "CSP", pass: candidateDomainScan.httpHeadersDetails.csp },
                            { label: "Referrer", pass: candidateDomainScan.httpHeadersDetails.referrerPolicy },
                          ].map(({ label, pass }) => (
                            <span key={label} className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${pass ? "bg-green-50 text-green-700 border border-green-200" : "bg-red-50 text-red-600 border border-red-200"}`}>
                              {pass ? "✓" : "✗"} {label}
                            </span>
                          ))}
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${candidateDomainScan.httpHeadersScore >= 70 ? "bg-green-50 text-green-700 border-green-200" : candidateDomainScan.httpHeadersScore >= 40 ? "bg-yellow-50 text-yellow-700 border-yellow-200" : "bg-red-50 text-red-600 border-red-200"}`}>
                            Skor: {candidateDomainScan.httpHeadersScore}/100
                          </span>
                        </div>
                      </div>
                    )}

                    {/* Tehdit İstihbaratı */}
                    <div>
                      <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1.5">Tehdit İstihbaratı</div>
                      <div className="flex flex-wrap gap-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${candidateDomainScan.blacklisted ? "bg-red-50 text-red-700 border-red-200" : "bg-green-50 text-green-700 border-green-200"}`}>
                          {candidateDomainScan.blacklisted ? `Kara Liste: ${candidateDomainScan.blacklistCount} liste` : "Kara Liste: Temiz"}
                        </span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${candidateDomainScan.hibpBreachCount > 0 ? "bg-orange-50 text-orange-700 border-orange-200" : "bg-green-50 text-green-700 border-green-200"}`}>
                          {candidateDomainScan.hibpBreachCount > 0 ? `HIBP: ${candidateDomainScan.hibpBreachCount} ihlal` : "HIBP: İhlal Yok"}
                        </span>
                        {candidateDomainScan.urlhausListed && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium border bg-red-50 text-red-700 border-red-200">
                            URLhaus: {candidateDomainScan.urlhausThreat ?? "Listelendi"}
                          </span>
                        )}
                        {candidateDomainScan.usomListed && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium border bg-red-50 text-red-700 border-red-200">USOM Listesi</span>
                        )}
                        {candidateDomainScan.safeBrowsingFlagged && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium border bg-red-50 text-red-700 border-red-200">Google Safe Browsing</span>
                        )}
                        {candidateDomainScan.virusTotalMalicious > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium border bg-red-50 text-red-700 border-red-200">
                            VT: {candidateDomainScan.virusTotalMalicious} zararlı
                          </span>
                        )}
                        {candidateDomainScan.wafDetected && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium border bg-blue-50 text-blue-700 border-blue-200">
                            WAF: {candidateDomainScan.wafProvider ?? "Tespit Edildi"}
                          </span>
                        )}
                        {candidateDomainScan.confidenceScore != null && candidateDomainScan.confidenceScore < 85 && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-medium border bg-amber-50 text-amber-800 border-amber-300" title="WAF/CDN nedeniyle tarama kısmi görünürlükle yapıldı. Açık port ve CVE bulguları için ek doğrulama önerilir.">
                            Kısmi Görünürlük ({candidateDomainScan.confidenceScore}/100)
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Açık Portlar (Shodan) */}
                    {candidateDomainScan.shodanOpenPorts && candidateDomainScan.shodanOpenPorts.length > 0 && (
                      <div>
                        <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1.5">
                          Açık Portlar ({candidateDomainScan.shodanOpenPorts.length})
                          {candidateDomainScan.shodanVulnCount > 0 && (
                            <span className="ml-2 text-red-600">{candidateDomainScan.shodanVulnCount} CVE</span>
                          )}
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {candidateDomainScan.shodanOpenPorts.slice(0, 12).map((p, i) => (
                            <span key={i} className="px-1.5 py-0.5 bg-slate-100 rounded text-[10px] font-mono" title={`${p.service}${p.product ? ` (${p.product})` : ""}`}>
                              {p.port}/{p.protocol}
                            </span>
                          ))}
                          {candidateDomainScan.shodanOpenPorts.length > 12 && (
                            <span className="text-[10px] text-muted-foreground">+{candidateDomainScan.shodanOpenPorts.length - 12}</span>
                          )}
                        </div>
                      </div>
                    )}

                    {/* CVE Özeti */}
                    {candidateDomainScan.cveSummary && candidateDomainScan.cveSummary.length > 0 && (
                      <div>
                        <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1.5">CVE Bulguları ({candidateDomainScan.cveSummary.length})</div>
                        <div className="space-y-1">
                          {candidateDomainScan.cveSummary.slice(0, 5).map((c, i) => (
                            <div key={i} className="flex items-center gap-2">
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold shrink-0 ${c.cvssScore >= 9 ? "bg-red-100 text-red-700" : c.cvssScore >= 7 ? "bg-orange-100 text-orange-700" : "bg-yellow-100 text-yellow-700"}`}>
                                {c.cvssScore.toFixed(1)}
                              </span>
                              <span className="font-mono text-[10px] text-blue-700 shrink-0">{c.cveId}</span>
                              <span className="text-muted-foreground truncate text-[10px]">{c.service}</span>
                            </div>
                          ))}
                          {candidateDomainScan.cveSummary.length > 5 && (
                            <div className="text-[10px] text-muted-foreground">+{candidateDomainScan.cveSummary.length - 5} daha</div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Shadow IT */}
                    {candidateDomainScan.shadowItServices && candidateDomainScan.shadowItServices.length > 0 && (
                      <div>
                        <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1.5">Shadow IT ({candidateDomainScan.shadowItServices.length})</div>
                        <div className="flex flex-wrap gap-1">
                          {candidateDomainScan.shadowItServices.map((s, i) => (
                            <span key={i} className={`px-1.5 py-0.5 rounded text-[10px] border ${s.risk === "Yüksek" ? "bg-red-50 text-red-700 border-red-200" : s.risk === "Orta" ? "bg-yellow-50 text-yellow-700 border-yellow-200" : "bg-slate-50 text-slate-600 border-slate-200"}`}
                              title={s.description}>
                              {s.name}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* CT Subdomains */}
                    {candidateDomainScan.ctSubdomainCount > 0 && (
                      <div>
                        <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1">CT Log Alt Domainleri ({candidateDomainScan.ctSubdomainCount})</div>
                        <div className="font-mono text-[10px] text-muted-foreground">{candidateDomainScan.ctSubdomains.slice(0, 6).join(", ")}{candidateDomainScan.ctSubdomainCount > 6 ? ` +${candidateDomainScan.ctSubdomainCount - 6}` : ""}</div>
                      </div>
                    )}

                    {/* HIBP İhlaleleri */}
                    {candidateDomainScan.hibpBreaches && candidateDomainScan.hibpBreaches.length > 0 && (
                      <div>
                        <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1.5">Veri İhlali Geçmişi</div>
                        <div className="space-y-1">
                          {candidateDomainScan.hibpBreaches.slice(0, 3).map((b, i) => (
                            <div key={i} className="flex items-center gap-2 text-[10px]">
                              <span className="font-semibold shrink-0">{b.name}</span>
                              <span className="text-muted-foreground">{b.breachDate}</span>
                              <span className="text-orange-600">{b.pwnCount.toLocaleString("tr-TR")} hesap</span>
                            </div>
                          ))}
                          {candidateDomainScan.hibpBreaches.length > 3 && (
                            <div className="text-[10px] text-muted-foreground">+{candidateDomainScan.hibpBreaches.length - 3} daha</div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

            </div>

            {/* ISR Aksiyonları — varsayılan kapalı */}
            <div className="mx-4 mb-2">
              <button
                onClick={() => setIsrOpen(o => !o)}
                className="w-full flex items-center justify-between text-[11px] font-semibold text-blue-700 dark:text-blue-400 uppercase tracking-wide px-3 py-2 rounded-md border border-blue-200 bg-blue-50/60 dark:border-blue-800 dark:bg-blue-950/20 hover:bg-blue-100/60 dark:hover:bg-blue-900/30 transition-colors"
              >
                <span>ISR Aksiyonları</span>
                {isrOpen ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
              </button>
              {isrOpen && (
                <div className="mt-1 rounded-md border border-blue-200 bg-blue-50/60 dark:border-blue-800 dark:bg-blue-950/20 p-3 space-y-3">
                  <div className="flex gap-2 flex-wrap">
                    <a
                      href={buildLinkedInUrl(detailCandidate)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md bg-[#0A66C2] text-white hover:bg-[#0057b7] font-medium"
                    >
                      LinkedIn&apos;de Ara
                    </a>
                    <a
                      href={buildSalesNavUrl(detailCandidate)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-[#0A66C2] text-[#0A66C2] hover:bg-[#0A66C2]/10 font-medium"
                    >
                      Sales Nav
                    </a>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div>
                      <div className="text-muted-foreground mb-0.5">MERSIS Yetkili</div>
                      <div className="font-medium">{detailCandidate.officerName ?? "Bulunamadı"}</div>
                    </div>
                    <div>
                      <div className="text-muted-foreground mb-0.5">Unvan</div>
                      <div>{detailCandidate.officerTitle ?? "—"}</div>
                    </div>
                    <div className="col-span-2">
                      <div className="text-muted-foreground mb-0.5">Kontakt E-posta</div>
                      <div className="font-medium">{detailCandidate.contactEmail ?? "Boş"}</div>
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] text-muted-foreground mb-1">ISR Notları</div>
                    <textarea
                      className="w-full text-xs border rounded-md p-2 resize-none bg-background"
                      rows={3}
                      placeholder="Bu lead için notlarınız..."
                      value={isrNotesEdit}
                      onChange={(e) => setIsrNotesEdit(e.target.value)}
                    />
                    <Button
                      size="sm"
                      className="mt-1 text-xs h-7"
                      onClick={() => saveIsrNotes.mutate({ id: detailCandidate.id, notes: isrNotesEdit })}
                      disabled={saveIsrNotes.isPending}
                    >
                      {saveIsrNotes.isPending ? "Kaydediliyor..." : "Notları Kaydet"}
                    </Button>
                  </div>
                </div>
              )}
            </div>

            {/* Aksiyonlar — sabit alt bar */}
            <div className="flex gap-2 px-4 py-3 border-t shrink-0 flex-wrap bg-background">
              {detailCandidate.isQualified && (
                <Button size="sm" variant="outline" onClick={() => { generateTeaser.mutate(detailCandidate.id); setDetailCandidate(null); }}>
                  {detailCandidate.teaserSubject ? "Teaser Yeniden Üret" : "Teaser Üret"}
                </Button>
              )}
              {detailCandidate.isQualified && (
                detailCandidate.isrPromotedAt ? (
                  <span className="inline-flex items-center px-3 py-1 rounded-md border border-green-200 bg-green-50 text-green-700 text-sm font-medium">
                    ISR Listesinde
                  </span>
                ) : (
                  <Button size="sm" variant="outline" className="text-purple-600 border-purple-200"
                    onClick={() => { promoteToIsr.mutate(detailCandidate); setDetailCandidate(null); }}
                    disabled={promoteToIsr.isPending}>
                    ISR Listesine Ekle
                  </Button>
                )
              )}
              <Button size="sm" variant="outline" className="text-cyan-600 border-cyan-200"
                onClick={() => { setFingerprintResult(null); fingerprintLead.mutate(detailCandidate.domain); }}
                disabled={fingerprintLead.isPending}>
                {fingerprintLead.isPending ? "Taranıyor..." : "Tech Fingerprint"}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => { setDetailCandidate(null); setFingerprintResult(null); }}>Kapat</Button>
            </div>
          </DialogContent>
        </Dialog>
      )}

      {/* Teaser Preview Dialog */}
      {!!teaserPreview && (
        <Dialog open={!!teaserPreview} onOpenChange={() => setTeaserPreview(null)}>
          <DialogContent className="max-w-3xl w-[95vw]">
            <DialogHeader>
              <DialogTitle>Teaser Önizleme — {teaserPreview.domain}</DialogTitle>
            </DialogHeader>
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="text-xs text-muted-foreground mb-1">Konu</div>
                  <div className="font-medium text-sm">{teaserPreview.teaserSubject}</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground mb-1">Alıcı</div>
                  <div className="text-sm">{teaserPreview.contactEmail ?? "—"}</div>
                </div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground mb-1">İçerik</div>
                <div className="border rounded-md overflow-hidden" style={{ height: 480 }}>
                  <iframe
                    srcDoc={teaserPreview.teaserBody ?? ""}
                    className="w-full h-full"
                    sandbox="allow-same-origin"
                    title="Teaser Önizleme"
                  />
                </div>
              </div>
              <div className="flex gap-2 justify-end pt-2">
                <Button variant="outline" onClick={() => setTeaserPreview(null)}>Kapat</Button>
                <Button
                  variant="outline"
                  onClick={() => { generateTeaser.mutate(teaserPreview.id); setTeaserPreview(null); }}
                  disabled={generateTeaser.isPending}
                >
                  Yeniden Üret
                </Button>
                {!teaserPreview.teaserSentAt && teaserPreview.contactEmail && (
                  <Button
                    onClick={() => {
                      sendTeaser.mutate(teaserPreview.id);
                      setTeaserPreview(null);
                    }}
                  >
                    Gönderildi Olarak İşaretle
                  </Button>
                )}
              </div>
            </div>
          </DialogContent>
        </Dialog>
      )}
      {/* Kontak Düzenleme Dialog */}
      {!!contactEditTarget && (
        <Dialog open={!!contactEditTarget} onOpenChange={() => setContactEditTarget(null)}>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>Kontak Düzenle — {contactEditTarget.domain}</DialogTitle>
            </DialogHeader>
            <div className="space-y-3 py-2">
              <div>
                <Label className="text-xs mb-1 block">E-posta *</Label>
                <Input
                  value={editEmail}
                  onChange={(e) => setEditEmail(e.target.value)}
                  placeholder="ornek@sirket.com.tr"
                  type="email"
                />
              </div>
              <div>
                <Label className="text-xs mb-1 block">Ad Soyad</Label>
                <Input
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  placeholder="Ahmet Yılmaz"
                />
              </div>
              <div>
                <Label className="text-xs mb-1 block">Unvan</Label>
                <Input
                  value={editTitle}
                  onChange={(e) => setEditTitle(e.target.value)}
                  placeholder="IT Müdürü"
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setContactEditTarget(null)}>Vazgec</Button>
              <Button
                disabled={!editEmail || saveContact.isPending}
                onClick={() =>
                  saveContact.mutate({
                    id: contactEditTarget.id,
                    contactEmail: editEmail,
                    contactName: editName,
                    contactTitle: editTitle,
                  })
                }
              >
                Kaydet
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </AdminLayout>
  );
}
