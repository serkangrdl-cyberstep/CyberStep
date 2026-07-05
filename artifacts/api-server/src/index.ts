import fs from "fs";
import { randomUUID } from "crypto";
import app from "./app";
import { logger } from "./lib/logger";
import { db, pool } from "@workspace/db";
import { adminUsersTable, pricingPlansTable, questionsTable, assessmentsTable, reportsTable, domainScansTable, customersTable, partnersTable, workPackagesTable, blogPostsTable, demoReportsTable } from "@workspace/db";
import { eq, count, sql, and, isNull, lte } from "drizzle-orm";
import { checkSPF, checkDMARC, checkDKIM, checkMX, checkSSL, calcScore, refreshUsomList } from "./routes/domain-scan/index";
import { loadApiKeysFromDb } from "./routes/admin-panel/settings";
import { sendReminderEmail, sendDomainRescanEmail, sendWeeklyDeltaEmail, sendMail } from "./services/email";
import { generateAndPublishBlogPost } from "./services/blog-autopilot";
import { startFabricCrons } from "./services/fabric-cron";
import { scanCRTSH } from "./services/crtshScanner";
import { scanShodanFree, SHODAN_FREE_QUERIES } from "./services/shodanDiscovery";
import { runRipeDiscovery } from "./services/ripeDiscovery";
import { runNetcraftDiscovery } from "./services/leadDiscovery/netcraftDiscovery";
import { runBgpToolsDiscovery } from "./services/leadDiscovery/bgpToolsDiscovery";
import { runUrlscanDiscovery } from "./services/leadDiscovery/urlscanDiscovery";
import { runVirusTotalDiscovery } from "./services/leadDiscovery/virusTotalDiscovery";
import { runCensysDiscovery } from "./services/leadDiscovery/censysDiscovery";
import { runSearchDorking } from "./services/leadDiscovery/searchDorking";
import { runCompanyRegistryDiscovery } from "./services/leadDiscovery/companyRegistryDiscovery";
import { getSourceQualityStats } from "./routes/admin-panel/source-stats";
import { qualifyPendingCandidates, preScreenPendingCandidates, getISOWeek } from "./services/discoveryPipeline";
import { generateEcosystemReport } from "./services/ecosystemReportService";
import { checkPhishingCertificates } from "./services/ctPhishingMonitor";
import { cronStart, cronIsEnabled, cronGetLimit, wrapCron, getCronFn, cleanupStaleRunningJobs, cleanupStaleDiscoveryRuns, startCronWatchdog } from "./services/cronRegistry";
import { runCVEFeedCheck } from "./services/cve/cveOrchestrator";
import { setAiCostLogger } from "@workspace/ai";
import { logAiCost } from "./services/aiCostTracker";
import { checkSubscriptionExpiryReminders } from "./services/subscription-renewal";
import { startSOCCrons } from "./services/soc/soc-cron";
import { startDnsCrons } from "./services/dns-cron";
import { ensureCtTable } from "./routes/ct-monitor/index";
import { ensureMs365Tables } from "./routes/ms365/index";
import { ensureCustomerServiceConfigsTable } from "./routes/customer/index";
import { ensureTechDiscoveryTable } from "./routes/tech-discovery/index";
import { ensureIspTables } from "./routes/admin-panel/lead-discovery";
import { ensureKvkkTables, checkKvkkDeadlines } from "./services/kvkkAssessor";
import { ensureServiceNowTables, syncServiceNowIncidents, checkServiceNowConnections } from "./services/serviceNowClient";
import { ensureWebhookTables, retryFailedWebhooks } from "./services/webhookDispatcher";
import { ensureTelegramTables } from "./services/telegramNotifier";
import { ensureNetgsmTables } from "./services/netgsmNotifier";
import { initSOCWebSocket } from "./services/soc/soc-ws";
import { runScanLeadDripCron } from "./routes/scan-leads/index";
import { collectRSSFeeds, seedDefaultSources } from "./routes/digest/rss-collector";
import { generateWeeklyDigest } from "./routes/digest/claude-processor";
import { ensureNewsItemColumns, enrichNewsItems } from "./services/news/newsEnricher";
import { calculateAllHealthScores } from "./routes/health/index";
import { collectDailySummary } from "./services/dailyDashboard";
import { runDunningCron } from "./services/dunningManager";
import { runUpsellEngine } from "./services/upsellEngine";
import { runMarketWatcher, sendWeeklyMarketSummary } from "./services/marketWatcher";
import { fetchVulnCheckKEV } from "./services/intelligence/vulncheckService";
import { checkIntelFeeds } from "./services/intelligence/intelFeedWatcher";
import { sendMonthlyReportReminder } from "./services/intelligence/annualReportScheduler";
import { checkPlatformCosts } from "./services/platformMonitor";
import { runDay1EmailCron } from "./services/onboardingEmailSeries";
import { runCollectionReminderCron } from "./services/invoice";
import { runAutoTagCron, runTaskReminderCron, runNpsCron } from "./routes/crm/index";
import { startRenewalCron } from "./services/subscription-renewal";
import { processEmailQueue } from "./services/email-sequences";
import {
  runFortiGatePollCron,
  runAvailabilityCron,
  runNOCTriageCron,
  checkAndCompleteBaselines,
} from "./services/noc-service";
import cron from "node-cron";
import bcrypt from "bcryptjs";

// Güvenlik ağı: beklenmeyen/ele alınmamış hatalar tüm sunucuyu çökertmesin.
// Bu, kritik bir hatayı gizlemek için değil, tekil istek/cron içindeki
// öngörülemeyen edge-case'lerin (ör. bozuk URL, ağ hatası) process'i
// öldürüp cron'ları/kuyruğu kesintiye uğratmasını önlemek içindir.
process.on("uncaughtException", (err) => {
  logger.error({ err }, "Uncaught exception yakalandı — process çökmedi");
});
process.on("unhandledRejection", (reason) => {
  logger.error({ err: reason }, "Unhandled promise rejection yakalandı — process çökmedi");
});

const rawPort = process.env["PORT"];

if (!rawPort) {
  throw new Error(
    "PORT environment variable is required but was not provided.",
  );
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

// ─── Startup: admin şifre sıfırlama (opsiyonel) ───────────────────────────────
async function maybeResetAdminPassword() {
  const resetPassword = process.env["ADMIN_RESET_PASSWORD"];
  if (!resetPassword) return;

  if (resetPassword.length < 12) {
    logger.warn("ADMIN_RESET_PASSWORD set but too short (min 12 chars) — skipping reset");
    return;
  }

  const [admin] = await db.select({ id: adminUsersTable.id, email: adminUsersTable.email })
    .from(adminUsersTable)
    .limit(1);

  if (!admin) {
    logger.warn("ADMIN_RESET_PASSWORD set but no admin user found — skipping reset");
    return;
  }

  const hash = await bcrypt.hash(resetPassword, 12);
  await db.update(adminUsersTable)
    .set({ passwordHash: hash })
    .where(eq(adminUsersTable.id, admin.id));

  logger.info({ email: admin.email }, "Admin password reset via ADMIN_RESET_PASSWORD env var — remove the var now!");
}

// ─── Startup: questions tablosunu oluştur (yoksa) ────────────────────────────
async function ensureQuestionsTable() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS questions (
      id SERIAL PRIMARY KEY,
      number INTEGER NOT NULL,
      type TEXT NOT NULL DEFAULT 'mini',
      domain TEXT NOT NULL,
      text TEXT NOT NULL,
      weight INTEGER NOT NULL DEFAULT 1,
      is_red_alarm BOOLEAN NOT NULL DEFAULT false,
      is_active BOOLEAN NOT NULL DEFAULT true,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);
}

// ─── Startup: fiyatlandırma planlarını seed et (boşsa) ───────────────────────
async function maybeSeedPricingPlans() {
  const [{ cnt }] = await db.select({ cnt: count() }).from(pricingPlansTable);
  if (Number(cnt) > 0) return;

  await db.insert(pricingPlansTable).values([
    {
      slug: "mini",
      name: "Mini Değerlendirme",
      price: "0",
      currency: "TRY",
      description: "20 soruluk ücretsiz başlangıç değerlendirmesi",
      features: ["20 soruluk hızlı risk değerlendirmesi", "5 güvenlik alanı (A-E)", "Anlık risk skoru ve seviyesi", "Kırmızı alarm tespiti", "Yapay zeka destekli temel rapor"],
      isActive: true,
      sortOrder: 0,
    },
    {
      slug: "full",
      name: "Tam Değerlendirme",
      price: "5990",
      currency: "TRY",
      description: "55 soruluk kapsamlı siber güvenlik denetimi — Claude AI destekli detaylı rapor",
      features: ["55 soruluk kapsamlı risk değerlendirmesi", "10 güvenlik alanı (A-J)", "Claude AI destekli detaylı rapor", "PDF rapor indirme", "Sektörel karşılaştırma", "Birebir uzman danışmanlık görüşmesi (1 saat)"],
      isActive: true,
      sortOrder: 1,
    },
    {
      slug: "premium",
      name: "Premium Danışmanlık",
      price: "17990",
      currency: "TRY",
      description: "Kişisel danışmanlık, saha değerlendirmesi ve 6 ay uzman desteği",
      features: ["Tam değerlendirme dahil", "1-1 uzman görüşmesi", "Saha incelemesi", "Teknik yol haritası", "6 ay takip desteği"],
      isActive: true,
      sortOrder: 2,
    },
    {
      slug: "starter",
      name: "Başlangıç Aboneliği",
      price: "690",
      currency: "TRY",
      description: "1-10 çalışanlı KOBİler için aylık sürekli izleme",
      features: ["Alan adı otomatik yeniden tarama (30 günlük)", "Mini değerlendirme erişimi", "Sızıntı izleyici bildirimleri", "E-posta destek", "Claude AI destekli temel rapor"],
      isActive: true,
      sortOrder: 3,
    },
    {
      slug: "growth",
      name: "Büyüme Aboneliği",
      price: "1990",
      currency: "TRY",
      description: "11-200 çalışanlı KOBİler için kapsamlı aylık koruma",
      features: ["Tam değerlendirme (yılda 2)", "Tüm domain tarama modülleri", "KVKK uyum haritası", "Sektörel kıyaslama raporu", "Öncelikli e-posta desteği", "Claude AI destekli detaylı rapor"],
      isActive: true,
      sortOrder: 4,
    },
    {
      slug: "enterprise",
      name: "Kurumsal Abonelik",
      price: "5990",
      currency: "TRY",
      description: "200+ çalışanlı işletmeler için kurumsal siber güvenlik yönetimi",
      features: ["Sınırsız değerlendirme", "Birebir danışman görüşmesi (aylık)", "ISR tehdit istihbaratı", "TPRM tedarik zinciri taraması", "White-label raporlama", "SLA destekli öncelikli destek", "Claude AI gelişmiş analiz"],
      isActive: true,
      sortOrder: 5,
    },
  ]);

  logger.info("Pricing plans seeded (table was empty)");
}

// ─── Startup: Mini Assessment sorularını seed et (boşsa) ─────────────────────
async function maybeSeedQuestions() {
  const [{ cnt }] = await db.select({ cnt: count() }).from(questionsTable);
  if (Number(cnt) > 0) return;

  const MINI_SEED = [
    { number: 1,  domain: "Firma ve Yönetişim",             text: "Şirketinizde siber güvenlikten ana sorumlu bir kişi veya rol net olarak tanımlı mı?",                                       weight: 1, isRedAlarm: false },
    { number: 2,  domain: "Firma ve Yönetişim",             text: "Kritik iş uygulamalarınızın ve temel sistemlerinizin listesi güncel olarak mevcut mu?",                                       weight: 1, isRedAlarm: false },
    { number: 3,  domain: "Firma ve Yönetişim",             text: "Yeni işe giren ve işten ayrılan çalışanlar için kullanıcı hesabı açma/kapama süreci tanımlı mı?",                            weight: 2, isRedAlarm: true  },
    { number: 4,  domain: "Firma ve Yönetişim",             text: "Şirketinizde hassas bilgilerin hangi sistemlerde tutulduğu güncel bir envanterle takip ediliyor mu?",                        weight: 1, isRedAlarm: false },
    { number: 5,  domain: "Kimlik ve Erişim",               text: "Çalışanlar e-posta ve iş uygulamalarına girerken MFA/2FA kullanıyor mu?",                                                    weight: 2, isRedAlarm: true  },
    { number: 6,  domain: "Kimlik ve Erişim",               text: "Uzak erişim, VPN, yönetici yetkili hesaplarda ek doğrulama zorunlu mu?",                                                     weight: 2, isRedAlarm: true  },
    { number: 7,  domain: "Kimlik ve Erişim",               text: "İşten ayrılan çalışanların sistem erişimleri aynı gün kaldırılıyor mu?",                                                     weight: 2, isRedAlarm: true  },
    { number: 8,  domain: "Kimlik ve Erişim",               text: "Aynı kullanıcı hesabının birden fazla kişi tarafından kullanımı engelleniyor mu?",                                           weight: 1, isRedAlarm: false },
    { number: 9,  domain: "E-posta ve İnsan Faktörü",       text: "Çalışanlara şüpheli e-posta ve parola hırsızlığı riskleri hakkında farkındalık eğitimi veriliyor mu?",                       weight: 1, isRedAlarm: false },
    { number: 10, domain: "E-posta ve İnsan Faktörü",       text: "Şüpheli e-posta geldiğinde çalışanların bunu kime bildireceği biliniyor mu?",                                                weight: 1, isRedAlarm: false },
    { number: 11, domain: "E-posta ve İnsan Faktörü",       text: "IBAN değişikliği veya acil para transferi gibi durumlarda e-posta dışında ikinci doğrulama uygulanıyor mu?",                 weight: 2, isRedAlarm: true  },
    { number: 12, domain: "E-posta ve İnsan Faktörü",       text: "E-posta alan adınız üzerinden sahte mail gönderilmesini engelleyecek (SPF, DKIM, DMARC) yapılandırmalar devrede mi?",        weight: 2, isRedAlarm: true  },
    { number: 13, domain: "Cihaz Güvenliği",                text: "Şirkette kullanılan bilgisayarların güncel bir listesi tutuluyor mu?",                                                        weight: 1, isRedAlarm: false },
    { number: 14, domain: "Cihaz Güvenliği",                text: "Çalışan bilgisayarlarında zararlı yazılımlara karşı merkezi bir güvenlik çözümü bulunuyor mu?",                             weight: 2, isRedAlarm: true  },
    { number: 15, domain: "Cihaz Güvenliği",                text: "Bilgisayarlar ve iş uygulamaları düzenli olarak güncelleniyor mu?",                                                          weight: 1, isRedAlarm: false },
    { number: 16, domain: "Cihaz Güvenliği",                text: "Dizüstü veya mobil cihazlarda ekran kilidi ve güçlü parola uygulanıyor mu?",                                                 weight: 1, isRedAlarm: false },
    { number: 17, domain: "Veri Koruma ve Yedekleme",       text: "Kritik verileriniz düzenli olarak (tercihen otomatik) yedekleniyor mu?",                                                     weight: 2, isRedAlarm: true  },
    { number: 18, domain: "Veri Koruma ve Yedekleme",       text: "Alınan yedeklerin geri yüklenip çalışabildiği son 12 ayda test edildi mi?",                                                  weight: 2, isRedAlarm: true  },
    { number: 19, domain: "Veri Koruma ve Yedekleme",       text: "Bir siber olay yaşanırsa ilk kimin devreye gireceği ve ne yapılacağı yazılı olarak belli mi?",                               weight: 1, isRedAlarm: false },
    { number: 20, domain: "Veri Koruma ve Yedekleme",       text: "Hassas dosyalara kimlerin erişebildiği düzenli olarak kontrol ediliyor mu?",                                                 weight: 1, isRedAlarm: false },
  ];

  await db.insert(questionsTable).values(
    MINI_SEED.map((q, i) => ({ ...q, type: "mini", isActive: true, sortOrder: i }))
  );

  logger.info("Mini assessment questions seeded (table was empty)");
}

// ─── Cron: 30-günlük hatırlatıcı e-postası (her gün 09:45'de çalışır) ─────────
function startReminderCron() {
  cron.schedule("45 9 * * *", wrapCron("reminder_30day", "45 9 * * *", async () => {
    logger.info("Running 30-day reminder cron job");
    try {
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      const thirtyOneDaysAgo = new Date();
      thirtyOneDaysAgo.setDate(thirtyOneDaysAgo.getDate() - 31);

      const due = await db
        .select({
          id: assessmentsTable.id,
          companyName: assessmentsTable.companyName,
          contactName: assessmentsTable.contactName,
          email: assessmentsTable.email,
          riskLevel: assessmentsTable.riskLevel,
          totalScore: assessmentsTable.totalScore,
          maxScore: assessmentsTable.maxScore,
        })
        .from(assessmentsTable)
        .where(
          and(
            sql`${assessmentsTable.status} = 'report_ready'`,
            isNull(assessmentsTable.reminderSentAt),
            lte(assessmentsTable.completedAt, thirtyDaysAgo),
            sql`${assessmentsTable.completedAt} >= ${thirtyOneDaysAgo}`,
          )
        );

      const base = process.env["REPLIT_DOMAINS"]
        ? `https://${process.env["REPLIT_DOMAINS"].split(",")[0]?.trim()}`
        : "http://localhost:80";

      for (const a of due) {
        const scorePercent = a.totalScore && a.maxScore
          ? Math.round((a.totalScore / a.maxScore) * 100)
          : 0;
        await sendReminderEmail({
          assessmentId: a.id,
          companyName: a.companyName,
          contactName: a.contactName,
          customerEmail: a.email,
          riskLevel: a.riskLevel ?? "Bilinmiyor",
          scorePercent,
          assessmentUrl: `${base}/assessment/${a.id}/report`,
        });
        await db
          .update(assessmentsTable)
          .set({ reminderSentAt: new Date() })
          .where(eq(assessmentsTable.id, a.id));

        logger.info({ assessmentId: a.id }, "Reminder email sent and reminderSentAt updated");
      }

      if (due.length === 0) {
        logger.info("No reminders due today");
      }
    } catch (err) {
      logger.error({ err }, "Reminder cron job failed");
    }
  }), { timezone: "Europe/Istanbul" });

  logger.info("30-day reminder cron scheduled (09:45 Istanbul)");

  // Domain re-tarama: e-postası olan ve 30+ gün önce taranan kayıtları yeniden tara
  cron.schedule("30 9 * * *", wrapCron("domain_rescan", "30 9 * * *", async () => {
    logger.info("Running domain re-scan cron job");
    try {
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

      const due = await db
        .select()
        .from(domainScansTable)
        .where(
          and(
            sql`${domainScansTable.email} IS NOT NULL`,
            lte(domainScansTable.createdAt, thirtyDaysAgo),
            isNull(domainScansTable.notifiedAt),
          )
        );

      for (const scan of due) {
        try {
          const [spf, dmarc, dkim, mx, ssl] = await Promise.all([
            checkSPF(scan.domain),
            checkDMARC(scan.domain),
            checkDKIM(scan.domain),
            checkMX(scan.domain),
            checkSSL(scan.domain),
          ]);
          const { total: newScore } = calcScore(spf.strength, dmarc.policy ?? null, dkim.pass, mx.pass, ssl.daysUntilExpiry);
          const scoreChanged = newScore !== scan.overallScore;

          await db.insert(domainScansTable).values({
            domain: scan.domain,
            email: scan.email,
            spfPass: spf.pass,
            spfRecord: spf.record,
            dmarcPass: dmarc.pass,
            dmarcRecord: dmarc.record,
            dkimPass: dkim.pass,
            dkimSelectors: dkim.selectors,
            mxPass: mx.pass,
            mxRecords: mx.records,
            sslPass: ssl.pass,
            sslExpiry: ssl.expiryDate,
            sslIssuer: ssl.issuer,
            sslDaysUntilExpiry: ssl.daysUntilExpiry,
            overallScore: newScore,
            notifiedAt: new Date(),
          });

          await db.update(domainScansTable)
            .set({ notifiedAt: new Date() })
            .where(eq(domainScansTable.id, scan.id));

          if (scan.email) {
            await sendDomainRescanEmail({
              email: scan.email,
              domain: scan.domain,
              oldScore: scan.overallScore ?? 0,
              newScore,
              spfPass: spf.pass,
              dmarcPass: dmarc.pass,
              dkimPass: dkim.pass,
              mxPass: mx.pass,
              sslPass: ssl.pass,
            });
            if (scoreChanged) {
              logger.info({ domain: scan.domain, oldScore: scan.overallScore, newScore }, "Domain score changed — rescan email sent");
            }
          }
          logger.info({ domain: scan.domain, newScore }, "Domain re-scan complete");
        } catch (err) {
          logger.error({ err, domain: scan.domain }, "Domain re-scan failed for single domain");
        }
      }
    } catch (err) {
      logger.error({ err }, "Domain re-scan cron job failed");
    }
  }), { timezone: "Europe/Istanbul" });

  logger.info("Domain re-scan cron scheduled (09:30 Istanbul)");

  cron.schedule("0 8 * * 1", wrapCron("weekly_delta", "0 8 * * 1", async () => {
    logger.info("Running weekly delta cron job");
    try {
      const sixtyDaysAgo = new Date();
      sixtyDaysAgo.setDate(sixtyDaysAgo.getDate() - 60);

      const recentScans = await db
        .select()
        .from(domainScansTable)
        .where(
          and(
            sql`${domainScansTable.email} IS NOT NULL`,
            sql`${domainScansTable.createdAt} >= ${sixtyDaysAgo.toISOString()}`
          )
        )
        .orderBy(sql`${domainScansTable.createdAt} DESC`);

      const seenDomains = new Set<string>();
      const uniqueScans = recentScans.filter(s => {
        if (seenDomains.has(s.domain)) return false;
        seenDomains.add(s.domain);
        return true;
      });

      for (const scan of uniqueScans) {
        try {
          const [spf, dmarc, dkim, mx, ssl] = await Promise.all([
            checkSPF(scan.domain),
            checkDMARC(scan.domain),
            checkDKIM(scan.domain),
            checkMX(scan.domain),
            checkSSL(scan.domain),
          ]);
          const { total: newScore } = calcScore(spf.strength, dmarc.policy ?? null, dkim.pass, mx.pass, ssl.daysUntilExpiry);

          const changes: Array<{ check: string; wasPass: boolean; isPass: boolean }> = [];
          if ((scan.spfPass ?? false) !== spf.pass) changes.push({ check: "SPF (Sahte E-posta Koruması)", wasPass: scan.spfPass ?? false, isPass: spf.pass });
          if ((scan.dmarcPass ?? false) !== dmarc.pass) changes.push({ check: "DMARC (E-posta Kimlik Dogrulama)", wasPass: scan.dmarcPass ?? false, isPass: dmarc.pass });
          if ((scan.dkimPass ?? false) !== dkim.pass) changes.push({ check: "DKIM (E-posta Imzalama)", wasPass: scan.dkimPass ?? false, isPass: dkim.pass });
          if ((scan.mxPass ?? false) !== mx.pass) changes.push({ check: "MX Kayıtları", wasPass: scan.mxPass ?? false, isPass: mx.pass });
          if ((scan.sslPass ?? false) !== ssl.pass) changes.push({ check: "SSL Sertifikası", wasPass: scan.sslPass ?? false, isPass: ssl.pass });

          if (changes.length > 0 || newScore !== scan.overallScore) {
            const newIssues = changes.filter(c => !c.isPass && c.wasPass).length;
            const resolvedIssues = changes.filter(c => c.isPass && !c.wasPass).length;

            await db.insert(domainScansTable).values({
              domain: scan.domain,
              email: scan.email,
              spfPass: spf.pass, spfRecord: spf.record ?? null,
              dmarcPass: dmarc.pass, dmarcRecord: dmarc.record ?? null,
              dkimPass: dkim.pass, dkimSelectors: dkim.selectors,
              mxPass: mx.pass, mxRecords: mx.records,
              sslPass: ssl.pass, sslExpiry: ssl.expiryDate ?? null,
              sslIssuer: ssl.issuer ?? null, sslDaysUntilExpiry: ssl.daysUntilExpiry ?? null,
              overallScore: newScore,
            });

            if (scan.email) {
              await sendWeeklyDeltaEmail({
                email: scan.email,
                domain: scan.domain,
                oldScore: scan.overallScore ?? 0,
                newScore,
                changes,
                newIssues,
                resolvedIssues,
                date: new Date().toLocaleDateString("tr-TR"),
              });
            }
            logger.info({ domain: scan.domain, oldScore: scan.overallScore, newScore, changesCount: changes.length }, "Weekly delta email sent");
          } else {
            logger.info({ domain: scan.domain, score: newScore }, "Weekly delta: no changes, skipping email");
          }
        } catch (err) {
          logger.error({ err, domain: scan.domain }, "Weekly delta check failed for domain");
        }
      }
    } catch (err) {
      logger.error({ err }, "Weekly delta cron job failed");
    }
  }), { timezone: "Europe/Istanbul" });

  logger.info("Weekly delta cron scheduled (Monday 08:00 Istanbul)");
}

async function ensureTenantsTable() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS tenants (
      id SERIAL PRIMARY KEY,
      slug TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      plan TEXT NOT NULL DEFAULT 'free',
      max_users INTEGER NOT NULL DEFAULT 1,
      max_assessments INTEGER NOT NULL DEFAULT 10,
      isr_enabled BOOLEAN NOT NULL DEFAULT false,
      logo_url TEXT,
      primary_color TEXT,
      ai_provider TEXT NOT NULL DEFAULT 'gemini-replit',
      ai_api_key TEXT,
      ai_model TEXT,
      quote_terms TEXT,
      quote_valid_days INTEGER NOT NULL DEFAULT 30,
      quote_footer TEXT,
      imap_host TEXT,
      imap_user TEXT,
      imap_pass TEXT,
      smtp_host TEXT,
      smtp_user TEXT,
      smtp_pass TEXT,
      smtp_port INTEGER NOT NULL DEFAULT 587,
      is_active BOOLEAN NOT NULL DEFAULT true,
      settings JSONB DEFAULT '{}',
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS tenant_users (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL REFERENCES tenants(id),
      admin_user_id INTEGER NOT NULL,
      role TEXT NOT NULL DEFAULT 'member',
      invited_by_admin_user_id INTEGER,
      joined_at TIMESTAMP NOT NULL DEFAULT NOW(),
      UNIQUE(tenant_id, admin_user_id)
    )
  `);
}

async function ensureIsrTables() {
  // Add tenant_id columns to existing ISR tables if missing
  await db.execute(sql`ALTER TABLE IF EXISTS isr_vendors ADD COLUMN IF NOT EXISTS tenant_id INTEGER NOT NULL DEFAULT 1`);
  await db.execute(sql`ALTER TABLE IF EXISTS isr_distributors ADD COLUMN IF NOT EXISTS tenant_id INTEGER NOT NULL DEFAULT 1`);
  await db.execute(sql`ALTER TABLE IF EXISTS isr_deals ADD COLUMN IF NOT EXISTS tenant_id INTEGER NOT NULL DEFAULT 1`);
  await db.execute(sql`ALTER TABLE IF EXISTS isr_margin_rules ADD COLUMN IF NOT EXISTS tenant_id INTEGER NOT NULL DEFAULT 1`);
  await db.execute(sql`ALTER TABLE IF EXISTS isr_email_inbox ADD COLUMN IF NOT EXISTS tenant_id INTEGER NOT NULL DEFAULT 1`);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS isr_vendors (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL DEFAULT 1,
      name TEXT NOT NULL,
      display_name TEXT NOT NULL,
      logo_url TEXT,
      sales_rep_name TEXT,
      sales_rep_email TEXT,
      deal_reg_url TEXT,
      notes TEXT,
      is_active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS isr_distributors (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL DEFAULT 1,
      vendor_id INTEGER NOT NULL REFERENCES isr_vendors(id),
      name TEXT NOT NULL,
      contact_name TEXT,
      contact_email TEXT NOT NULL,
      phone TEXT,
      notes TEXT,
      is_active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS isr_deals (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL DEFAULT 1,
      customer_name TEXT,
      customer_email TEXT NOT NULL,
      customer_company TEXT,
      customer_phone TEXT,
      vendor_id INTEGER REFERENCES isr_vendors(id),
      vendor_name TEXT,
      product_keywords TEXT,
      original_subject TEXT,
      original_body TEXT,
      ai_summary TEXT,
      status TEXT NOT NULL DEFAULT 'new',
      assigned_rep_email TEXT,
      priority TEXT NOT NULL DEFAULT 'normal',
      notes TEXT,
      email_message_id TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS isr_rfqs (
      id SERIAL PRIMARY KEY,
      deal_id INTEGER NOT NULL REFERENCES isr_deals(id),
      distributor_id INTEGER REFERENCES isr_distributors(id),
      sent_to_email TEXT NOT NULL,
      sent_to_name TEXT,
      subject TEXT NOT NULL,
      body TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'sent',
      email_message_id TEXT,
      sent_at TIMESTAMP NOT NULL DEFAULT NOW(),
      responded_at TIMESTAMP
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS isr_rfq_responses (
      id SERIAL PRIMARY KEY,
      rfq_id INTEGER NOT NULL REFERENCES isr_rfqs(id),
      deal_id INTEGER NOT NULL REFERENCES isr_deals(id),
      from_email TEXT NOT NULL,
      subject TEXT,
      body TEXT,
      ai_parsed JSONB,
      currency TEXT NOT NULL DEFAULT 'TRY',
      valid_until TEXT,
      notes TEXT,
      received_at TIMESTAMP NOT NULL
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS isr_quote_lines (
      id SERIAL PRIMARY KEY,
      rfq_response_id INTEGER REFERENCES isr_rfq_responses(id),
      quote_id INTEGER,
      sku TEXT,
      description TEXT NOT NULL,
      quantity INTEGER NOT NULL DEFAULT 1,
      unit_cost NUMERIC(18,4),
      unit_price NUMERIC(18,4),
      discount NUMERIC(5,2) DEFAULT 0,
      line_total NUMERIC(18,4),
      currency TEXT NOT NULL DEFAULT 'TRY',
      is_custom BOOLEAN NOT NULL DEFAULT false,
      sort_order INTEGER NOT NULL DEFAULT 0
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS isr_quotes (
      id SERIAL PRIMARY KEY,
      deal_id INTEGER NOT NULL REFERENCES isr_deals(id),
      quote_number TEXT NOT NULL,
      currency TEXT NOT NULL DEFAULT 'TRY',
      subtotal NUMERIC(18,4),
      kdv_rate NUMERIC(5,2) DEFAULT 20,
      kdv_amount NUMERIC(18,4),
      total NUMERIC(18,4),
      valid_days INTEGER NOT NULL DEFAULT 30,
      notes TEXT,
      terms TEXT,
      status TEXT NOT NULL DEFAULT 'draft',
      approved_by_email TEXT,
      approved_at TIMESTAMP,
      sent_at TIMESTAMP,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS isr_margin_rules (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL DEFAULT 1,
      vendor_id INTEGER REFERENCES isr_vendors(id),
      name TEXT NOT NULL,
      min_margin_pct NUMERIC(5,2) NOT NULL DEFAULT 15,
      target_margin_pct NUMERIC(5,2) NOT NULL DEFAULT 25,
      max_discount_pct NUMERIC(5,2) NOT NULL DEFAULT 10,
      auto_approve_below NUMERIC(18,4),
      require_approval_above NUMERIC(18,4),
      is_default BOOLEAN NOT NULL DEFAULT false,
      is_active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS isr_email_inbox (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL DEFAULT 1,
      message_id TEXT NOT NULL UNIQUE,
      from_email TEXT NOT NULL,
      from_name TEXT,
      to_email TEXT,
      subject TEXT,
      body_text TEXT,
      body_html TEXT,
      processed_as TEXT,
      deal_id INTEGER REFERENCES isr_deals(id),
      rfq_id INTEGER REFERENCES isr_rfqs(id),
      received_at TIMESTAMP NOT NULL,
      processed_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  // ─── Enterprise & LeadGen tables ─────────────────────────────────────────────
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS enterprise_prospects (
      id SERIAL PRIMARY KEY,
      company_name VARCHAR(255) NOT NULL,
      domain VARCHAR(255) NOT NULL,
      sector VARCHAR(100),
      employee_count VARCHAR(50),
      city VARCHAR(100),
      contact_name VARCHAR(255),
      contact_title VARCHAR(100),
      contact_email VARCHAR(255),
      contact_phone VARCHAR(50),
      linkedin_url VARCHAR(500),
      source VARCHAR(50) DEFAULT 'manual',
      assigned_to VARCHAR(100),
      status VARCHAR(30) DEFAULT 'new',
      notes TEXT,
      lost_reason VARCHAR(255),
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      last_activity_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS teaser_reports (
      id SERIAL PRIMARY KEY,
      prospect_id INTEGER REFERENCES enterprise_prospects(id),
      domain_scan_data JSONB,
      attack_scenarios JSONB,
      overall_risk_score INTEGER,
      risk_level VARCHAR(20),
      critical_count INTEGER DEFAULT 0,
      high_count INTEGER DEFAULT 0,
      medium_count INTEGER DEFAULT 0,
      low_count INTEGER DEFAULT 0,
      teaser_headline TEXT,
      teaser_findings JSONB,
      teaser_scenario_preview TEXT,
      locked_sections_hint TEXT,
      urgency_note TEXT,
      preview_token VARCHAR(64) UNIQUE NOT NULL,
      email_sent_at TIMESTAMP,
      email_opened_at TIMESTAMP,
      preview_viewed_at TIMESTAMP,
      cta_clicked_at TIMESTAMP,
      cta_contact_name VARCHAR(255),
      cta_contact_email VARCHAR(255),
      cta_contact_phone VARCHAR(50),
      cta_message TEXT,
      followup_1_sent_at TIMESTAMP,
      followup_2_sent_at TIMESTAMP,
      approved_by VARCHAR(100),
      approved_at TIMESTAMP,
      status VARCHAR(20) DEFAULT 'draft',
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS prospect_replies (
      id SERIAL PRIMARY KEY,
      prospect_id INTEGER REFERENCES enterprise_prospects(id),
      teaser_report_id INTEGER REFERENCES teaser_reports(id),
      message_id VARCHAR(255) UNIQUE,
      from_email VARCHAR(255),
      from_name VARCHAR(255),
      subject TEXT,
      body_text TEXT,
      received_at TIMESTAMP NOT NULL DEFAULT NOW(),
      is_handled BOOLEAN DEFAULT FALSE,
      handled_at TIMESTAMP,
      handled_by VARCHAR(100),
      handler_notes TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS enterprise_contracts (
      id SERIAL PRIMARY KEY,
      prospect_id INTEGER REFERENCES enterprise_prospects(id),
      customer_id INTEGER,
      contract_number VARCHAR(30) UNIQUE NOT NULL,
      company_name VARCHAR(255) NOT NULL,
      company_tax_id VARCHAR(50),
      company_tax_office VARCHAR(100),
      company_address TEXT,
      billing_contact_name VARCHAR(255),
      billing_contact_email VARCHAR(255),
      contract_type VARCHAR(30) DEFAULT 'annual',
      billing_cycle VARCHAR(20) DEFAULT 'annual',
      payment_method VARCHAR(30) DEFAULT 'bank_transfer',
      payment_terms INTEGER DEFAULT 30,
      start_date DATE NOT NULL,
      end_date DATE,
      total_amount_tl DECIMAL(12,2),
      discount_pct INTEGER DEFAULT 0,
      discount_reason VARCHAR(255),
      status VARCHAR(30) DEFAULT 'draft',
      sent_at TIMESTAMP,
      signed_at TIMESTAMP,
      signed_by VARCHAR(255),
      activated_at TIMESTAMP,
      activated_by VARCHAR(100),
      contract_pdf_path VARCHAR(500),
      signed_pdf_path VARCHAR(500),
      internal_notes TEXT,
      created_by VARCHAR(100),
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS enterprise_contract_services (
      id SERIAL PRIMARY KEY,
      contract_id INTEGER REFERENCES enterprise_contracts(id),
      service_slug VARCHAR(100) NOT NULL,
      service_name VARCHAR(255) NOT NULL,
      unit_price_tl DECIMAL(10,2) NOT NULL,
      quantity INTEGER DEFAULT 1,
      line_total_tl DECIMAL(10,2) NOT NULL,
      is_active BOOLEAN DEFAULT false,
      activated_at TIMESTAMP,
      expires_at TIMESTAMP,
      usage_limit INTEGER,
      usage_count INTEGER DEFAULT 0,
      notes VARCHAR(500),
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS enterprise_invoices (
      id SERIAL PRIMARY KEY,
      contract_id INTEGER REFERENCES enterprise_contracts(id),
      customer_id INTEGER,
      invoice_number VARCHAR(30) UNIQUE NOT NULL,
      period_start DATE,
      period_end DATE,
      subtotal_tl DECIMAL(12,2),
      vat_rate INTEGER DEFAULT 20,
      vat_amount_tl DECIMAL(12,2),
      total_tl DECIMAL(12,2),
      due_date DATE,
      paid_at TIMESTAMP,
      paid_amount_tl DECIMAL(12,2),
      status VARCHAR(20) DEFAULT 'pending',
      pdf_path VARCHAR(500),
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS lead_scan_queue (
      id SERIAL PRIMARY KEY,
      domain VARCHAR(255) NOT NULL,
      company_name VARCHAR(255),
      source VARCHAR(50),
      scan_status VARCHAR(20) DEFAULT 'pending',
      domain_scan_data JSONB,
      risk_score INTEGER,
      risk_level VARCHAR(20),
      critical_count INTEGER DEFAULT 0,
      high_count INTEGER DEFAULT 0,
      lead_score INTEGER,
      lead_score_factors JSONB,
      contacts JSONB,
      imported_at TIMESTAMP,
      imported_to_customer_id INTEGER,
      skipped_reason VARCHAR(255),
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      scanned_at TIMESTAMP
    )
  `);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_scan_queue ADD COLUMN IF NOT EXISTS ai_score_status VARCHAR(20)`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_scan_queue ADD COLUMN IF NOT EXISTS ai_score_retry_count INTEGER DEFAULT 0`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_scan_queue ADD COLUMN IF NOT EXISTS ai_score_last_retry_at TIMESTAMP`);
  // ─── WAF Post-Qualification Enrichment columns ────────────────────────────
  await db.execute(sql`ALTER TABLE lead_candidates ADD COLUMN IF NOT EXISTS waf_enriching_started_at TIMESTAMPTZ`);
  await db.execute(sql`ALTER TABLE lead_candidates ADD COLUMN IF NOT EXISTS waf_enriched_at TIMESTAMPTZ`);
  await db.execute(sql`ALTER TABLE lead_candidates ADD COLUMN IF NOT EXISTS waf_detected BOOLEAN`);
  await db.execute(sql`ALTER TABLE lead_candidates ADD COLUMN IF NOT EXISTS waf_provider VARCHAR(100)`);
  await db.execute(sql`ALTER TABLE lead_candidates ADD COLUMN IF NOT EXISTS waf_confidence INTEGER`);
  await db.execute(sql`ALTER TABLE lead_candidates ADD COLUMN IF NOT EXISTS waf_enrichment_attempts INTEGER NOT NULL DEFAULT 0`);
  await db.execute(sql`ALTER TABLE lead_candidates ADD COLUMN IF NOT EXISTS waf_enrichment_status VARCHAR(30)`);
  // Partial index: sadece enrichment bekleyen satırları kapsar — tablo büyüdükçe full scan önlenir.
  await db.execute(sql`CREATE INDEX IF NOT EXISTS idx_lead_candidates_waf_pending ON lead_candidates (id) WHERE waf_enriched_at IS NULL AND waf_enrichment_status IS DISTINCT FROM 'unknown_timeout'`);
  // .bel.tr domain pattern → city çıkarımı (garantili, AI maliyeti yok)
  // istanbul.bel.tr → Istanbul, ankara.bel.tr → Ankara vb.
  await db.execute(sql`
    UPDATE lead_candidates
    SET city = INITCAP(REPLACE(SPLIT_PART(domain, '.bel.tr', 1), '-', ' '))
    WHERE domain LIKE '%.bel.tr'
      AND SPLIT_PART(domain, '.bel.tr', 1) NOT LIKE '%.%'
      AND LENGTH(SPLIT_PART(domain, '.bel.tr', 1)) >= 2
      AND city IS NULL
  `);
  // ─── Haiku Enrichment kolonları ──────────────────────────────────────────────
  await db.execute(sql`ALTER TABLE lead_candidates ADD COLUMN IF NOT EXISTS enrichment_status VARCHAR(20) DEFAULT 'pending'`);
  await db.execute(sql`ALTER TABLE lead_candidates ADD COLUMN IF NOT EXISTS enrichment_method VARCHAR(50)`);
  await db.execute(sql`ALTER TABLE lead_candidates ADD COLUMN IF NOT EXISTS enrichment_confidence VARCHAR(10)`);
  await db.execute(sql`ALTER TABLE lead_candidates ADD COLUMN IF NOT EXISTS enrichment_attempted_at TIMESTAMPTZ`);
  await db.execute(sql`ALTER TABLE lead_candidates ADD COLUMN IF NOT EXISTS enrichment_completed_at TIMESTAMPTZ`);
  // Sektörü dolu olan (import/TLD/keyword kaynaklı) kayıtları 'enriched' say — Haiku tekrar işlemesin
  await db.execute(sql`
    UPDATE lead_candidates
    SET enrichment_status = 'enriched',
        enrichment_method = CASE
          WHEN sector_confidence = 'tld_rule'       THEN 'tld_pattern'
          WHEN sector_confidence = 'keyword_multi'  THEN 'keyword'
          WHEN sector_confidence = 'keyword_single' THEN 'keyword'
          ELSE 'import'
        END
    WHERE sector IS NOT NULL
      AND (enrichment_status IS NULL OR enrichment_status = 'pending')
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS contact_enrichment_log (
      id SERIAL PRIMARY KEY,
      customer_id INTEGER,
      domain VARCHAR(255),
      apollo_searched_at TIMESTAMP,
      apollo_contacts_found INTEGER DEFAULT 0,
      apollo_data JSONB,
      hunter_searched_at TIMESTAMP,
      hunter_emails_found INTEGER DEFAULT 0,
      hunter_data JSONB,
      linkedin_searched_at TIMESTAMP,
      linkedin_notes TEXT,
      selected_contact_name VARCHAR(255),
      selected_contact_title VARCHAR(100),
      selected_contact_email VARCHAR(255),
      selected_contact_phone VARCHAR(50),
      selected_contact_linkedin VARCHAR(500),
      selection_confidence VARCHAR(20),
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS sales_team (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      title VARCHAR(100),
      phone VARCHAR(50),
      is_active BOOLEAN DEFAULT true,
      monthly_target_tl DECIMAL(12,2),
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS lead_campaigns (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      target_sectors TEXT[],
      target_employee_min INTEGER,
      target_employee_max INTEGER,
      target_cities TEXT[],
      sources TEXT[],
      status VARCHAR(20) DEFAULT 'active',
      domains_found INTEGER DEFAULT 0,
      domains_scanned INTEGER DEFAULT 0,
      leads_imported INTEGER DEFAULT 0,
      deals_created INTEGER DEFAULT 0,
      deals_won INTEGER DEFAULT 0,
      created_by VARCHAR(100),
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      completed_at TIMESTAMP
    )
  `);
}

function startIsrImapCron() {
  cron.schedule("*/10 * * * *", wrapCron("isr_imap", "*/10 * * * *", async () => {
    try {
      const { processInbox } = await import("./services/isr-imap");
      await processInbox();
    } catch (err) {
      logger.error({ err }, "ISR IMAP cron error");
    }
  }), { timezone: "Europe/Istanbul" });
  logger.info("ISR IMAP poller scheduled (every 10 minutes)");

  // Teaser yanıt poller — her 15 dakikada bir (ISR IMAP ile farklı servis)
  cron.schedule("*/15 * * * *", wrapCron("teaser_reply_poll", "*/15 * * * *", async () => {
    try {
      const { pollTeaserReplies } = await import("./services/teaserReplyPoller");
      await pollTeaserReplies();
    } catch (err) {
      logger.error({ err }, "Teaser reply poller error");
    }
  }), { timezone: "Europe/Istanbul" });
  logger.info("Teaser reply poller scheduled (every 15 minutes)");

  // Teaser follow-up e-postaları — her gün 09:15 İstanbul
  cron.schedule("15 9 * * *", wrapCron("teaser_followup", "15 9 * * *", async () => {
    try {
      const { runFollowUpCron } = await import("./services/teaserFollowupService");
      await runFollowUpCron();
    } catch (err) {
      logger.error({ err }, "Teaser follow-up cron error");
    }
  }), { timezone: "Europe/Istanbul" });
  logger.info("Teaser follow-up cron scheduled (daily 09:15 Istanbul)");

  // D+3 — teaser gönderildi ama 3 gün geçti, hâlâ müşteri olmadı → ISR'ye hatırlatma
  cron.schedule("0 10 * * *", wrapCron("isr_leadgen_d3", "0 10 * * *", async () => {
    try {
      const { and, isNotNull, isNull, lte, gte } = await import("drizzle-orm");
      const { leadCandidatesTable } = await import("@workspace/db");
      const { sendMail } = await import("./services/email");
      const { buildFollowupReminderHtml } = await import("./lib/email-templates/isrEmails");
      const { getIsrEmail, getIsrBaseUrl } = await import("./lib/isr/teamConfig");

      const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);
      const fourDaysAgo  = new Date(Date.now() - 4 * 24 * 60 * 60 * 1000);

      const leads = await db.select().from(leadCandidatesTable).where(and(
        isNotNull(leadCandidatesTable.teaserSentAt),
        lte(leadCandidatesTable.teaserSentAt, threeDaysAgo),
        gte(leadCandidatesTable.teaserSentAt, fourDaysAgo),
        isNull(leadCandidatesTable.isrPromotedAt),
        isNull(leadCandidatesTable.isrFollowupD3SentAt),
      ));

      const baseUrl = getIsrBaseUrl();
      for (const lead of leads) {
        const isrEmail = getIsrEmail("isr-team");
        await sendMail({
          to: isrEmail,
          subject: `Takip Gerekli: ${lead.scrapedCompanyName ?? lead.domain} (3 gündür müşteri olmadı)`,
          html: buildFollowupReminderHtml({
            leadName: lead.scrapedCompanyName ?? lead.companyName ?? lead.domain,
            contactName: lead.contactName ?? null,
            contactEmail: lead.contactEmail ?? null,
            daysSinceSent: 3,
            riskScore: lead.riskScore ?? null,
            leadUrl: `${baseUrl}/panel/isr/leads`,
            action: "Telefon araması veya LinkedIn mesajı önerilir.",
          }),
        });
        await db.update(leadCandidatesTable)
          .set({ isrFollowupD3SentAt: new Date(), updatedAt: new Date() })
          .where(sql`${leadCandidatesTable.id} = ${lead.id}`);
      }
      logger.info({ count: leads.length }, "D+3 ISR leadgen followup tamamlandı");
    } catch (err) {
      logger.error({ err }, "ISR D+3 cron hatası");
    }
  }), { timezone: "Europe/Istanbul" });
  logger.info("ISR D+3 leadgen followup cron scheduled (daily 10:00 Istanbul)");

  // D+7 — teaser gönderildi, 7 gün geçti, hâlâ müşteri olmadı → adaya + ISR'ye
  cron.schedule("30 10 * * *", wrapCron("isr_leadgen_d7", "30 10 * * *", async () => {
    try {
      const { and, isNotNull, isNull, lte, gte } = await import("drizzle-orm");
      const { leadCandidatesTable } = await import("@workspace/db");
      const { sendMail } = await import("./services/email");
      const { buildD7FollowupHtml, buildFollowupReminderHtml } = await import("./lib/email-templates/isrEmails");
      const { getIsrEmail, getIsrBaseUrl } = await import("./lib/isr/teamConfig");

      const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      const eightDaysAgo = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000);

      const leads = await db.select().from(leadCandidatesTable).where(and(
        isNotNull(leadCandidatesTable.teaserSentAt),
        lte(leadCandidatesTable.teaserSentAt, sevenDaysAgo),
        gte(leadCandidatesTable.teaserSentAt, eightDaysAgo),
        isNull(leadCandidatesTable.isrPromotedAt),
        isNull(leadCandidatesTable.isrFollowupD7SentAt),
      ));

      const baseUrl = getIsrBaseUrl();
      for (const lead of leads) {
        const criticalFindings = lead.criticalFindings ?? 0;
        const urgencyNote = criticalFindings > 0
          ? `Raporunuzda ${criticalFindings} kritik bulgu bulunuyor — bu açıklar zaman geçtikçe daha riskli hale geliyor.`
          : "Güvenlik durumunuzu iyileştirmek için adımları görüntüleyin.";

        // 1. Adaya D+7 e-posta
        if (lead.contactEmail) {
          await sendMail({
            to: lead.contactEmail,
            subject: `${lead.scrapedCompanyName ?? lead.domain} — Güvenlik Raporunuz Hâlâ Sizi Bekliyor`,
            html: buildD7FollowupHtml({
              companyName: lead.scrapedCompanyName ?? lead.companyName ?? lead.domain,
              contactName: lead.contactName ?? null,
              domain: lead.domain,
              riskScore: lead.riskScore ?? null,
              urgencyNote,
            }),
          });
        }

        // 2. ISR ekibine bildirim
        const isrEmail = getIsrEmail("isr-team");
        await sendMail({
          to: isrEmail,
          subject: `D+7 Follow-up Gönderildi: ${lead.scrapedCompanyName ?? lead.domain}`,
          html: buildFollowupReminderHtml({
            leadName: lead.scrapedCompanyName ?? lead.companyName ?? lead.domain,
            contactName: lead.contactName ?? null,
            contactEmail: lead.contactEmail ?? null,
            daysSinceSent: 7,
            riskScore: lead.riskScore ?? null,
            leadUrl: `${baseUrl}/panel/isr/leads`,
            action: "Rapor açıldı, 7 gün geçti. Telefon araması zamanı.",
          }),
        });

        await db.update(leadCandidatesTable)
          .set({ isrFollowupD7SentAt: new Date(), updatedAt: new Date() })
          .where(sql`${leadCandidatesTable.id} = ${lead.id}`);
      }
      logger.info({ count: leads.length }, "D+7 ISR leadgen followup tamamlandı");
    } catch (err) {
      logger.error({ err }, "ISR D+7 cron hatası");
    }
  }), { timezone: "Europe/Istanbul" });
  logger.info("ISR D+7 leadgen followup cron scheduled (daily 10:30 Istanbul)");
}

// ─── Cron: Scan lead e-posta aktivasyon dizisi (her saat bir kez) ─────────────
function startScanLeadDripCron() {
  cron.schedule(
    "0 * * * *",
    wrapCron("scan_lead_drip", "0 * * * *", async () => {
      await runScanLeadDripCron();
    }),
    { timezone: "Europe/Istanbul" },
  );
  logger.info("Scan lead drip cron scheduled (hourly)");
}

function startLeadWebEnrichCron() {
  cron.schedule(
    "0 6 * * *",
    wrapCron("lead_web_enrich", "0 6 * * *", async () => {
      const { enrichLeadFromWeb } = await import("./services/leadDiscovery/webContentEnrichment");
      const leads = await db.execute(
        sql`SELECT id, domain FROM lead_candidates WHERE is_qualified = true AND web_scraped_at IS NULL LIMIT 40`,
      );
      const rows = leads.rows as Array<{ id: number; domain: string }>;
      let alive = 0;
      for (const lead of rows) {
        try {
          await enrichLeadFromWeb(lead.id, lead.domain);
          // brief pause to avoid hammering targets
          await new Promise((r) => setTimeout(r, 1500));
        } catch (err) {
          logger.warn({ id: lead.id, domain: lead.domain, err: String(err) }, "Web enrich single-lead hata");
        }
      }
      const aliveCount = await db.execute(
        sql`SELECT COUNT(*) as c FROM lead_candidates WHERE is_alive = true AND web_scraped_at IS NOT NULL`,
      );
      alive = Number((aliveCount.rows[0] as { c: string }).c ?? 0);
      logger.info({ total: rows.length, aliveTotal: alive }, "Lead web enrich cron tamamlandı");
      return rows.length;
    }),
    { timezone: "Europe/Istanbul" },
  );
  logger.info("Lead web enrich cron scheduled (daily 06:00 Istanbul)");
}

function startAiScoreRetryCron() {
  // Üstel backoff: retry_count=0→1h, 1→2h, 2→4h, 3→8h, 4+→16h (tavan)
  // Bu sayede kalıcı başarısızlıklar kotadan düşer, taze hatalar önce işlenir.
  cron.schedule(
    "45 * * * *",
    wrapCron("ai_score_retry", "45 * * * *", async () => {
      const { scoreLeadWithAI } = await import("./services/leadScoringService");
      const { leadScanQueueTable } = await import("@workspace/db");
      const { eq } = await import("drizzle-orm");
      // Backoff: bekleme = 2^min(retry_count,4) saat; az retry_count'lu kayıtlar önce seçilir
      const pending = await db.execute(
        sql`SELECT id, domain, company_name, domain_scan_data,
                   COALESCE(ai_score_retry_count, 0) AS retry_count
            FROM lead_scan_queue
            WHERE ai_score_status IN ('failed','timeout','rate_limited')
              AND COALESCE(ai_score_last_retry_at, scanned_at) <
                  NOW() - (POWER(2, LEAST(COALESCE(ai_score_retry_count,0), 4)) || ' hours')::INTERVAL
            ORDER BY COALESCE(ai_score_retry_count, 0) ASC, scanned_at ASC
            LIMIT 20`,
      );
      const rows = pending.rows as Array<{
        id: number;
        domain: string;
        company_name: string | null;
        domain_scan_data: Record<string, unknown> | null;
        retry_count: number;
      }>;
      let retried = 0, succeeded = 0;
      for (const row of rows) {
        try {
          const scanData = row.domain_scan_data ?? { domain: row.domain };
          const scored = await scoreLeadWithAI(row.domain, row.company_name, scanData);
          if (scored.status === "scored") {
            await db.update(leadScanQueueTable).set({
              scanStatus: "scored",
              leadScore: scored.score,
              leadScoreFactors: scored.factors,
              aiScoreStatus: "scored",
              aiScoreRetryCount: 0,
              aiScoreLastRetryAt: new Date(),
              scannedAt: new Date(),
            }).where(eq(leadScanQueueTable.id, row.id));
            succeeded++;
          } else {
            await db.update(leadScanQueueTable).set({
              aiScoreStatus: scored.status,
              aiScoreRetryCount: (row.retry_count ?? 0) + 1,
              aiScoreLastRetryAt: new Date(),
            }).where(eq(leadScanQueueTable.id, row.id));
          }
          retried++;
        } catch (err) {
          logger.warn({ err: String(err), id: row.id }, "AI score retry hata");
        }
      }
      logger.info({ retried, succeeded }, "AI score retry cron tamamlandı");
      return succeeded;
    }),
    { timezone: "Europe/Istanbul" },
  );
  logger.info("AI score retry cron scheduled (saatte bir, :45, üstel backoff)");
}

function startLeadTrEnrichCron() {
  cron.schedule(
    "30 7 * * *",
    wrapCron("lead_tr_enrich", "30 7 * * *", async () => {
      const { enrichLeadFromTrSources } = await import("./services/leadDiscovery/trSourcesEnrichment");
      const leads = await db.execute(
        sql`SELECT id, domain FROM lead_candidates WHERE is_qualified = true AND officer_name IS NULL LIMIT 50`,
      );
      const rows = leads.rows as Array<{ id: number; domain: string }>;
      let enriched = 0;
      for (const lead of rows) {
        const r = await enrichLeadFromTrSources(lead.id, lead.domain);
        if (r.officerName) enriched++;
      }
      logger.info({ total: rows.length, enriched }, "Lead TR enrich cron tamamlandı");
      return enriched;
    }),
    { timezone: "Europe/Istanbul" },
  );
  logger.info("Lead TR enrich cron scheduled (daily 07:30 Istanbul)");
}

function startFreeScanFollowupCron() {
  // ─── Ücretsiz tarama takip e-postası — her saat ──────────────────────────
  cron.schedule(
    "0 * * * *",
    wrapCron("free_scan_followup", "0 * * * *", async () => {
      const { runFreeScanFollowup } = await import("./services/free-scan-followup");
      return await runFreeScanFollowup();
    }),
    { timezone: "Europe/Istanbul" },
  );
  logger.info("Free scan followup cron scheduled (hourly)");
}

async function ensureAssessmentsColumns() {
  await db.execute(sql`ALTER TABLE IF EXISTS assessments ADD COLUMN IF NOT EXISTS tenant_id INTEGER`);
}

async function ensureBlogContentColumns() {
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS seo_title TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS seo_title_en TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS meta_description TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS meta_description_en TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS focus_keyword TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS focus_keyword_en TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS seo_tags JSONB DEFAULT '[]'`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS seo_tags_en JSONB DEFAULT '[]'`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS linkedin_post_tr TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS linkedin_post_en TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS instagram_carousel_tr JSONB DEFAULT '[]'`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS instagram_carousel_en JSONB DEFAULT '[]'`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS instagram_caption_tr TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS instagram_caption_en TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS visual_prompts_tr JSONB`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS visual_prompts_en JSONB`);
  await db.execute(sql`ALTER TABLE IF EXISTS blog_posts ADD COLUMN IF NOT EXISTS refs_json JSONB DEFAULT '[]'`);

  // Mevcut yayınlanmış yazılardaki [DOĞRULA: ...] placeholder'larını temizle
  await db.execute(sql`
    UPDATE blog_posts
    SET
      content         = regexp_replace(content,         '\[DOĞRULA:[^\]]*\]', '', 'gi'),
      excerpt         = regexp_replace(excerpt,         '\[DOĞRULA:[^\]]*\]', '', 'gi'),
      meta_description= regexp_replace(COALESCE(meta_description, ''), '\[DOĞRULA:[^\]]*\]', '', 'gi')
    WHERE
      content          ILIKE '%[DOĞRULA:%'
      OR excerpt       ILIKE '%[DOĞRULA:%'
      OR meta_description ILIKE '%[DOĞRULA:%'
  `);
}

async function ensureDomainScanEnrichmentColumns() {
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS http_headers_score INTEGER NOT NULL DEFAULT 0`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS http_headers_details JSONB DEFAULT '{}'`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS urlhaus_listed BOOLEAN NOT NULL DEFAULT false`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS urlhaus_threat TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS usom_listed BOOLEAN NOT NULL DEFAULT false`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS ct_subdomains JSONB NOT NULL DEFAULT '[]'`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS ct_subdomain_count INTEGER NOT NULL DEFAULT 0`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS cve_summary JSONB NOT NULL DEFAULT '[]'`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS shodan_open_ports JSONB`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS shodan_vuln_count INTEGER NOT NULL DEFAULT 0`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS shodan_country TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS shodan_isp TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS virustotal_reputation INTEGER`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS virustotal_malicious INTEGER NOT NULL DEFAULT 0`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS virustotal_suspicious INTEGER NOT NULL DEFAULT 0`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS abuseipdb_score INTEGER`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS abuseipdb_total_reports INTEGER NOT NULL DEFAULT 0`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS abuseipdb_country TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS abuseipdb_isp TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS safe_browsing_flagged BOOLEAN`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS safe_browsing_threats JSONB NOT NULL DEFAULT '[]'`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS ssl_labs_grade TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS badge_token TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS referral_source TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS kep_configured BOOLEAN`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS kep_relays JSONB NOT NULL DEFAULT '[]'::jsonb`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS kep_secure BOOLEAN`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS asn_number TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS asn_name TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS orphaned_assets JSONB`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS censys_related_hosts JSONB`);
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS censys_total_found INTEGER`);
}

async function updatePricingPlanFeatures() {
  await db.update(pricingPlansTable).set({
    features: [
      "20 soruluk hızlı risk değerlendirmesi",
      "5 güvenlik alanı (A-E)",
      "Anlık risk skoru ve seviyesi",
      "Kırmızı alarm tespiti",
      "Yapay zeka destekli temel rapor",
      "Domain tarama: SPF, DMARC, DKIM, MX, SSL",
      "HIBP veri sızıntısı kontrolü",
      "Kara liste ve Shadow IT tespiti",
    ],
  }).where(eq(pricingPlansTable.slug, "mini"));

  await db.update(pricingPlansTable).set({
    features: [
      "55 soruluk kapsamlı risk değerlendirmesi",
      "10 güvenlik alanı (A-J)",
      "Detaylı Gemini AI raporu",
      "Mini değerlendirmedeki tüm özellikler dahil",
      "HTTP güvenlik başlıkları analizi",
      "URLhaus & USOM zararlı alan taraması",
      "crt.sh Alt Alan Şeffaflığı (subdomain tespiti)",
      "NIST NVD CVE güvenlik açığı taraması",
      "VirusTotal domain reputation taraması",
      "AbuseIPDB IP kötüye kullanım geçmişi",
      "Shodan internet maruziyet taraması (ücretli)",
      "KVKK Madde 12 Teknik Tedbir Haritası",
      "NIST CSF 2.0 Uyum Seviyesi",
      "PDF rapor indirme",
      "30 günlük otomatik yeniden tarama bildirimi",
      "Sektörel karşılaştırma",
      "Birebir uzman danışmanlık görüşmesi (1 saat)",
    ],
  }).where(eq(pricingPlansTable.slug, "full"));
}

async function ensureReportEnrichmentColumns() {
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS estimated_breach_cost_min INTEGER`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS estimated_breach_cost_max INTEGER`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS risk_reduction_percent INTEGER`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS weekly_action_plan JSONB NOT NULL DEFAULT '[]'::jsonb`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS kvkk_penalty_min INTEGER`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS kvkk_penalty_max INTEGER`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS kvkk_risk_level TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS kvkk_risk_articles JSONB NOT NULL DEFAULT '[]'::jsonb`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS kvkk_risk_summary TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS sector_benchmark_percent INTEGER`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS sector_benchmark_comment TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS verbis_required BOOLEAN`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS verbis_risk_level TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS verbis_steps JSONB NOT NULL DEFAULT '[]'::jsonb`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS insurance_readiness_percent INTEGER`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS insurance_gaps JSONB NOT NULL DEFAULT '[]'::jsonb`);
}

async function ensureSecurityAdvisoriesTable() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS security_advisories (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT 'manual',
      link TEXT,
      summary TEXT,
      severity TEXT DEFAULT 'medium',
      sector TEXT,
      published_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (title, source)
    )
  `);
  const res = await db.execute(sql`SELECT COUNT(*) as cnt FROM security_advisories`);
  const cnt = Number((res.rows[0] as Record<string, unknown>)["cnt"] ?? 0);
  if (cnt === 0) {
    const daysAgo = (d: number) => new Date(Date.now() - d * 86_400_000);
    const seeds = [
      { title: "Türkiye Geneli KOBİ'lere Yönelik Fidye Yazılım Saldırıları Artıyor", source: "USOM", summary: "Türkiye genelinde küçük ve orta ölçekli işletmeleri hedef alan fidye yazılım saldırılarında belirgin artış gözlemlenmektedir. Güncel yedek alınması ve e-posta filtrelerinin güncellenmesi kritik önem taşımaktadır.", severity: "high", published_at: daysAgo(2) },
      { title: "İş E-postası Ele Geçirme (BEC) Saldırıları: IBAN Değişikliği Dolandırıcılığı", source: "BTK", summary: "Muhasebe ve finans çalışanlarını hedef alan sosyal mühendislik saldırılarında artış görülmektedir. IBAN değişiklik taleplerini her zaman telefon ile doğrulayın.", severity: "high", published_at: daysAgo(5) },
      { title: "Microsoft: Windows Defender SmartScreen Kritik Güvenlik Açığı (CVE-2024-21412)", source: "Microsoft", summary: "Windows Defender SmartScreen bileşeninde güvenlik filtrelerini atlayan kritik açık tespit edildi. Tüm Windows sistemlerin güncellenmesi gerekmektedir.", severity: "critical", published_at: daysAgo(8) },
      { title: "Phishing Kampanyası: Türk Bankalarını Taklit Eden Sahte E-postalar", source: "USOM", summary: "Türk bankalarının adını kullanan kimlik avı e-postaları tespit edildi. Banka bağlantılarını e-postadan değil tarayıcıdan doğrudan açın.", severity: "medium", published_at: daysAgo(12) },
    ];
    for (const s of seeds) {
      await db.execute(sql`
        INSERT INTO security_advisories (title, source, summary, severity, published_at)
        VALUES (${s.title}, ${s.source}, ${s.summary}, ${s.severity}, ${s.published_at})
        ON CONFLICT DO NOTHING
      `);
    }
    logger.info("Security advisories demo data seeded");
  }
}

async function ensureEmailTables() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS email_templates (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      description TEXT,
      category TEXT NOT NULL DEFAULT 'custom',
      subject TEXT NOT NULL,
      body_html TEXT NOT NULL,
      body_text TEXT,
      variables JSONB DEFAULT '[]',
      is_default BOOLEAN NOT NULL DEFAULT false,
      is_active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS email_sends (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER NOT NULL,
      template_id INTEGER,
      to_email TEXT NOT NULL,
      to_name TEXT,
      subject TEXT NOT NULL,
      body_html TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'sent',
      related_type TEXT,
      related_id INTEGER,
      error TEXT,
      sent_at TIMESTAMP DEFAULT NOW(),
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
}

// ─── Startup: demo müşteri hesabını oluştur (yoksa veya şifre yanlışsa) ───────
async function maybeSeedDemoCustomer() {
  const DEMO_EMAIL = "demo@cyberstep.io";
  const DEMO_PASSWORD = "Demo2024!";

  const [existing] = await db.select({ id: customersTable.id, passwordHash: customersTable.passwordHash })
    .from(customersTable)
    .where(eq(customersTable.email, DEMO_EMAIL));

  const correctHash = "$2b$12$KRWNZYbJaAvqMH8GoDhJteL830QrbCj3oa.cNwew0XkGEH5UACZsy";

  if (!existing) {
    await db.insert(customersTable).values({
      email: DEMO_EMAIL,
      passwordHash: correctHash,
      fullName: "Demo Kullanici",
      companyName: "Demo Sirket",
    });
    logger.info("Demo customer created");
    return;
  }

  // Şifre hash'i yanlışsa güncelle
  const ok = await bcrypt.compare(DEMO_PASSWORD, existing.passwordHash);
  if (!ok) {
    await db.update(customersTable)
      .set({ passwordHash: correctHash, updatedAt: new Date() })
      .where(eq(customersTable.id, existing.id));
    logger.info("Demo customer password reset to Demo2024!");
  }
}

async function maybeSeedPaidTestCustomer() {
  const TEST_EMAIL = "test@cyberstep.io";
  const TEST_HASH = "$2b$12$l/8PXqA3HJIDhY9igm5BSugQMPcpvqXE47nMN.Hdb72o43IwigVzq";

  const [existing] = await db.select({ id: customersTable.id, subscriptionPlan: customersTable.subscriptionPlan })
    .from(customersTable)
    .where(eq(customersTable.email, TEST_EMAIL));

  if (!existing) {
    await db.insert(customersTable).values({
      email: TEST_EMAIL,
      passwordHash: TEST_HASH,
      fullName: "Test Kullanici",
      companyName: "CyberStep Test A.S.",
      subscriptionPlan: "full",
      subscriptionStatus: "active",
    });
    logger.info("Paid test customer created: test@cyberstep.io");
    return;
  }

  if (existing.subscriptionPlan !== "full") {
    await db.update(customersTable)
      .set({ subscriptionPlan: "full", subscriptionStatus: "active", updatedAt: new Date() })
      .where(eq(customersTable.id, existing.id));
    logger.info("Paid test customer plan upgraded to full");
  }
}

async function seedBlogPosts() {
  const [{ cnt }] = await db.select({ cnt: count() })
    .from(blogPostsTable)
    .where(eq(blogPostsTable.slug, "kobi-siber-guvenlik-temel-onlemler"));
  if (Number(cnt) > 0) return;

  const now = new Date();
  const posts = [
    {
      slug: "kobi-siber-guvenlik-temel-onlemler",
      title: "KOBİ'ler İçin 10 Temel Siber Güvenlik Önlemi",
      excerpt: "Küçük ve orta ölçekli işletmelerin siber saldırılara karşı hemen alabileceği, düşük maliyetli ama yüksek etkili 10 güvenlik adımı.",
      content: `<h2>Neden KOBİ'ler Hedef Alınıyor?</h2>
<p>Siber saldırganlar büyük şirketleri değil, daha kolay hedefleri tercih eder. KOBİ'lerin %43'ü her yıl siber saldırıya uğruyor; ancak bunların yalnızca %14'ü savunmaya yeterince hazırlıklı. Sebebi basit: büyük kurumsal güvenlik bütçesi olmaksızın dijital varlıklar korunmaya çalışılıyor.</p>
<p>İyi haber şu ki temel güvenlik önlemlerinin büyük çoğunluğu ücretsiz ya da çok düşük maliyetlidir ve teknik bilgi gerektirmez.</p>
<h2>1. Güçlü ve Benzersiz Parolalar Kullanın</h2>
<p>Her hesap için farklı, en az 12 karakter uzunluğunda bir parola belirleyin. Rakam, büyük-küçük harf ve özel karakter içermeli. Bitwarden veya KeePass gibi ücretsiz bir parola yöneticisi bu işi kolaylaştırır.</p>
<h2>2. İki Faktörlü Kimlik Doğrulama (2FA) Açın</h2>
<p>E-posta, banka ve bulut sistemlerinizde 2FA'yı etkinleştirin. SMS yerine Google Authenticator veya Authy gibi bir uygulama kullanmak çok daha güvenlidir.</p>
<h2>3. Yazılımları Güncel Tutun</h2>
<p>Yamalar çıktıkça güncelleyin. Siber saldırıların %60'ı bilinen güvenlik açıklarını hedef alır ve bu açıkların çoğu aylar önce kapatılmıştır — yalnızca güncelleme yapılmamıştır.</p>
<h2>4. E-posta Filtrelerinizi Yapılandırın</h2>
<p>SPF, DKIM ve DMARC kayıtlarını DNS'inize ekleyin. Bu üç kayıt, alan adınızın sahte e-postalarda kullanılmasını engelleyen en temel korumadır.</p>
<h2>5. Çalışanlarınızı Eğitin</h2>
<p>Phishing saldırıları hâlâ en yaygın giriş noktası. Yılda en az bir kez bilinçlendirme eğitimi yapın; çalışanlarınıza şüpheli e-postaları nasıl tanıyacaklarını öğretin.</p>
<h2>6. Düzenli Yedekleme Yapın</h2>
<p>3-2-1 kuralını uygulayın: 3 kopya, 2 farklı ortam, 1 kopya tesis dışında. Yedekleri en az haftada bir test edin.</p>
<h2>7. Wi-Fi Ağınızı Ayırın</h2>
<p>Misafir, iş ve IoT cihazları için ayrı ağ segmentleri oluşturun. Yazıcı veya kameranız saldırıya uğrasa bile diğer sistemleriniz korunmuş olur.</p>
<h2>8. Antivirüs ve EDR Kullanın</h2>
<p>Ücretsiz antivirüsler temel koruma sağlar; ancak orta ve büyük KOBİ'ler için EDR (Endpoint Detection and Response) çözümleri çok daha etkilidir.</p>
<h2>9. Erişim Yetkilerini Sınırlayın</h2>
<p>Her çalışana yalnızca işini yapabilmesi için gereken en az yetkiyi verin. Ayrılan çalışanların erişimlerini aynı gün kapatın.</p>
<h2>10. Risk Değerlendirmesi Yaptırın</h2>
<p>Yılda en az bir kez profesyonel bir siber güvenlik risk değerlendirmesi yapın. CyberStep.io'nun ücretsiz Mini Değerlendirme aracıyla 10 dakikada mevcut durumunuzu öğrenebilirsiniz.</p>
<h2>Sonuç</h2>
<p>Siber güvenlik bir kerelik yapılıp biten bir proje değil, sürekli bir süreçtir. Yukarıdaki 10 adımı hayata geçirerek saldırganların büyük çoğunluğunu engellemiş olursunuz. Küçük adımlar, büyük fark yaratır.</p>`,
      authorName: "CyberStep.io",
      status: "published",
      publishedAt: new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000),
      readingMinutesTr: 5,
      readingMinutesEn: 5,
    },
    {
      slug: "kvkk-uyumlulugu-kobi-rehberi",
      title: "KVKK Uyumluluğu: KOBİ'ler İçin Adım Adım Rehber",
      excerpt: "Kişisel Verilerin Korunması Kanunu kapsamında KOBİ'lerin yerine getirmesi gereken yükümlülükler ve pratik uygulama adımları.",
      content: `<h2>KVKK Nedir ve KOBİ'leri Neden İlgilendiriyor?</h2>
<p>6698 sayılı Kişisel Verilerin Korunması Kanunu (KVKK), çalışan, müşteri veya tedarikçi verisi işleyen her kuruluşu kapsar. Şirket büyüklüğünden bağımsız olarak kişisel veri işliyorsanız KVKK'ya tabissiniz. İhlaller için 1 milyon TL'ye kadar idari para cezası söz konusu olabilir.</p>
<h2>Hangi Veriler "Kişisel Veri" Sayılır?</h2>
<p>Ad-soyad, T.C. kimlik numarası, e-posta adresi, telefon numarası, konum verisi, IP adresi ve daha fazlası kişisel veri kapsamındadır. Sağlık, din ve biyometrik veriler ise "özel nitelikli kişisel veri" olarak çok daha sıkı kurallara tabidir.</p>
<h2>KOBİ'ler İçin 5 Temel Adım</h2>
<h3>1. Veri Envanteri Çıkarın</h3>
<p>Hangi verileri topladığınızı, nerede sakladığınızı, kimlerle paylaştığınızı ve ne kadar süre tuttuğunuzu bir tabloda belgeleyin. Bu "Veri İşleme Envanteri" KVKK'nın temel belgesidir.</p>
<h3>2. Aydınlatma Metinlerini Hazırlayın</h3>
<p>Müşterilerinize, çalışanlarınıza ve tedarikçilerinize hangi verileri neden topladığınızı açıklayan aydınlatma metinleri hazırlayın. Bu metinler web sitenizde, sözleşmelerde ve başvuru formlarında yer almalıdır.</p>
<h3>3. Açık Rıza Yönetimi Kurun</h3>
<p>Pazarlama e-postaları veya çerezler gibi rızaya dayalı işlemler için açık onay alın ve bu onayları kayıt altında tutun.</p>
<h3>4. Teknik Önlemler Alın</h3>
<p>Kişisel verileri şifreleyin, erişim yetkilerini kısıtlayın ve düzenli güvenlik testleri yapın. KVKK yalnızca hukuki değil, teknik uyum da ister.</p>
<h3>5. İhlal Bildirimi Prosedürü Oluşturun</h3>
<p>Veri ihlali durumunda 72 saat içinde Kişisel Verileri Koruma Kurumu'na (KVKK) bildirim yapmanız gerekiyor. Bu prosedürü önceden hazırlayın.</p>
<h2>Ceza Riski Gerçek Mi?</h2>
<p>Evet. Kurul, 2023 yılında yüzlerce şirkete toplamda onlarca milyon TL para cezası kesti. KOBİ'ler de bu denetimlerden muaf değil. Ancak uyum belgesi oluşturmuş ve iyi niyet gösteren şirketlere verilen cezaların çok daha düşük olduğu gözlemleniyor.</p>
<h2>Neden Şimdi Başlamalısınız?</h2>
<p>KVKK uyumu bir defada tamamlanan bir proje değildir; devam eden bir süreçtir. Ne kadar erken başlarsanız, olası denetimde o kadar güçlü konumda olursunuz. CyberStep.io'nun risk değerlendirme aracı KVKK'ya dair açık noktalarınızı tespit etmenize yardımcı olur.</p>`,
      authorName: "CyberStep.io",
      status: "published",
      publishedAt: new Date(now.getTime() - 14 * 24 * 60 * 60 * 1000),
      readingMinutesTr: 6,
      readingMinutesEn: 6,
    },
    {
      slug: "fidye-yazilimi-saldirilarindan-korunma",
      title: "Fidye Yazılımı Saldırıları: İşletmenizi Nasıl Korursunuz?",
      excerpt: "Ransomware saldırıları KOBİ'leri giderek daha fazla hedef alıyor. Saldırı nasıl gerçekleşir, nasıl önlenir ve saldırı sonrası ne yapılır?",
      content: `<h2>Fidye Yazılımı Nedir?</h2>
<p>Fidye yazılımı (ransomware), sisteminize sızan ve dosyalarınızı şifreleyerek erişiminizi engelleyen bir kötü amaçlı yazılım türüdür. Saldırganlar, dosyaları geri vermek için genellikle kripto para cinsinden fidye talep eder. Ödeme yapsanız bile verilerinizi geri almanızın garantisi yoktur.</p>
<h2>KOBİ'ler Neden Özellikle Risk Altında?</h2>
<p>2023 verilerine göre fidye yazılımı saldırılarının %82'si 1.000'den az çalışana sahip şirketleri hedef aldı. Sebep açık: büyük şirketlere kıyasla daha zayıf savunma, ama yeterince değerli veri ve ödeme kapasitesi.</p>
<h2>Saldırı Nasıl Gerçekleşir?</h2>
<p>En yaygın giriş noktaları şunlardır:</p>
<ul>
<li><strong>Phishing e-postaları:</strong> Sahte fatura, kargo bildirimi veya iş teklifi görünümlü e-postalar</li>
<li><strong>Uzak masaüstü (RDP) açıkları:</strong> Zayıf parola veya yama yapılmamış RDP portları</li>
<li><strong>Yazılım açıkları:</strong> Güncellenmemiş işletim sistemi veya uygulamalar</li>
<li><strong>Tedarikçi zinciri saldırıları:</strong> Güvendiğiniz bir tedarikçi üzerinden giriş</li>
</ul>
<h2>Önleme Stratejileri</h2>
<h3>Yedekleme — En Kritik Savunma</h3>
<p>3-2-1 yedekleme kuralını uygulayın: en az 3 kopya, 2 farklı ortam, 1 kopya çevrimdışı veya bulutta izole. Yedekleri haftada bir test edin. Fidye yazılımı bulaştıktan sonra tek kurtuluş yolunuz temiz yedektir.</p>
<h3>E-posta Güvenliği</h3>
<p>SPF, DKIM, DMARC kayıtlarını yapılandırın. E-posta filtreleme çözümü kullanın. Çalışanlarınızı phishing simülasyonlarıyla eğitin.</p>
<h3>Yama Yönetimi</h3>
<p>İşletim sistemleri ve uygulamaları otomatik güncelleyin. RDP portu varsa VPN arkasına alın veya kapatın.</p>
<h3>Ağ Segmentasyonu</h3>
<p>Kritik sistemleri ayrı ağ segmentlerinde tutun. Böylece bir cihaz bulaşsa bile tüm sisteme yayılmasını yavaşlatabilirsiniz.</p>
<h2>Saldırı Gerçekleşirse Ne Yapmalısınız?</h2>
<ol>
<li><strong>Sistemi izole edin:</strong> Etkilenen cihazları ağdan hemen kesin</li>
<li><strong>Fidye ödemeyin:</strong> Ödeme, dosyaların geri geleceğini garantilemez ve sizi tekrar hedef yapar</li>
<li><strong>Yetkililere bildirin:</strong> BTK ve KVKK'ya bildirim zorunluluğunuz olabilir</li>
<li><strong>Yedekten geri yükleyin:</strong> Temiz yedekten sistemleri sıfırdan kurun</li>
<li><strong>Forensic analiz yaptırın:</strong> Giriş noktasını tespit etmeden sistemi açmayın</li>
</ol>
<h2>Sonuç</h2>
<p>Fidye yazılımına karşı %100 güvenli bir sistem yoktur. Ancak doğru önlemlerle saldırıyı çok daha zorlaştırabilir ve saldırı gerçekleşse bile zararı minimize edebilirsiniz. Güçlü yedekleme + e-posta güvenliği + çalışan eğitimi üçlüsü, en etkili savunma hattını oluşturur.</p>`,
      authorName: "CyberStep.io",
      status: "published",
      publishedAt: new Date(now.getTime() - 21 * 24 * 60 * 60 * 1000),
      readingMinutesTr: 7,
      readingMinutesEn: 7,
    },
    {
      slug: "e-posta-guvenligi-spf-dmarc-dkim",
      title: "E-posta Güvenliği: SPF, DKIM ve DMARC Nedir, Nasıl Kurulur?",
      excerpt: "İşletme e-postanızın sahte gönderilere karşı korunması için kritik üç DNS kaydı — SPF, DKIM ve DMARC — adım adım açıklaması.",
      content: `<h2>E-posta Sahteciliği (Spoofing) Nedir?</h2>
<p>E-posta sahteciliği, bir saldırganın sizin alan adınızı (@sirketiniz.com) kullanarak sanki sizden gönderiliyormuş gibi e-posta göndermesidir. Bu teknik; müşterilerinizi kandırmak, tedarikçilerle sahte fatura iletişimi kurmak veya çalışanlarınızı hedef almak için kullanılır. İyi haber: SPF, DKIM ve DMARC kayıtlarıyla bu saldırıların büyük çoğunluğunu önleyebilirsiniz.</p>
<h2>SPF (Sender Policy Framework)</h2>
<p>SPF, alan adınız adına e-posta göndermeye yetkili IP adreslerini listeleyen bir DNS kaydıdır. Alıcı sunucu, e-posta geldiğinde "Bu IP adresine bu alan adı adına e-posta gönderme izni var mı?" diye kontrol eder.</p>
<p><strong>Örnek SPF kaydı:</strong></p>
<pre><code>v=spf1 include:_spf.google.com include:mail.sirketiniz.com ~all</code></pre>
<p>TXT kaydı olarak DNS'inize ekleyin. <code>~all</code> "yumuşak ret" (soft fail), <code>-all</code> ise "sert ret" (hard fail) anlamına gelir. Başlangıç için <code>~all</code> önerilir.</p>
<h2>DKIM (DomainKeys Identified Mail)</h2>
<p>DKIM, e-postanın gönderilirken kriptografik olarak imzalanmasını sağlar. Alıcı sunucu bu imzayı doğrulayarak e-postanın yolda değiştirilmediğini ve gerçekten sizin sunucunuzdan geldiğini teyit eder.</p>
<p>E-posta servis sağlayıcınız (Google Workspace, Microsoft 365, vb.) DKIM anahtarlarını sizin için oluşturur. Sağlayıcınızın yönetim panelinden "DKIM" ayarlarına girerek oluşturulan TXT kaydını DNS'inize ekleyin.</p>
<h2>DMARC (Domain-based Message Authentication)</h2>
<p>DMARC, SPF ve DKIM'den birinin başarısız olması durumunda ne yapılacağını tanımlar. Ayrıca size raporlama imkânı sunar.</p>
<p><strong>Örnek DMARC kaydı:</strong></p>
<pre><code>v=DMARC1; p=quarantine; rua=mailto:dmarc-raporlar@sirketiniz.com; pct=100</code></pre>
<p><code>_dmarc.sirketiniz.com</code> adıyla TXT kaydı olarak ekleyin.</p>
<ul>
<li><code>p=none</code> — sadece raporla, aksiyon alma (başlangıç için ideal)</li>
<li><code>p=quarantine</code> — başarısız e-postaları spam klasörüne gönder</li>
<li><code>p=reject</code> — başarısız e-postaları tamamen reddet (hedef politika)</li>
</ul>
<h2>Doğrulama Adımları</h2>
<ol>
<li>MXToolbox.com adresinden alan adınızın SPF, DKIM ve DMARC kayıtlarını kontrol edin</li>
<li>CyberStep.io'nun Alan Tarama aracıyla e-posta güvenlik skorunuzu görün</li>
<li>DMARC raporlarını birkaç hafta izleyin, ardından politikayı <code>reject</code>'e yükseltin</li>
</ol>
<h2>Ne Kadar Sürer?</h2>
<p>Teknik bilgiye sahip biri için SPF ve DMARC kurulumu 15-30 dakika alır. DKIM, e-posta sağlayıcınıza göre değişir ancak genellikle bir saatten fazla sürmez. Yayılma (propagation) için 24-48 saat beklenebilir.</p>
<h2>Sonuç</h2>
<p>Bu üç kayıt, e-posta güvenliğinin temel katmanını oluşturur ve tamamen ücretsizdir. Kurulu olmayan her alan adı, saldırganların kolayca kullanabileceği açık bir kapı bırakmaktadır. Alan adınızın durumunu hemen kontrol edin.</p>`,
      authorName: "CyberStep.io",
      status: "published",
      publishedAt: new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000),
      readingMinutesTr: 6,
      readingMinutesEn: 6,
    },
  ];

  for (const p of posts) {
    await db.insert(blogPostsTable).values({
      title: p.title,
      slug: p.slug,
      excerpt: p.excerpt,
      content: p.content,
      authorName: p.authorName,
      status: p.status,
      publishedAt: p.publishedAt,
    });
  }
  logger.info({ count: posts.length }, "Blog seed: inserted starter posts");
}

async function ensurePartnerEcosystemTables() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS partners (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER,
      company_name TEXT NOT NULL,
      contact_name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      phone TEXT,
      website TEXT,
      categories TEXT[] DEFAULT '{}',
      tier TEXT NOT NULL DEFAULT 'silver',
      status TEXT NOT NULL DEFAULT 'pending',
      monthly_fee INTEGER DEFAULT 0,
      subscription_status TEXT DEFAULT 'trial',
      password_hash TEXT,
      description TEXT,
      total_projects_completed INTEGER DEFAULT 0,
      total_revenue INTEGER DEFAULT 0,
      rating INTEGER,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      approved_at TIMESTAMP
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS work_packages (
      id SERIAL PRIMARY KEY,
      tenant_id INTEGER,
      assessment_id INTEGER,
      domain_scan_id INTEGER,
      title TEXT NOT NULL,
      description TEXT,
      category TEXT NOT NULL,
      priority TEXT NOT NULL DEFAULT 'medium',
      estimated_cost INTEGER,
      commission_rate INTEGER DEFAULT 15,
      status TEXT NOT NULL DEFAULT 'open',
      partner_id INTEGER,
      assigned_at TIMESTAMP,
      completed_at TIMESTAMP,
      verified_at TIMESTAMP,
      completion_note TEXT,
      score_before INTEGER,
      score_after INTEGER,
      company_name TEXT,
      domain TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
}

async function ensurePasswordResetColumns() {
  await db.execute(sql`ALTER TABLE IF EXISTS customers ADD COLUMN IF NOT EXISTS password_reset_token TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS customers ADD COLUMN IF NOT EXISTS password_reset_expires_at TIMESTAMP`);
}

async function ensureReferralCodeColumn() {
  await db.execute(sql`ALTER TABLE IF EXISTS assessments ADD COLUMN IF NOT EXISTS referral_code TEXT`);
}

async function ensureAiCostLogTable() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS ai_cost_log (
      id            SERIAL PRIMARY KEY,
      service       VARCHAR(100) NOT NULL,
      model         VARCHAR(100) NOT NULL,
      input_tokens  INTEGER NOT NULL DEFAULT 0,
      output_tokens INTEGER NOT NULL DEFAULT 0,
      cost_usd      NUMERIC(12,8) NOT NULL DEFAULT 0,
      customer_id   INTEGER,
      metadata      JSONB,
      recorded_at   TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`CREATE INDEX IF NOT EXISTS ai_cost_log_service_date_idx ON ai_cost_log (service, recorded_at DESC)`);
  await db.execute(sql`CREATE INDEX IF NOT EXISTS ai_cost_log_date_idx ON ai_cost_log (recorded_at DESC)`);
}

async function ensureLeadCandidatesExtraColumns() {
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS officer_name VARCHAR(255)`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS officer_title VARCHAR(100)`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS isr_notes TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS isr_followup_d3_sent_at TIMESTAMP`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS isr_followup_d7_sent_at TIMESTAMP`);
}

async function ensureWebEnrichColumns() {
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS http_status INTEGER`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS is_alive BOOLEAN`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS response_time_ms INTEGER`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS scraped_phone VARCHAR(50)`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS scraped_address TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS scraped_company_name VARCHAR(255)`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS web_scraped_at TIMESTAMP`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS isr_promoted_at TIMESTAMP`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS isr_customer_id INTEGER REFERENCES isr_customers(id) ON DELETE SET NULL`);
}

async function ensureLeadCandidatesTierColumns() {
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS tier VARCHAR(20) DEFAULT 'tier3'`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS last_scanned_at TIMESTAMP`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS scan_depth VARCHAR(20) DEFAULT 'lightweight'`);
  await db.execute(sql`ALTER TABLE IF EXISTS lead_candidates ADD COLUMN IF NOT EXISTS needs_manual_contact BOOLEAN DEFAULT false`);
  await db.execute(sql`CREATE INDEX IF NOT EXISTS idx_lead_candidates_tier ON lead_candidates (tier)`);
  await db.execute(sql`
    UPDATE lead_candidates SET tier = 'tier1', last_scanned_at = updated_at, scan_depth = 'full'
    WHERE scan_status = 'scanned' AND is_qualified = true AND tier IS NULL
  `);
  await db.execute(sql`
    UPDATE lead_candidates SET tier = 'tier2', last_scanned_at = updated_at, scan_depth = 'full'
    WHERE scan_status = 'scanned' AND is_qualified = false AND tier IS NULL
  `);
  await db.execute(sql`
    UPDATE lead_candidates SET tier = 'tier3'
    WHERE scan_status IN ('pending', 'failed') AND tier IS NULL
  `);
  // 'prescreening' durumunda kalan adayları 'pending'e döndür (crash recovery).
  await db.execute(sql`
    UPDATE lead_candidates SET scan_status = 'pending', updated_at = now()
    WHERE scan_status = 'prescreening'
  `);
  await db.execute(sql`
    UPDATE lead_candidates SET needs_manual_contact = true
    WHERE is_qualified = true AND contact_email IS NULL AND needs_manual_contact = false
  `);
}

async function ensurePerformanceIndexes() {
  await db.execute(sql`CREATE INDEX IF NOT EXISTS domain_scans_email_idx ON domain_scans (email)`);
  await db.execute(sql`CREATE INDEX IF NOT EXISTS domain_scans_created_at_idx ON domain_scans (created_at DESC)`);
  await db.execute(sql`CREATE INDEX IF NOT EXISTS assessments_email_idx ON assessments (email)`);
  await db.execute(sql`CREATE INDEX IF NOT EXISTS fabric_events_customer_id_idx ON fabric_events (customer_id)`);
  await db.execute(sql`CREATE INDEX IF NOT EXISTS fabric_events_created_at_idx ON fabric_events (created_at DESC)`);
  await db.execute(sql`CREATE INDEX IF NOT EXISTS domain_scans_overall_score_idx ON domain_scans (overall_score)`);
}

async function ensureBreachMonitorTable() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS breach_monitor_requests (
      id          SERIAL PRIMARY KEY,
      domain      TEXT NOT NULL,
      ip_hash     TEXT NOT NULL,
      breach_count INTEGER NOT NULL DEFAULT 0,
      queried_at  TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`CREATE INDEX IF NOT EXISTS breach_monitor_domain_idx ON breach_monitor_requests (domain)`);
}

async function ensureVerificationColumns() {
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS verified_at TIMESTAMP`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS verification_expires_at TIMESTAMP`);
  await db.execute(sql`ALTER TABLE IF EXISTS reports ADD COLUMN IF NOT EXISTS verification_duration_years INTEGER`);
}

async function ensureDomainScanLimitColumn() {
  await db.execute(sql`ALTER TABLE IF EXISTS customers ADD COLUMN IF NOT EXISTS domain_scan_limit INTEGER`);
}

async function ensureBadgeAdvantagesTable() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS badge_advantages (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      partner_name TEXT NOT NULL,
      description TEXT NOT NULL,
      discount_percent INTEGER,
      badge_text TEXT,
      logo_url TEXT,
      is_active BOOLEAN NOT NULL DEFAULT true,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
}

async function startup() {
  await maybeResetAdminPassword();
  await ensureAssessmentsColumns();
  await ensureQuestionsTable();
  await ensureTenantsTable();
  await ensureIsrTables();
  await ensureEmailTables();
  await maybeSeedPricingPlans();
  await maybeSeedQuestions();
  const { maybeSeedServiceCatalog } = await import("./services/service-catalog-seed");
  await maybeSeedServiceCatalog();
  await maybeSeedDemoCustomer();
  await maybeSeedPaidTestCustomer();
  await ensureBlogContentColumns();
  await ensureDomainScanEnrichmentColumns();
  await ensureReportEnrichmentColumns();
  await ensureSecurityAdvisoriesTable();
  await updatePricingPlanFeatures();
  await ensurePartnerEcosystemTables();
  await seedBlogPosts();
  await ensureVerificationColumns();
  await ensureBadgeAdvantagesTable();
  await ensureDomainScanLimitColumn();
  await ensurePasswordResetColumns();
  await ensureBreachMonitorTable();
  await ensureReferralCodeColumn();
  await ensureDomainScanPurchasesTable();
  await ensureAiCostLogTable();
  setAiCostLogger(({ task, model, inputTokens, outputTokens, cacheType }) => {
    logAiCost({ task, service: task, model, inputTokens, outputTokens, cacheType }).catch(() => {});
  });
  await ensurePerformanceIndexes();
  await ensureDnsTables();
  await ensureCtTable();
  await ensureMs365Tables();
  await ensureCustomerServiceConfigsTable();
  await ensureKvkkTables();
  await ensureServiceNowTables();
  await ensureWebhookTables();
  await ensureTelegramTables();
  await ensureNetgsmTables();
  await ensureNewsItemColumns();
  await ensureOnboardingEmailColumns();
  await ensureBadgeAndEmergingColumns();
  await ensureTechDiscoveryTable();
  await ensureIspTables();
  await ensureLeadCandidatesExtraColumns();
  await ensureWebEnrichColumns();
  await ensureLeadCandidatesTierColumns();
  await db.execute(sql`ALTER TABLE IF EXISTS domain_scans ADD COLUMN IF NOT EXISTS redirected_to TEXT`);
  await ensureSocialMediaTables();
  await ensureAdminPermissions();
  await ensureIocTables();
  await loadApiKeysFromDb();
  // One-time data fix: NVD has not indexed these 2026 CISA KEV entries yet
  await db.execute(sql`
    UPDATE cve_tracker
    SET patch_available = true,
        patch_url = CASE cve_id
          WHEN 'CVE-2026-42897' THEN 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-42897'
          WHEN 'CVE-2026-54420' THEN 'https://www.cve.org/CVERecord?id=CVE-2026-54420'
        END,
        patch_became_available_at = COALESCE(patch_became_available_at, NOW())
    WHERE cve_id IN ('CVE-2026-42897', 'CVE-2026-54420')
      AND NOT patch_available
  `);
  // One-time data fix: severity values were hardcoded "critical" for all CISA KEV entries
  // regardless of actual CVSS score. Recalculate per NVD standard:
  //   ≥9.0=critical, 7.0–8.9=high, 4.0–6.9=medium, 0.1–3.9=low
  await db.execute(sql`
    UPDATE cve_tracker
    SET severity = CASE
      WHEN cvss_score::numeric >= 9.0 THEN 'critical'
      WHEN cvss_score::numeric >= 7.0 THEN 'high'
      WHEN cvss_score::numeric >= 4.0 THEN 'medium'
      WHEN cvss_score::numeric >= 0.1 THEN 'low'
      ELSE severity
    END
    WHERE cvss_score IS NOT NULL
      AND severity != CASE
        WHEN cvss_score::numeric >= 9.0 THEN 'critical'
        WHEN cvss_score::numeric >= 7.0 THEN 'high'
        WHEN cvss_score::numeric >= 4.0 THEN 'medium'
        ELSE 'low'
      END
  `);
  await runLivenessTimeoutBugFixOnce();
  maybeSeedDemoReports();
}

// One-time data fix marker table — startup() runs on every process boot (including
// crash-loop restarts), so any "one-time" DB fix gated only by a WHERE clause on
// mutable columns (scan_status/is_alive/http_status) will keep re-firing every
// restart and can re-queue domains that a cron already legitimately re-processed
// in the meantime. This table makes such fixes idempotent across restarts.
async function ensureOneTimeFixesTable(): Promise<void> {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS applied_one_time_fixes (
      fix_key    TEXT PRIMARY KEY,
      applied_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
}

async function runLivenessTimeoutBugFixOnce(): Promise<void> {
  await ensureOneTimeFixesTable();
  const FIX_KEY = "lead_candidates_liveness_timeout_reset_2026_07";
  const already = await db.execute(sql`
    SELECT 1 FROM applied_one_time_fixes WHERE fix_key = ${FIX_KEY}
  `);
  if (already.rowCount && already.rowCount > 0) return;

  // Liveness timeout bug fix: outer timeout was 9s but checkLiveness tries 2 URLs × 8s each.
  // When HTTPS timed out at 8s, only 1s remained for HTTP fallback — live domains were
  // incorrectly marked dead (scan_status=failed, http_status=0, is_alive=false).
  // Reset these tier2 candidates back to pending so they get re-scanned with correct 18s timeout.
  // Runs exactly once (tracked via applied_one_time_fixes), not on every restart.
  const resetResult = await db.execute(sql`
    UPDATE lead_candidates
    SET scan_status = 'pending',
        is_alive    = NULL,
        http_status = NULL,
        updated_at  = NOW()
    WHERE tier        = 'tier2'
      AND scan_status = 'failed'
      AND is_alive    = false
      AND http_status = 0
  `);
  logger.info({ resetCount: resetResult.rowCount }, "Liveness timeout bug: yanlış 'dead' etiketli tier2 domainler pending'e alındı (tek seferlik)");
  await db.execute(sql`
    INSERT INTO applied_one_time_fixes (fix_key) VALUES (${FIX_KEY})
    ON CONFLICT (fix_key) DO NOTHING
  `);
}

function maybeSeedDemoReports(): void {
  setImmediate(async () => {
    try {
      const existing = await db
        .select({ id: demoReportsTable.id, pdfPath: demoReportsTable.pdfPath })
        .from(demoReportsTable)
        .limit(6);

      // DB kayıt yok VEYA herhangi bir PDF dosyası disk üzerinde eksikse yeniden üret
      const missingFile = existing.some(
        (r) => !r.pdfPath || !fs.existsSync(r.pdfPath),
      );

      if (existing.length > 0 && !missingFile) return;

      logger.info(
        { dbRows: existing.length, missingFile },
        "Demo raporlar eksik — otomatik uretim baslıyor",
      );
      const { generateAllDemoReports } = await import("./services/demoReportGenerator");
      await generateAllDemoReports();
      logger.info("Demo rapor seed tamamlandi");
    } catch (err) {
      logger.warn({ err }, "Demo rapor seed hatasi");
    }
  });
}

async function ensureIocTables() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS ioc_entries (
      id SERIAL PRIMARY KEY,
      value VARCHAR(500) NOT NULL,
      ioc_type VARCHAR(20) NOT NULL,
      sources TEXT[] DEFAULT '{}',
      confidence_score INTEGER DEFAULT 0,
      confidence_level VARCHAR(20),
      first_seen_at TIMESTAMP DEFAULT NOW(),
      last_seen_at TIMESTAMP DEFAULT NOW(),
      expires_at TIMESTAMP,
      is_active BOOLEAN DEFAULT TRUE,
      malware_family VARCHAR(100),
      threat_type VARCHAR(100),
      tags TEXT[],
      UNIQUE(value, ioc_type)
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS customer_ip_whitelist (
      id SERIAL PRIMARY KEY,
      customer_id INTEGER,
      ip_cidr VARCHAR(50) NOT NULL,
      label VARCHAR(150),
      reason VARCHAR(50),
      added_by VARCHAR(100),
      is_active BOOLEAN DEFAULT TRUE,
      expires_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(customer_id, ip_cidr)
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS ioc_action_log (
      id SERIAL PRIMARY KEY,
      customer_id INTEGER,
      ioc_value VARCHAR(500) NOT NULL,
      ioc_type VARCHAR(20),
      ioc_id INTEGER,
      action VARCHAR(30) NOT NULL,
      confidence_score INTEGER,
      sources TEXT[],
      skip_reason VARCHAR(100),
      performed_by VARCHAR(50) DEFAULT 'auto',
      fortinet_response JSONB,
      reverted_at TIMESTAMP,
      revert_reason VARCHAR(100),
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS system_settings (
      key VARCHAR(100) PRIMARY KEY,
      value TEXT NOT NULL,
      description VARCHAR(255),
      updated_by VARCHAR(100),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);
  // Seed default settings
  await db.execute(sql`
    INSERT INTO system_settings (key, value, description) VALUES
      ('auto_block_enabled',             'false', 'FortiGate otomatik blok — varsayilan kapali'),
      ('min_confidence_for_block',       '80',    'Otomatik blok icin minimum confidence skoru'),
      ('min_sources_for_block',          '2',     'Blok icin minimum kaynak sayisi'),
      ('ioc_report_confidence_threshold','40',    'Musteriye raporlama icin minimum skor'),
      ('kill_switch_active',             'false', 'Acil durdurma — tum otomatik aksiyonlari durdurur')
    ON CONFLICT (key) DO NOTHING
  `);
}

async function ensureAdminPermissions() {
  await db.execute(sql`ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS departments TEXT[] NOT NULL DEFAULT '{}'`);
  await db.execute(sql`ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS is_superadmin BOOLEAN NOT NULL DEFAULT FALSE`);
  // Mevcut ilk yöneticiyi superadmin yap (tek admin varsa)
  await db.execute(sql`
    UPDATE admin_users SET is_superadmin = TRUE
    WHERE id = (SELECT MIN(id) FROM admin_users)
      AND NOT EXISTS (SELECT 1 FROM admin_users WHERE is_superadmin = TRUE)
  `);
}

async function ensureSocialMediaTables() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS social_media_accounts (
      id SERIAL PRIMARY KEY,
      platform VARCHAR(20) UNIQUE NOT NULL,
      account_name VARCHAR(100),
      account_id VARCHAR(100),
      access_token TEXT,
      token_expires_at TIMESTAMP,
      is_active BOOLEAN DEFAULT true,
      last_posted_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS special_days (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      name_en VARCHAR(255),
      day INTEGER,
      month INTEGER,
      is_lunar BOOLEAN DEFAULT false,
      category VARCHAR(30),
      tone VARCHAR(20),
      cybersecurity_angle TEXT,
      is_active BOOLEAN DEFAULT true
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS content_calendar (
      id SERIAL PRIMARY KEY,
      week_start DATE NOT NULL,
      generated_at TIMESTAMP,
      status VARCHAR(20) DEFAULT 'pending',
      total_posts INTEGER DEFAULT 0,
      approved_posts INTEGER DEFAULT 0,
      published_posts INTEGER DEFAULT 0,
      generation_cost_usd DECIMAL(8,6) DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS social_media_posts (
      id SERIAL PRIMARY KEY,
      calendar_id INTEGER REFERENCES content_calendar(id),
      platform VARCHAR(20) NOT NULL,
      post_type VARCHAR(30) DEFAULT 'standard',
      scheduled_date DATE,
      scheduled_time TIME DEFAULT '09:30',
      caption TEXT,
      hashtags TEXT[],
      alt_text VARCHAR(500),
      slides JSONB,
      thread_tweets JSONB,
      image_svg TEXT,
      image_png_path VARCHAR(500),
      image_dimensions VARCHAR(20),
      status VARCHAR(20) DEFAULT 'draft',
      revision_request TEXT,
      revision_count INTEGER DEFAULT 0,
      approved_by VARCHAR(100),
      approved_at TIMESTAMP,
      published_at TIMESTAMP,
      platform_post_id VARCHAR(255),
      platform_post_url VARCHAR(500),
      likes INTEGER DEFAULT 0,
      comments INTEGER DEFAULT 0,
      shares INTEGER DEFAULT 0,
      impressions INTEGER DEFAULT 0,
      clicks INTEGER DEFAULT 0,
      fetched_at TIMESTAMP,
      special_day_id INTEGER REFERENCES special_days(id),
      data_source VARCHAR(100),
      generation_prompt TEXT,
      generation_cost_usd DECIMAL(8,6) DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);
  // Özel günleri seed et (ilk çalıştırmada)
  await db.execute(sql`
    INSERT INTO special_days (name, day, month, category, tone, cybersecurity_angle) VALUES
      ('Cumhuriyet Bayramı', 29, 10, 'national', 'celebratory', 'Dijital Türkiye de güvende olmalı. 7545 Kanunu bu yolda önemli bir adım.'),
      ('Atatürk''u Anma Günü', 10, 11, 'national', 'solemn', 'Ulu Önder''in mirası güçlü bir Türkiye. Dijital çağda bu güç siber güvenlikten geçiyor.'),
      ('Ulusal Egemenlik Günü', 23, 4, 'national', 'celebratory', 'Dijital egemenlik de ulusal egemenliğin parçası.'),
      ('Gençlik Bayramı', 19, 5, 'national', 'celebratory', 'Gençlerimizin dijital geleceği güvende olsun.'),
      ('Zafer Bayramı', 30, 8, 'national', 'celebratory', 'Siber uzayda da zafer kazanacağız.'),
      ('Yılbaşı', 1, 1, 'global', 'celebratory', 'Yeni yılda siber güvenlik önceliğiniz olsun. Ücretsiz tarama hediyemiz.'),
      ('Veri Gizliliği Günü', 28, 1, 'cybersecurity', 'awareness', 'Verilerinizin değerini biliyor musunuz?'),
      ('Dünya Yedekleme Günü', 31, 3, 'cybersecurity', 'awareness', 'Verilerinizi yedeklediniz mi? Fidye yazılımına hazırlık.')
    ON CONFLICT DO NOTHING
  `);
}

async function ensureDnsTables() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS dns_watched_domains (
      id SERIAL PRIMARY KEY,
      customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
      domain TEXT NOT NULL,
      is_active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      last_checked_at TIMESTAMP,
      UNIQUE(customer_id, domain)
    )
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS dns_snapshots (
      id SERIAL PRIMARY KEY,
      customer_id INTEGER NOT NULL,
      domain TEXT NOT NULL,
      a_records JSONB NOT NULL DEFAULT '[]',
      mx_records JSONB NOT NULL DEFAULT '[]',
      ns_records JSONB NOT NULL DEFAULT '[]',
      txt_records JSONB NOT NULL DEFAULT '[]',
      cname_records JSONB NOT NULL DEFAULT '[]',
      checked_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS dns_snapshots_customer_domain_idx
    ON dns_snapshots(customer_id, domain, checked_at DESC)
  `);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS dns_change_events (
      id SERIAL PRIMARY KEY,
      customer_id INTEGER NOT NULL,
      domain TEXT NOT NULL,
      record_type TEXT NOT NULL,
      old_values JSONB,
      new_values JSONB,
      severity TEXT NOT NULL DEFAULT 'medium',
      soc_case_id INTEGER,
      detected_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
  await db.execute(sql`
    CREATE INDEX IF NOT EXISTS dns_change_events_customer_idx
    ON dns_change_events(customer_id, detected_at DESC)
  `);
}

async function ensureOnboardingEmailColumns() {
  await db.execute(sql`ALTER TABLE IF EXISTS customers ADD COLUMN IF NOT EXISTS onboarding_d3_sent_at TIMESTAMP`);
  await db.execute(sql`ALTER TABLE IF EXISTS customers ADD COLUMN IF NOT EXISTS onboarding_d7_sent_at TIMESTAMP`);
}

async function ensureBadgeAndEmergingColumns() {
  await db.execute(sql`ALTER TABLE IF EXISTS customers ADD COLUMN IF NOT EXISTS badge_token TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS customers ADD COLUMN IF NOT EXISTS badge_enabled BOOLEAN NOT NULL DEFAULT TRUE`);
  await db.execute(sql`ALTER TABLE IF EXISTS customers ADD COLUMN IF NOT EXISTS badge_impression_count INTEGER NOT NULL DEFAULT 0`);
  await db.execute(sql`ALTER TABLE IF EXISTS cve_tracker ADD COLUMN IF NOT EXISTS is_emerging BOOLEAN DEFAULT FALSE`);
  await db.execute(sql`ALTER TABLE IF EXISTS cve_tracker ADD COLUMN IF NOT EXISTS severity_label TEXT`);
  await db.execute(sql`ALTER TABLE IF EXISTS cve_tracker ADD COLUMN IF NOT EXISTS alert_sent_at TIMESTAMP`);
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS emerging_threat_alerts (
      id SERIAL PRIMARY KEY,
      cve_id VARCHAR(30) REFERENCES cve_tracker(cve_id),
      customer_id INTEGER REFERENCES customers(id),
      technology_matched VARCHAR(150),
      sent_at TIMESTAMP,
      email_status VARCHAR(20) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
}

async function ensureDomainScanPurchasesTable() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS domain_scan_purchases (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      domain TEXT,
      scan_id INTEGER,
      status TEXT NOT NULL DEFAULT 'pending',
      amount_try INTEGER NOT NULL DEFAULT 99000,
      payment_ref TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      paid_at TIMESTAMP
    )
  `);

  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS annual_reports (
      id SERIAL PRIMARY KEY,
      domain TEXT NOT NULL,
      company_name TEXT,
      year INTEGER NOT NULL,
      year_end_score INTEGER NOT NULL,
      year_end_grade TEXT,
      prev_year_score INTEGER,
      score_delta INTEGER,
      total_scans INTEGER NOT NULL DEFAULT 0,
      closed_findings INTEGER NOT NULL DEFAULT 0,
      surface_reduction INTEGER NOT NULL DEFAULT 0,
      avg_critical_close_days INTEGER,
      monthly_scores JSONB,
      top_achievement TEXT,
      sector_percentile INTEGER,
      svg_content TEXT,
      pdf_url TEXT,
      email_sent_at TIMESTAMP,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )
  `);
}

// ─── Cron: 6-aylık fiyat güncelleme hatırlatıcısı (her Pazartesi 09:30'da) ────
function startEmergingThreatCron() {
  cron.schedule("0 */4 * * *", wrapCron("emerging_threats", "0 */4 * * *", async () => {
    const { checkEmergingThreats } = await import("./services/emergingThreatService");
    await checkEmergingThreats();
  }));
}

function startInflationReminderCron() {
  cron.schedule("30 9 * * 1", wrapCron("inflation_reminder", "30 9 * * 1", async () => {
    try {
      const SIX_MONTHS_MS = 180 * 24 * 60 * 60 * 1000;
      const plans = await db.select().from(pricingPlansTable).orderBy(pricingPlansTable.updatedAt);
      if (plans.length === 0) return;

      const oldestDate = new Date(plans[0].updatedAt);
      const ageMs = Date.now() - oldestDate.getTime();
      if (ageMs < SIX_MONTHS_MS) return;

      const monthsOld = Math.floor(ageMs / (30 * 24 * 60 * 60 * 1000));
      const adminEmail = process.env.SMTP_USER ?? process.env.ADMIN_EMAIL;
      if (!adminEmail) {
        logger.warn("Inflation reminder: no admin email configured (SMTP_USER missing)");
        return;
      }

      const planLines = plans
        .filter(p => Number(p.price) > 0)
        .map(p => `<tr><td style="padding:4px 12px">${p.name}</td><td style="padding:4px 12px">${Number(p.price).toLocaleString("tr-TR")} TL</td><td style="padding:4px 12px">${Math.round(Number(p.price) * 1.25).toLocaleString("tr-TR")} TL</td></tr>`)
        .join("");

      await sendMail({
        to: adminEmail,
        subject: `CyberStep — Fiyat Güncelleme Hatırlatıcısı (${monthsOld} ay geçti)`,
        html: `
          <div style="font-family:sans-serif;max-width:600px;margin:0 auto">
            <h2 style="color:#f59e0b">Fiyat Güncelleme Zamanı</h2>
            <p>Fiyatlarınız en son <strong>${oldestDate.toLocaleDateString("tr-TR", { day:"numeric", month:"long", year:"numeric" })}</strong> tarihinde güncellendi (<strong>${monthsOld} ay önce</strong>).</p>
            <p>TÜFE verilerine göre önerilen <strong>%25 artış</strong> uygulandığında:</p>
            <table border="1" cellpadding="0" cellspacing="0" style="border-collapse:collapse;width:100%;border-color:#374151">
              <thead><tr style="background:#1f2937;color:#9ca3af">
                <th style="padding:6px 12px;text-align:left">Plan</th>
                <th style="padding:6px 12px;text-align:left">Mevcut</th>
                <th style="padding:6px 12px;text-align:left">Önerilen</th>
              </tr></thead>
              <tbody style="color:#111827">${planLines}</tbody>
            </table>
            <p style="margin-top:20px">
              <a href="${process.env.ADMIN_URL ?? "https://cyberstep.io"}/admin/fiyatlandirma"
                 style="background:#10b981;color:white;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:bold">
                Fiyatları Güncelle
              </a>
            </p>
            <p style="color:#6b7280;font-size:12px;margin-top:24px">Bu hatırlatıcı her Pazartesi sabahı kontrol edilir ve güncelleme gerektiren planlar varsa gönderilir.</p>
          </div>`,
      });
      logger.info({ monthsOld, adminEmail }, "Inflation reminder email sent");
      return 1;
    } catch (err) {
      logger.warn({ err }, "Inflation reminder cron failed");
    }
    return 0;
  }), { timezone: "Europe/Istanbul" });
  logger.info("Inflation reminder cron scheduled (every Monday 09:30)");

  // ─── Otomatik TÜFE Fiyat Güncelleme — Her yıl 1 Ocak 09:00 Istanbul ──────
  cron.schedule("0 9 1 1 *", wrapCron("price_auto_update", "0 9 1 1 *", async () => {
    const { runPriceAutoUpdate } = await import("./services/price-auto-update");
    return await runPriceAutoUpdate();
  }), { timezone: "Europe/Istanbul" });
  logger.info("Price auto-update cron scheduled (1 Jan 09:00 Istanbul)");

  // ─── Yıllık Güvenlik Raporu — Her yıl 1 Ocak 09:30 Istanbul ──────────────
  cron.schedule("30 9 1 1 *", wrapCron("annual_security_report", "30 9 1 1 *", async () => {
    const { generateAnnualReports } = await import("./lib/reports/annualReportSvg.js");
    const year = new Date().getFullYear() - 1;
    const sent = await generateAnnualReports(year);
    logger.info(`Annual reports: ${sent} sent for year ${year}`);
    return sent;
  }), { timezone: "Europe/Istanbul" });
  logger.info("Annual security report cron scheduled (1 Jan 09:30 Istanbul)");
}

// ─── Digest Cron ─────────────────────────────────────────────────────────────
// 06:00 RSS topla → 06:30 Claude zenginleştir → Cuma 07:00 digest üret (İstanbul)
function startDigestCron() {
  cron.schedule("30 3 * * *", wrapCron("digest_rss_collect", "30 3 * * *", async () => {
    logger.info("Digest: RSS haber toplama başlıyor");
    try {
      await collectRSSFeeds();
    } catch (err) {
      logger.error({ err }, "Digest: RSS haber toplama başarısız");
    }
  }), { timezone: "Europe/Istanbul" });

  cron.schedule("0 4 * * *", wrapCron("digest_enrich", "0 4 * * *", async () => {
    logger.info("Digest: Haber zenginleştirme (AI özet + CVE çıkarma) başlıyor");
    try {
      await enrichNewsItems();
    } catch (err) {
      logger.error({ err }, "Digest: Haber zenginleştirme başarısız");
    }
  }), { timezone: "Europe/Istanbul" });

  cron.schedule("0 4 * * 5", wrapCron("digest_weekly_generate", "0 4 * * 5", async () => {
    logger.info("Digest: Haftalık digest oluşturma başlıyor");
    try {
      const id = await generateWeeklyDigest();
      logger.info({ id }, "Digest: Haftalık digest oluşturuldu");
    } catch (err) {
      logger.error({ err }, "Digest: Haftalık digest oluşturma başarısız");
    }
  }), { timezone: "Europe/Istanbul" });

  logger.info("Digest cron scheduled (06:00 collect → 06:30 enrich → Fri 07:00 generate Istanbul)");
}

// ─── Blog Autopilot Cron ──────────────────────────────────────────────────────
// Pazartesi + Perşembe 09:00 İstanbul (UTC+3 = 06:00 UTC)
function startBlogAutopilotCron() {
  const runJob = async () => {
    logger.info("Blog autopilot: yazı üretimi başlıyor");
    await generateAndPublishBlogPost();
    // Hataları yutma — wrapCron yakalar, DB'ye hata kaydeder ve mail atar
  };
  cron.schedule("0 6 * * 1", wrapCron("blog_autopilot_mon", "0 6 * * 1", runJob), { timezone: "Europe/Istanbul" }); // Her Pazartesi 09:00 İstanbul
  cron.schedule("0 6 * * 4", wrapCron("blog_autopilot_thu", "0 6 * * 4", runJob), { timezone: "Europe/Istanbul" }); // Her Perşembe 09:00 İstanbul
  logger.info("Blog autopilot cron scheduled (Mon & Thu 09:00 Istanbul)");
}

// ─── Cron: Sosyal Medya — Pazar 20:00 İstanbul haftalık içerik üret ────────────
function startSocialMediaWeeklyCron() {
  cron.schedule("0 17 * * 0", wrapCron("social_media_weekly", "0 17 * * 0", async () => {
    try {
      logger.info("Sosyal medya haftalık içerik üretimi başlıyor (Pazar 20:00)");
      const { generateWeeklyContent } = await import("./routes/social-media/contentGenerator");
      const { db: _db } = await import("@workspace/db");
      const { contentCalendarTable } = await import("@workspace/db");
      const nextMonday = new Date();
      nextMonday.setDate(nextMonday.getDate() + 1);
      nextMonday.setHours(0, 0, 0, 0);
      const [calendar] = await _db.insert(contentCalendarTable).values({
        weekStart: nextMonday.toISOString().split("T")[0],
      }).returning();
      await generateWeeklyContent(nextMonday, calendar.id);
      logger.info({ calendarId: calendar.id }, "Sosyal medya haftalık içerik tamamlandı");
    } catch (err) {
      logger.error({ err }, "Sosyal medya haftalık içerik cron hatası");
    }
  }), { timezone: "Europe/Istanbul" });
  logger.info("Sosyal medya haftalık içerik cron zamanlandı (Pazar 20:00 İstanbul)");
}

// ─── Cron: AI Araç Politika İzleme (her Pazar 02:00 İstanbul) ─────────────────
function startAiToolMonitorCron() {
  cron.schedule("0 2 * * 0", wrapCron("ai_tool_monitor", "0 2 * * 0", async () => {
    try {
      logger.info("AI araç politika kontrolü başlıyor");
      const { checkAllToolsForChanges } = await import("./services/ai-tool-monitor");
      await checkAllToolsForChanges();
    } catch (err) {
      logger.error({ err }, "AI araç politika kontrol cron hatası");
    }
  }), { timezone: "Europe/Istanbul" });
  logger.info("AI araç politika izleme cron zamanlandı (Pazar 02:00 İstanbul)");
}

// ─── Cron: AI Politika Çeyreklik Güncelleme (1 Oca/Nis/Tem/Eki 03:00) ─────────
function startQuarterlyPolicyUpdateCron() {
  cron.schedule("0 3 1 1,4,7,10 *", wrapCron("quarterly_policy_update", "0 3 1 1,4,7,10 *", async () => {
    try {
      logger.info("AI politika çeyreklik güncelleme başlıyor");
      const { runQuarterlyPolicyUpdate } = await import("./services/policy-generator");
      await runQuarterlyPolicyUpdate();
    } catch (err) {
      logger.error({ err }, "AI politika çeyreklik güncelleme cron hatası");
    }
  }), { timezone: "Europe/Istanbul" });
  logger.info("AI politika çeyreklik güncelleme cron zamanlandı (1 Oca/Nis/Tem/Eki 03:00 İstanbul)");
}

// ─── Growth Engine Crons ──────────────────────────────────────────────────────
function startGrowthEngineCrons() {
  // SSL bitiş taraması — her gece 01:00 İstanbul (22:00 UTC)
  cron.schedule("0 22 * * *", wrapCron("growth_ssl_expiry", "0 22 * * *", async () => {
    try {
      const { runSSLExpiryCron } = await import("./services/growth-engine");
      await runSSLExpiryCron();
    } catch (err) {
      logger.warn({ err }, "SSL expiry growth cron failed");
    }
  }));
  // CVE uyarısı — her gece 02:30 İstanbul (23:30 UTC)
  cron.schedule("30 23 * * *", wrapCron("growth_cve_alert", "30 23 * * *", async () => {
    try {
      const { runCVEAlertCron } = await import("./services/growth-engine");
      await runCVEAlertCron();
    } catch (err) {
      logger.warn({ err }, "CVE alert growth cron failed");
    }
  }));
  // Port değişikliği — her Pazar 04:00 İstanbul (01:00 UTC)
  cron.schedule("0 1 * * 0", wrapCron("growth_port_change", "0 1 * * 0", async () => {
    try {
      const { runPortChangeCron } = await import("./services/growth-engine");
      await runPortChangeCron();
    } catch (err) {
      logger.warn({ err }, "Port change growth cron failed");
    }
  }));
  logger.info("Growth engine crons scheduled (SSL 01:00, CVE 02:30, Port Sun 04:00 Istanbul)");
}

startup()
  .then(() => {
    startReminderCron();
    startScanLeadDripCron();
    startLeadWebEnrichCron();
    startLeadTrEnrichCron();
    startAiScoreRetryCron();
    startFreeScanFollowupCron();
    startIsrImapCron();
    startInflationReminderCron();
    startEmergingThreatCron();
    startBlogAutopilotCron();
    startSocialMediaWeeklyCron();
    startDigestCron();
    startAiToolMonitorCron();
    startQuarterlyPolicyUpdateCron();
    startGrowthEngineCrons();
    seedDefaultSources().catch((err) => logger.warn({ err }, "Digest: default sources seed failed"));
    // USOM zararlı alan listesini arka planda yükle ve günlük yenile
    refreshUsomList().catch((err) => logger.warn({ err }, "USOM initial fetch failed"));
    cron.schedule("15 3 * * *", wrapCron("usom_refresh", "15 3 * * *", async () => {
      await refreshUsomList();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    // Müşteri sağlık skoru — her gece 02:00'de hesapla
    cron.schedule("0 2 * * *", wrapCron("health_score", "0 2 * * *", async () => {
      await calculateAllHealthScores();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Health score cron scheduled (02:00 Istanbul)");
    // Tahsilat hatırlatıcı — her gün 10:00'da vadesi geçen faturaları kontrol et
    cron.schedule("0 10 * * *", wrapCron("collection_reminder", "0 10 * * *", async () => {
      await runCollectionReminderCron(sendMail);
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Collection reminder cron scheduled (10:00 Istanbul)");
    // Otomatik CRM etiketleme — her gece 03:30'da
    cron.schedule("50 3 * * *", wrapCron("auto_tag", "50 3 * * *", async () => {
      await runAutoTagCron();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Auto-tag cron scheduled (03:30 Istanbul)");
    // Görev hatırlatıcı — her gün 08:30'da
    cron.schedule("30 8 * * *", wrapCron("task_reminder", "30 8 * * *", async () => {
      await runTaskReminderCron();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Task reminder cron scheduled (08:30 Istanbul)");
    // NPS otomatik gönderim — her Salı 11:00'da
    cron.schedule("0 11 * * 2", wrapCron("nps_send", "0 11 * * 2", async () => {
      await runNpsCron();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("NPS cron scheduled (Tuesday 11:00 Istanbul)");
    startFabricCrons();
    startSOCCrons();
    startDnsCrons();
    logger.info("Certstream devre dışı — crt.sh polling kullanılıyor");

    // ─── Certstream GitHub Actions dispatch — saatte bir ─────────────────────
    // GitHub'ın schedule'ına güvenmiyoruz; kendi cron'umuzdan dispatch ediyoruz.
    cron.schedule("5 * * * *", wrapCron("certstream_dispatch", "5 * * * *", async () => {
      const pat = process.env["GITHUB_PAT"];
      const repo = "serkangrdl-cyberstep/CyberStep";
      const workflowId = "certstream-bridge.yml";
      if (!pat) { logger.warn("GITHUB_PAT eksik — certstream dispatch atlandı"); return 0; }
      const { dispatchWorkflow, watchRunInBackground } = await import("./services/githubActionsHelper");
      const dispatchedAt = new Date();
      const correlationId = randomUUID();
      const result = await dispatchWorkflow({ pat, repo, workflowId, inputs: { correlation_id: correlationId } });
      if (result.dispatched) {
        logger.info({ workflow: workflowId, correlationId }, "Certstream dispatch tetiklendi — run izleniyor");
        watchRunInBackground({ pat, repo, workflowId, dispatchedAt, correlationId, logContext: { trigger: "cron" } });
      } else {
        logger.warn({ status: result.httpStatus, workflow: workflowId }, "Certstream dispatch başarısız");
      }
      return result.dispatched ? 1 : 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Certstream GitHub dispatch cron scheduled (saatte bir, :05)");

    // ─── Microsoft 365 Graph API poller — her 15 dakikada ────────────────────
    cron.schedule("*/15 * * * *", wrapCron("ms365_poller", "*/15 * * * *", async () => {
      const { pollAllMs365Integrations } = await import("./services/ms365Graph");
      await pollAllMs365Integrations();
    }), { timezone: "Europe/Istanbul" });
    logger.info("MS365 Graph API poller scheduled (every 15 min)");

    // ─── Onboarding email serisi — Her gün 10:30 (D+3 ve D+7) ───────────────
    cron.schedule("30 10 * * *", wrapCron("onboarding_d3d7", "30 10 * * *", async () => {
      logger.info("Running onboarding email cron (D+3, D+7)");
      const { sendOnboardingD3Email, sendOnboardingD7Email } = await import("./services/email");
      const base = process.env["REPLIT_DOMAINS"]
        ? `https://${process.env["REPLIT_DOMAINS"].split(",")[0]?.trim()}`
        : "http://localhost:80";

      let sent = 0;
      // D+3: kayıt 3-4 gün önce, d3 emaili henüz gönderilmemiş
      const d3Due = await db.execute<{ id: number; email: string; full_name: string; company_name: string | null }>(sql`
        SELECT id, email, full_name, company_name
        FROM customers
        WHERE created_at >= NOW() - INTERVAL '4 days'
          AND created_at < NOW() - INTERVAL '3 days'
          AND onboarding_d3_sent_at IS NULL
        LIMIT 50
      `);
      for (const c of (d3Due as unknown as { rows: { id: number; email: string; full_name: string; company_name: string | null }[] }).rows) {
        await sendOnboardingD3Email({
          email: c.email, fullName: c.full_name,
          companyName: c.company_name ?? undefined,
          assessmentUrl: `${base}/assessment/start`,
        }).catch(err => logger.warn({ err, email: c.email }, "Onboarding D+3 email failed"));
        await db.execute(sql`UPDATE customers SET onboarding_d3_sent_at = NOW() WHERE id = ${c.id}`);
        logger.info({ customerId: c.id }, "Onboarding D+3 email sent");
        sent++;
      }

      // D+7: kayıt 7-8 gün önce, d7 emaili henüz gönderilmemiş
      const d7Due = await db.execute<{ id: number; email: string; full_name: string; company_name: string | null }>(sql`
        SELECT id, email, full_name, company_name
        FROM customers
        WHERE created_at >= NOW() - INTERVAL '8 days'
          AND created_at < NOW() - INTERVAL '7 days'
          AND onboarding_d7_sent_at IS NULL
        LIMIT 50
      `);
      for (const c of (d7Due as unknown as { rows: { id: number; email: string; full_name: string; company_name: string | null }[] }).rows) {
        await sendOnboardingD7Email({
          email: c.email, fullName: c.full_name,
          companyName: c.company_name ?? undefined,
          fullAssessmentUrl: `${base}/assessment/full/start`,
          assessmentUrl: `${base}/assessment/start`,
        }).catch(err => logger.warn({ err, email: c.email }, "Onboarding D+7 email failed"));
        await db.execute(sql`UPDATE customers SET onboarding_d7_sent_at = NOW() WHERE id = ${c.id}`);
        logger.info({ customerId: c.id }, "Onboarding D+7 email sent");
        sent++;
      }
      return sent;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Onboarding email cron scheduled (10:30 Istanbul, D+3 & D+7)");

    // ─── Günlük Yönetici Özeti — Her sabah 08:00 ─────────────────────────────
    cron.schedule("0 8 * * *", wrapCron("daily_summary", "0 8 * * *", async () => {
      await collectDailySummary(new Date());
      return 1;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Daily summary cron scheduled (08:00 Istanbul)");

    // ─── Günlük Cron Sağlık Raporu — Her sabah 07:00 ──────────────────────────
    cron.schedule("0 7 * * *", wrapCron("daily_cron_report", "0 7 * * *", async () => {
      const { checkCronHealth } = await import("./services/cronHealthMonitor");
      const { sendMail } = await import("./services/email");
      const result = await checkCronHealth();
      if (result.healthy) return 0;
      const adminEmail = process.env["SOC_ADMIN_EMAIL"] ?? process.env["SMTP_USER"];
      if (!adminEmail) { logger.warn("daily_cron_report: ADMIN_EMAIL ayarlı değil, e-posta atlandı"); return 0; }
      const alertLines = result.alerts.map((a) =>
        `• [${a.issue.toUpperCase()}] ${a.label} (${a.job_name})\n  Son çalışma: ${a.last_run ?? "hiç"}\n  ${a.details}`
      ).join("\n\n");
      await sendMail({
        to: adminEmail,
        subject: `CyberStep Cron Uyarisi — ${result.alerts.length} job sorunlu`,
        html: `<h2>CyberStep Cron Uyarisi</h2><p><strong>${result.alerts.length} job sorunlu</strong> — ${new Date().toLocaleString("tr-TR", { timeZone: "Europe/Istanbul" })}</p><ul>${result.alerts.map((a) => `<li><strong>[${a.issue}] ${a.label}</strong><br>Son: ${a.last_run ?? "hic"}<br>${a.details}</li>`).join("")}</ul><hr><small>Toplam: ${result.summary.total_jobs} | Basarili: ${result.summary.successful} | Hatali: ${result.summary.failed} | Eksik: ${result.summary.missing}</small><pre style="font-size:11px;margin-top:12px;color:#555">${alertLines}</pre>`,
      });
      logger.info({ alertCount: result.alerts.length }, "daily_cron_report: saglik uyari e-postasi gonderildi");
      return result.alerts.length;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Daily cron health report cron scheduled (07:00 Istanbul)");

    // ─── Dunning (başarısız ödeme takibi) — Her gün 10:15 ────────────────────
    cron.schedule("15 10 * * *", wrapCron("dunning_check", "15 10 * * *", async () => {
      return runDunningCron();
    }), { timezone: "Europe/Istanbul" });
    logger.info("Dunning cron scheduled (10:15 Istanbul)");

    // ─── Upsell engine — Her gece 23:00 ──────────────────────────────────────
    cron.schedule("0 23 * * *", wrapCron("upsell_engine", "0 23 * * *", async () => {
      return runUpsellEngine();
    }), { timezone: "Europe/Istanbul" });
    logger.info("Upsell engine cron scheduled (23:00 Istanbul)");

    // ─── Pazar izleme — Her 4 saatte bir ────────────────────────────────────
    cron.schedule("0 */4 * * *", wrapCron("market_watcher", "0 */4 * * *", async () => {
      return runMarketWatcher();
    }), { timezone: "Europe/Istanbul" });
    logger.info("Market watcher cron scheduled (every 4h)");

    // ─── Haftalık pazar özeti — Her Cuma 09:00 ───────────────────────────────
    cron.schedule("0 9 * * 5", wrapCron("market_weekly_summary", "0 9 * * 5", async () => {
      await sendWeeklyMarketSummary();
      return 1;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Market weekly summary cron scheduled (Friday 09:00 Istanbul)");

    // ─── Platform maliyet kontrolü — Her gece 23:30 ───────────────────────────
    cron.schedule("45 23 * * *", wrapCron("platform_cost_check", "45 23 * * *", async () => {
      await checkPlatformCosts();
      return 1;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Platform cost check cron scheduled (23:30 Istanbul)");

    // ─── Onboarding D+1 emaili — Her gün 10:00 ───────────────────────────────
    cron.schedule("5 10 * * *", wrapCron("onboarding_day1_email", "5 10 * * *", async () => {
      return runDay1EmailCron();
    }), { timezone: "Europe/Istanbul" });
    logger.info("Onboarding D+1 email cron scheduled (10:00 Istanbul)");

    // ─── KVKK veri saklama politikası — Her ayın 1'i 03:00 ───────────────────
    cron.schedule("0 3 1 * *", wrapCron("kvkk_data_retention", "0 3 1 * *", async () => {
      if (process.env["DATA_RETENTION_ENABLED"] !== "true") return 0;
      const { db: dbInst } = await import("@workspace/db");
      const { dataRetentionPolicyTable } = await import("@workspace/db");
      const { sql: sqlHelper } = await import("drizzle-orm");
      const policies = await dbInst.select().from(dataRetentionPolicyTable);
      let cleaned = 0;
      for (const policy of policies) {
        try {
          const cutoff = new Date(Date.now() - policy.retentionDays * 86_400_000);
          if (policy.action === "delete") {
            await dbInst.execute(
              sqlHelper`DELETE FROM ${sqlHelper.identifier(policy.tableName)} WHERE created_at < ${cutoff}`
            );
          }
          await dbInst.update(dataRetentionPolicyTable)
            .set({ lastCleanedAt: new Date() })
            .where((await import("drizzle-orm")).eq(dataRetentionPolicyTable.tableName, policy.tableName));
          cleaned++;
        } catch (err) {
          logger.warn({ err, table: policy.tableName }, "KVKK retention: table cleanup failed");
        }
      }
      logger.info({ cleaned }, "KVKK data retention applied");
      return cleaned;
    }), { timezone: "Europe/Istanbul" });
    logger.info("KVKK data retention cron scheduled (1st of month 03:00 Istanbul)");

    // ─── KVKK zamanlanmış hesap silimi — Her gün 04:00 ───────────────────────
    cron.schedule("30 4 * * *", wrapCron("kvkk_scheduled_deletion", "30 4 * * *", async () => {
      if (process.env["DATA_RETENTION_ENABLED"] !== "true") return 0;
      const { db: dbInst } = await import("@workspace/db");
      const { customersTable: ct } = await import("@workspace/db");
      const { lte: lteOp, isNotNull: isNotNullOp, and: andOp } = await import("drizzle-orm");
      const due = await dbInst.select().from(ct).where(
        andOp(isNotNullOp(ct.scheduledDeletionAt), lteOp(ct.scheduledDeletionAt, new Date()))
      );
      for (const c of due) {
        await dbInst.update(ct).set({
          email: `deleted-${c.id}@removed.invalid`,
          fullName: "Silindi",
          companyName: null,
          passwordHash: "",
          archivedAt: new Date(),
          subscriptionStatus: "inactive",
          deletionRequestedAt: null,
          scheduledDeletionAt: null,
        }).where((await import("drizzle-orm")).eq(ct.id, c.id));
        logger.info({ customerId: c.id }, "KVKK: customer data anonymized");
      }
      return due.length;
    }), { timezone: "Europe/Istanbul" });
    logger.info("KVKK scheduled deletion cron scheduled (04:00 Istanbul)");

    // ─── CASM: Attack Path analizi — Her gece 02:00 ─────────────────────────
    cron.schedule("30 2 * * *", wrapCron("attack_path_analysis", "30 2 * * *", async () => {
      const { analyzeAttackPaths, getLatestScan, getActiveCustomers } = await import("./services/attackPathAnalyzer");
      const customers = await getActiveCustomers();
      let analyzed = 0;
      for (const c of customers) {
        const scan = await getLatestScan(c.id);
        if (scan) {
          await analyzeAttackPaths(c.id, scan.id);
          await new Promise(r => setTimeout(r, 3000));
          analyzed++;
        }
      }
      return analyzed;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Attack path analysis cron scheduled (02:30 Istanbul)");

    // ─── CASM: Remediation doğrulama kuyruğu — Her saat ─────────────────────
    cron.schedule("0 * * * *", wrapCron("verification_queue", "0 * * * *", async () => {
      const { processVerificationQueue } = await import("./services/verificationScanner");
      await processVerificationQueue();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Verification queue cron scheduled (hourly)");

    // ─── CASM: SLA ihlal kontrolü — Her gün 08:00 ────────────────────────────
    cron.schedule("20 8 * * *", wrapCron("sla_breach_check", "20 8 * * *", async () => {
      const { checkRemediationSLABreaches } = await import("./services/verificationScanner");
      await checkRemediationSLABreaches();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("SLA breach cron scheduled (08:00 Istanbul)");

    // ─── Churn otomatik müdahale — Her gün 08:30 ─────────────────────────────
    cron.schedule("30 8 * * *", wrapCron("churn_auto_intervention", "30 8 * * *", async () => {
      const { runChurnIntervention } = await import("./services/churn-intervention");
      return await runChurnIntervention();
    }), { timezone: "Europe/Istanbul" });
    logger.info("Churn auto intervention cron scheduled (08:30 Istanbul)");

    // ─── Müşteri aktivasyon izleyici — Her gün 11:00 ─────────────────────────
    cron.schedule("0 11 * * *", wrapCron("customer_activation_monitor", "0 11 * * *", async () => {
      const { runCustomerActivationMonitor } = await import("./services/customer-activation-monitor");
      return await runCustomerActivationMonitor();
    }), { timezone: "Europe/Istanbul" });
    logger.info("Customer activation monitor cron scheduled (11:00 Istanbul)");

    // ─── AI çıktı kalite izleme — Her gün 09:30 ──────────────────────────────
    cron.schedule("30 9 * * *", wrapCron("ai_quality_monitor", "30 9 * * *", async () => {
      const { runAiQualityMonitor } = await import("./services/ai-quality-monitor");
      return await runAiQualityMonitor();
    }), { timezone: "Europe/Istanbul" });
    logger.info("AI quality monitor cron scheduled (09:30 Istanbul)");

    // ─── Platform smoke test — Her saat 05. dakika ───────────────────────────
    cron.schedule("5 * * * *", wrapCron("platform_smoke_test", "5 * * * *", async () => {
      const { runPlatformSmokeTest } = await import("./services/platform-smoke-test");
      return await runPlatformSmokeTest();
    }), { timezone: "Europe/Istanbul" });
    logger.info("Platform smoke test cron scheduled (every hour :05)");

    // ─── SLA proaktif uyarı — Her 30 dakika ──────────────────────────────────
    cron.schedule("*/30 * * * *", wrapCron("sla_proactive_warning", "*/30 * * * *", async () => {
      const { runSlaProactiveWarning } = await import("./services/soc/sla-proactive-warning");
      return await runSlaProactiveWarning();
    }), { timezone: "Europe/Istanbul" });
    logger.info("SLA proactive warning cron scheduled (every 30 min)");

    // ─── Otomatik fatura oluşturma — Her gün 06:00 ───────────────────────────
    cron.schedule("0 6 * * *", wrapCron("auto_invoice_generate", "0 6 * * *", async () => {
      const { runAutoInvoiceGenerate } = await import("./services/auto-invoice");
      return await runAutoInvoiceGenerate();
    }), { timezone: "Europe/Istanbul" });
    logger.info("Auto invoice generate cron scheduled (06:00 Istanbul)");

    // ─── CASM: Cloud CSPM taraması — Her gece 03:45 ──────────────────────────
    cron.schedule("45 3 * * *", wrapCron("cloud_cspm", "45 3 * * *", async () => {
      const { db: dbI } = await import("@workspace/db");
      const { cloudConnectionsTable } = await import("@workspace/db");
      const { eq } = await import("drizzle-orm");
      const { runCloudScan } = await import("./routes/cloud-cspm/index");
      const conns = await dbI.select().from(cloudConnectionsTable).where(eq(cloudConnectionsTable.isActive, true));
      for (const conn of conns) {
        await runCloudScan(conn, conn.customerId!);
        await new Promise(r => setTimeout(r, 5000));
      }
      return conns.length;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Cloud CSPM cron scheduled (03:45 Istanbul)");

    // ─── CASM: GitHub secrets tarama — Her Pazar 04:00 ───────────────────────
    cron.schedule("0 5 * * 0", wrapCron("github_secrets_scan", "0 5 * * 0", async () => {
      const { getCustomersWithGitHub, scanGitHubOrg } = await import("./services/githubScanner");
      const { db: dbI } = await import("@workspace/db");
      const { codeSecretsFindingsTable } = await import("@workspace/db");
      const customers = await getCustomersWithGitHub();
      let findingsCount = 0;
      for (const c of customers) {
        if (!c.githubOrg) continue;
        const findings = await scanGitHubOrg(c.githubOrg, c.id);
        for (const f of findings) {
          await dbI.insert(codeSecretsFindingsTable).values(f).onConflictDoNothing();
        }
        findingsCount += findings.length;
        await new Promise(r => setTimeout(r, 10000));
      }
      return findingsCount;
    }), { timezone: "Europe/Istanbul" });
    logger.info("GitHub secrets scan cron scheduled (Sunday 05:00 Istanbul)");

    cron.schedule("*/30 * * * *", wrapCron("kvkk_deadline", "*/30 * * * *", async () => {
      await checkKvkkDeadlines();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("KVKK 72h deadline cron scheduled (every 30 min)");

    cron.schedule("*/15 * * * *", wrapCron("servicenow_sync", "*/15 * * * *", async () => {
      await syncServiceNowIncidents();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("ServiceNow incident sync cron scheduled (every 15 min)");

    // ─── ServiceNow bağlantı sağlık kontrolü — Her saat ──────────────────────
    cron.schedule("0 * * * *", wrapCron("servicenow_health", "0 * * * *", async () => {
      await checkServiceNowConnections();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("ServiceNow connection health check cron scheduled (every hour)");

    cron.schedule("*/10 * * * *", wrapCron("webhook_retry", "*/10 * * * *", async () => {
      await retryFailedWebhooks();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Webhook retry cron scheduled (every 10 min)");

    startRenewalCron();

    // ─── E-posta dizi kuyruğu — her 30 dakika ─────────────────────────────────
    cron.schedule("*/30 * * * *", wrapCron("email_sequence", "*/30 * * * *", async () => {
      await processEmailQueue();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Email sequence cron scheduled (every 30 min)");

    // ─── NOC: FortiGate polling — her 5 dakika, offset +3 dk ─────────────────
    cron.schedule("3,8,13,18,23,28,33,38,43,48,53,58 * * * *", wrapCron("noc_poll", "3,8,13,18,23,28,33,38,43,48,53,58 * * * *", async () => {
      await runFortiGatePollCron();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("NOC FortiGate poll cron scheduled (every 5 min, offset +3)");

    // ─── NOC: Availability monitor — her 5 dakika, offset +4 dk ──────────────
    cron.schedule("4,9,14,19,24,29,34,39,44,49,54,59 * * * *", wrapCron("noc_availability", "4,9,14,19,24,29,34,39,44,49,54,59 * * * *", async () => {
      await runAvailabilityCron();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("NOC availability cron scheduled (every 5 min, offset +4)");

    // ─── NOC: Claude triage — her 15 dakika ───────────────────────────────────
    cron.schedule("*/15 * * * *", wrapCron("noc_triage", "*/15 * * * *", async () => {
      await runNOCTriageCron();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("NOC triage cron scheduled (every 15 min)");

    // ─── NOC: Baseline tamamlama — her saat ──────────────────────────────────
    cron.schedule("0 * * * *", wrapCron("noc_baseline", "0 * * * *", async () => {
      await checkAndCompleteBaselines();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("NOC baseline check cron scheduled (every hour)");

    // ─── Lead Discovery: crt.sh — Her Gece 03:00 ─────────────────────────────
    // Her TLD ayrı try/catch içinde — biri 502 alsa diğerleri devam eder.
    // fetchCrtsh zaten 4 deneme + üstel geri çekilme yapıyor.
    cron.schedule("0 */4 * * *", wrapCron("crtsh", "0 */4 * * *", async () => {
      if (!await cronIsEnabled("crtsh")) { logger.info("crt.sh cron devre dışı, atlanıyor"); return 0; }
      const limit = await cronGetLimit("crtsh", 500);
      let totalAdded = 0;

      const TLD_QUERIES: Array<{ query: string; limitFactor: number }> = [
        { query: "%.com.tr",  limitFactor: 1.0 },
        { query: "%.net.tr",  limitFactor: 0.4 },
        { query: "%.org.tr",  limitFactor: 0.2 },
        { query: "%.web.tr",  limitFactor: 0.1 },
        { query: "%.biz.tr",  limitFactor: 0.1 },
        { query: "%.info.tr", limitFactor: 0.1 },
        { query: "%.gen.tr",  limitFactor: 0.1 },
        { query: "%.edu.tr",  limitFactor: 0.1 }, // sector=education, düşük öncelik
      ];

      for (const { query, limitFactor } of TLD_QUERIES) {
        try {
          const r = await scanCRTSH(query, { daysBack: 1, minCorporateScore: 10, limit: Math.max(1, Math.floor(limit * limitFactor)) });
          totalAdded += r.addedToLeads ?? 0;
        } catch (err) {
          logger.warn({ query, err: String(err) }, "crt.sh TLD taraması başarısız, diğerleriyle devam ediliyor");
        }
        await new Promise((r) => setTimeout(r, 4000));
      }

      return totalAdded;
    }), { timezone: "Europe/Istanbul" });
    logger.info("crt.sh discovery cron scheduled (every 4h Istanbul, daysBack:1, limit:500)");

    // ─── Lead Discovery: Shodan — Her gece 04:15 (4 sorgu/gece, tam rotasyon) ──
    // epoch-day bazlı rotasyon: 8 sorgunun sırayla 4'ü çalışır (crt.sh devre dışı → Shodan ana kaynak)
    cron.schedule("15 4 * * *", wrapCron("shodan", "15 4 * * *", async () => {
      if (!process.env["SHODAN_API_KEY"]) return 0;
      if (!await cronIsEnabled("shodan")) { logger.info("Shodan cron devre dışı, atlanıyor"); return 0; }
      const limit = await cronGetLimit("shodan", 300);
      const epochDay = Math.floor(Date.now() / 86_400_000);
      const qLen = SHODAN_FREE_QUERIES.length;
      const idx1 = epochDay % qLen;
      const idx2 = (epochDay + 1) % qLen;
      const idx3 = (epochDay + 2) % qLen;
      const idx4 = (epochDay + 3) % qLen;
      const r1 = await scanShodanFree(idx1, limit);
      await new Promise((r) => setTimeout(r, 8000));
      const r2 = await scanShodanFree(idx2, limit);
      await new Promise((r) => setTimeout(r, 8000));
      const r3 = await scanShodanFree(idx3, limit);
      await new Promise((r) => setTimeout(r, 8000));
      const r4 = await scanShodanFree(idx4, limit);
      return r1.addedToLeads + r2.addedToLeads + r3.addedToLeads + r4.addedToLeads;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Shodan discovery cron scheduled (daily 04:15 Istanbul, 4 queries/night, limit:300 each)");

    // ─── Lead Discovery: RIPE DNS — Her gece 02:00 ────────────────────────────
    // Türkiye IPv4 prefix'lerinden reverse DNS → yeni .tr domain keşfi (API key gerektirmez)
    cron.schedule("0 2 * * *", wrapCron("ripe_dns", "0 2 * * *", async () => {
      if (!await cronIsEnabled("ripe_dns")) { logger.info("RIPE DNS cron devre dışı, atlanıyor"); return 0; }
      const limit = await cronGetLimit("ripe_dns", 60);
      const result = await runRipeDiscovery({ maxPrefixes: limit });
      return result.addedToLeads;
    }), { timezone: "Europe/Istanbul" });
    logger.info("RIPE DNS discovery cron scheduled (daily 02:00 Istanbul, maxPrefixes:60)");

    // ─── Startup: BRIDGE_SECRET uyarısı ──────────────────────────────────────
    if (!process.env["BRIDGE_SECRET"]) {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const suggested = (require("crypto") as typeof import("crypto")).randomBytes(32).toString("hex");
      logger.warn({ suggested }, "BRIDGE_SECRET tanımlı değil — GitHub Actions bridge devre dışı. Replit Secrets ve GitHub Secrets'a aynı değeri ekle: BRIDGE_SECRET");
    }

    // ─── Lead Discovery: Netcraft — Her gece 05:30 ────────────────────────────
    cron.schedule("30 5 * * *", wrapCron("netcraft_discovery", "30 5 * * *", async () => {
      if (!await cronIsEnabled("netcraft_discovery")) { logger.info("Netcraft cron devre dışı, atlanıyor"); return 0; }
      const result = await runNetcraftDiscovery();
      return result.addedToLeads;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Netcraft discovery cron scheduled (daily 05:30 Istanbul)");

    // ─── Lead Discovery: BGP.tools — Her gece 06:15 ───────────────────────────
    cron.schedule("15 6 * * *", wrapCron("bgptools_discovery", "15 6 * * *", async () => {
      if (!await cronIsEnabled("bgptools_discovery")) { logger.info("BGP.tools cron devre dışı, atlanıyor"); return 0; }
      const result = await runBgpToolsDiscovery();
      return result.addedToLeads;
    }), { timezone: "Europe/Istanbul" });
    logger.info("BGP.tools discovery cron scheduled (daily 06:15 Istanbul)");

    // ─── Lead Discovery: URLScan.io — Her Pazartesi 03:00 ─────────────────────
    // Ücretsiz: ~100 istek/gün; URLSCAN_API_KEY varsa 1000/gün
    cron.schedule("0 3 * * 1", wrapCron("urlscan_discovery", "0 3 * * 1", async () => {
      if (!await cronIsEnabled("urlscan_discovery")) { logger.info("URLScan cron devre dışı, atlanıyor"); return 0; }
      const result = await runUrlscanDiscovery(5);
      return result.addedToLeads;
    }), { timezone: "Europe/Istanbul" });
    logger.info("URLScan discovery cron scheduled (Pazartesi 03:00 Istanbul, 5 sayfa)");

    // ─── Lead Discovery: VirusTotal Subdomain — Her Salı 04:00 ───────────────
    // VIRUSTOTAL_API_KEY gerekli; 4 istek/dakika limit — 50 domain × 15s bekleme
    cron.schedule("0 4 * * 2", wrapCron("virustotal_discovery", "0 4 * * 2", async () => {
      if (!await cronIsEnabled("virustotal_discovery")) { logger.info("VirusTotal cron devre dışı, atlanıyor"); return 0; }
      const limit = await cronGetLimit("virustotal_discovery", 50);
      const result = await runVirusTotalDiscovery(limit);
      return result.addedToLeads;
    }), { timezone: "Europe/Istanbul" });
    logger.info("VirusTotal subdomain cron scheduled (Salı 04:00 Istanbul, limit 50)");

    // ─── Lead Discovery: Censys SSL — Her gece 07:00 ──────────────────────────
    // CENSYS_API_ID + CENSYS_API_SECRET gerekli (censys.io ücretsiz hesap); 250 sorgu/ay limit
    cron.schedule("0 7 * * *", wrapCron("censys_discovery", "0 7 * * *", async () => {
      if (!await cronIsEnabled("censys_discovery")) { logger.info("Censys cron devre dışı, atlanıyor"); return 0; }
      const result = await runCensysDiscovery();
      return result.addedToLeads;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Censys discovery cron scheduled (daily 07:00 Istanbul, 3 TLD sorgusu)");

    // ─── Lead Discovery: Bing Dorking — Her gece 08:00 ────────────────────────
    // API key gerektirmez; Bing sonuçlarından .tr domain keşfi
    cron.schedule("0 8 * * *", wrapCron("search_dorking", "0 8 * * *", async () => {
      if (!await cronIsEnabled("search_dorking")) { logger.info("Search dorking cron devre dışı, atlanıyor"); return 0; }
      const result = await runSearchDorking();
      return result.addedToLeads;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Search dorking cron scheduled (daily 08:00 Istanbul, 5 Bing sorgusu)");

    // ─── Lead Discovery: OpenCorporates — Her Pazartesi 09:00 ─────────────────
    // API key gerektirmez; Türkiye şirket kaydından domain keşfi
    cron.schedule("0 9 * * 1", wrapCron("company_registry", "0 9 * * 1", async () => {
      if (!await cronIsEnabled("company_registry")) { logger.info("Company registry cron devre dışı, atlanıyor"); return 0; }
      const result = await runCompanyRegistryDiscovery();
      return result.addedToLeads;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Company registry cron scheduled (Pazartesi 09:00 Istanbul, 5 sayfa/hafta)");

    // ─── Source Quality Check — Her Pazartesi 08:30 ─────────────────────────────
    // Kalifikasyon oranı düşük kaynaklara ait uyarıları logla
    cron.schedule("30 8 * * 1", wrapCron("source_quality_check", "30 8 * * 1", async () => {
      if (!await cronIsEnabled("source_quality_check")) { logger.info("Source quality check devre dışı, atlanıyor"); return 0; }
      const stats = await getSourceQualityStats(30);
      let warnings = 0;
      for (const s of stats) {
        if (Number(s.total_scanned) >= 50 && Number(s.qualification_rate) < 10) {
          logger.warn(
            { source: s.source, qualification_rate: s.qualification_rate, total_scanned: s.total_scanned },
            `Kaynak kalitesi düşük: ${s.source} — %${s.qualification_rate} (%10 altında)`,
          );
          warnings++;
        }
      }
      return warnings;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Source quality check cron scheduled (Pazartesi 08:30 Istanbul)");

    // ─── Lead Discovery: Kalifikasyon — Her 20 dakikada bir ─────────────────────
    // Limit 200/çalışma: 3×200×24=14400 aday/gün. Her aday max 25s tarama + 25 dk circuit breaker.
    cron.schedule("*/5 * * * *", wrapCron("lead_prescreen", "*/5 * * * *", async () => {
      if (!await cronIsEnabled("lead_prescreen")) { logger.info("Lead ön-eleme cron devre dışı, atlanıyor"); return 0; }
      const limit = await cronGetLimit("lead_prescreen", 500);
      const result = await preScreenPendingCandidates(limit);
      return result.promoted;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Lead prescreen cron scheduled (her 5 dakika, limit 500)");

    cron.schedule("*/5 * * * *", wrapCron("lead_qual", "*/5 * * * *", async () => {
      if (!await cronIsEnabled("lead_qual")) { logger.info("Lead kalifikasyon cron devre dışı, atlanıyor"); return 0; }
      const limit = await cronGetLimit("lead_qual", 300);
      const result = await qualifyPendingCandidates(limit);
      return result.qualified;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Lead qualification cron scheduled (her 5 dakika, limit 300)");

    // ─── WAF Post-Qualification Enrichment — Her 30 dakika ────────────────────
    // Kalifikasyondan geçmiş lead'ler için WAF tespiti. Limit 50/run × 30dk = ~9 saat
    // için 886 lead. Atomic UPDATE...RETURNING + FOR UPDATE SKIP LOCKED ile
    // iki eşzamanlı run aynı satırı işleyemez. Timeout≠sonuç: sadece gerçek
    // detectWAF sonuçları waf_enriched_at'i set eder.
    cron.schedule("*/30 * * * *", wrapCron("waf_enrichment", "*/30 * * * *", async () => {
      if (!await cronIsEnabled("waf_enrichment")) { logger.info("WAF enrichment cron devre dışı, atlanıyor"); return 0; }
      const { runWafEnrichmentCron, runDomainScanWafEnrichment } = await import("./services/wafEnrichmentCron");
      const n1 = await runWafEnrichmentCron();
      const n2 = await runDomainScanWafEnrichment();
      return n1 + n2;
    }), { timezone: "Europe/Istanbul" });
    logger.info("WAF enrichment cron scheduled (her 30 dakika, limit 50/run)");

    // ─── Sektör Keyword Enrichment — Her 6 saatte bir ─────────────────────────
    // Pure CPU, harici API yok. Qualified domain'ler önce (ORDER BY is_qualified DESC).
    // Mevcut sector='teknoloji' AND sector_confidence IS NULL kayıtları da yeniden hesaplanır.
    // Eşleşme yoksa sector=NULL (null=bilinmiyor, 'Diğer' kullanılmaz).
    cron.schedule("0 */6 * * *", wrapCron("sector_enrichment", "0 */6 * * *", async () => {
      if (!await cronIsEnabled("sector_enrichment")) { logger.info("Sektör enrichment cron devre dışı, atlanıyor"); return 0; }
      const { runSectorEnrichmentCron } = await import("./services/sectorEnrichmentCron");
      const result = await runSectorEnrichmentCron();
      return result.updated + result.cleared;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Sektör enrichment cron scheduled (her 6 saatte bir)");

    // ─── Haiku Domain Enrichment — Her gece 02:30 Istanbul ───────────────────
    // lead_candidates.enrichment_status='pending' domainleri Claude Haiku ile zenginleştirir.
    // Batch: 500 domain/gece, ~$0.08/gece. Rate limit: 5 istek/sn.
    cron.schedule("30 2 * * *", wrapCron("haiku_enrichment", "30 2 * * *", async () => {
      if (!await cronIsEnabled("haiku_enrichment")) { logger.info("Haiku enrichment cron devre dışı, atlanıyor"); return 0; }
      const { runEnrichmentBatch } = await import("./services/enrichment/batch-enrichment");
      const result = await runEnrichmentBatch();
      return result.enriched + result.no_match;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Haiku enrichment cron scheduled (her gece 02:30 Istanbul)");

    // ─── Blacklist Monitoring — Her gece 03:00 Istanbul ──────────────────────
    // domain_scans'teki domainleri Spamhaus/SURBL/MXToolbox/SafeBrowsing ile kontrol eder.
    // 24 saatten eski veya hiç kontrol edilmemiş 50 domain/gece.
    cron.schedule("0 3 * * *", wrapCron("blacklist_monitor", "0 3 * * *", async () => {
      if (!await cronIsEnabled("blacklist_monitor")) { logger.info("Blacklist monitor cron devre dışı, atlanıyor"); return 0; }
      const { runBlacklistMonitor } = await import("./services/monitoring/blacklist-monitor");
      const result = await runBlacklistMonitor(50);
      return result.processed;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Blacklist monitor cron kayıtlandı (her gece 03:00 Istanbul)");

    // ─── SSL Monitor — Her gece 03:15 Istanbul ────────────────────────────────
    // domain_scans'teki domainleri SSL sertifika geçerliliği açısından kontrol eder.
    // 7 günden eski veya hiç kontrol edilmemiş 30 domain/gece.
    cron.schedule("15 3 * * *", wrapCron("ssl_monitor", "15 3 * * *", async () => {
      if (!await cronIsEnabled("ssl_monitor")) { logger.info("SSL monitor cron devre dışı, atlanıyor"); return 0; }
      const { runSslMonitor } = await import("./services/monitoring/ssl-mail-monitor");
      const result = await runSslMonitor(30);
      return result.processed;
    }), { timezone: "Europe/Istanbul" });
    logger.info("SSL monitor cron kayıtlandı (her gece 03:15 Istanbul)");

    // ─── Mail Reputation Monitor — Her gece 03:30 Istanbul ───────────────────
    // domain_scans'teki domainleri SPF/DKIM/DMARC/MX açısından kontrol eder.
    // 7 günden eski veya hiç kontrol edilmemiş 50 domain/gece.
    cron.schedule("30 3 * * *", wrapCron("mail_monitor", "30 3 * * *", async () => {
      if (!await cronIsEnabled("mail_monitor")) { logger.info("Mail monitor cron devre dışı, atlanıyor"); return 0; }
      const { runMailMonitor } = await import("./services/monitoring/ssl-mail-monitor");
      const result = await runMailMonitor(50);
      return result.processed;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Mail reputation monitor cron kayıtlandı (her gece 03:30 Istanbul)");

    // ─── Reputation Orchestrator — Her gece 03:45 Istanbul ───────────────────
    // Blacklist + SSL + mail pipeline'ını toparlayan özet cron; overall_score
    // reputation faktörlerini (kara liste, geçersiz SSL, zayıf mail) hesaba katar.
    cron.schedule("45 3 * * *", wrapCron("reputation_orchestrator", "45 3 * * *", async () => {
      if (!await cronIsEnabled("reputation_orchestrator")) { logger.info("Reputation orchestrator cron devre dışı, atlanıyor"); return 0; }
      const { runReputationMonitoring } = await import("./services/reputationOrchestrator");
      const result = await runReputationMonitoring();
      return result.processed;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Reputation orchestrator cron kayıtlandı (her gece 03:45 Istanbul)");

    // ─── Brand & Typosquatting Monitor — Her Pazar 04:00 Istanbul ───────────
    cron.schedule("0 4 * * 0", wrapCron("brand_monitor", "0 4 * * 0", async () => {
      if (!await cronIsEnabled("brand_monitor")) { logger.info("Brand monitor cron devre dışı, atlanıyor"); return 0; }
      const { runBrandMonitoring } = await import("./services/brandMonitor/brandMonitorOrchestrator");
      const result = await runBrandMonitoring();
      return result.new_variants;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Brand monitor cron kayıtlandı (her Pazar 04:00 Istanbul)");

    // ─── Aylık Metrik Toplama — Her ayın 1'i 06:00 Istanbul ──────────────────
    // domain_scans + lead_candidates'tan temel güvenlik metriklerini toplar.
    // Sonuç report_metrics_snapshot tablosuna yazılır; AI içerik üretimi bu veriden beslenir.
    cron.schedule("0 6 1 * *", wrapCron("report_metrics_collector", "0 6 1 * *", async () => {
      if (!await cronIsEnabled("report_metrics_collector")) { logger.info("Metrik toplama cron devre dışı, atlanıyor"); return 0; }
      const { runReportMetricsCollector } = await import("./services/reportMetricsCollector");
      const result = await runReportMetricsCollector();
      return result.snapshotsWritten;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Rapor metrik toplama cron kayıtlandı (her ayın 1'i 06:00 Istanbul)");

    // ─── Otomatik Taslak + Onaya Gönder — Her ayın 1'i 08:00 Istanbul ─────────
    // Metrik toplama (06:00) bittikten 2 saat sonra çalışır.
    // Mevcut ay için rapor yoksa taslak oluşturur ve doğrudan pending_review'a alır.
    // Idempotent: aynı periyot için ikinci kez çalışırsa atlar.
    cron.schedule("0 8 1 * *", wrapCron("report_auto_submit", "0 8 1 * *", async () => {
      if (!await cronIsEnabled("report_auto_submit")) { logger.info("report_auto_submit cron devre dışı, atlanıyor"); return 0; }
      const { db: _db } = await import("@workspace/db");
      const { cyberRiskReportsTable: _tbl } = await import("@workspace/db");
      const { eq: _eq } = await import("drizzle-orm");
      const now = new Date();
      const periodLabel = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
      const periodType = "monthly";
      const webSlug = `${periodType}-${periodLabel}`;
      // Idempotency: bu periyot için zaten bir rapor var mı?
      const existing = await _db.select({ id: _tbl.id })
        .from(_tbl)
        .where(_eq(_tbl.periodLabel, periodLabel))
        .limit(1);
      if (existing.length > 0) {
        logger.info({ periodLabel, existingId: existing[0]?.id }, "report_auto_submit: bu dönem için rapor zaten var, atlanıyor");
        return 0;
      }
      const [inserted] = await _db.insert(_tbl).values({
        periodType,
        periodLabel,
        sector: null,
        status: "pending_review",
        reportData: null,
        webSlug,
        reviewNotes: "Otomatik oluşturuldu — metrik toplama sonrası",
      }).returning();
      logger.info({ id: inserted?.id, periodLabel }, "report_auto_submit: taslak oluşturuldu ve onaya gönderildi");
      return 1;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Rapor otomatik taslak + onaya gönder cron kayıtlandı (her ayın 1'i 08:00 Istanbul)");

    // Her ayın 1'i 05:00 Istanbul — aylık executive CISO raporu
    cron.schedule("0 5 1 * *", wrapCron("executive_report_monthly", "0 5 1 * *", async () => {
      if (!await cronIsEnabled("executive_report_monthly")) { logger.info("executive_report_monthly cron devre dışı, atlanıyor"); return 0; }
      const { generateMonthlyReports } = await import("./services/executive/executiveReportOrchestrator");
      const result = await generateMonthlyReports();
      logger.info(result, "executive_report_monthly tamamlandı");
      return result.generated;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Executive CISO raporu cron kayıtlandı (her ayın 1'i 05:00 Istanbul)");

    // Her Çarşamba 04:30 Istanbul — haftalık data leakage tarama
    cron.schedule("30 4 * * 3", wrapCron("data_leakage_monitor", "30 4 * * 3", async () => {
      if (!await cronIsEnabled("data_leakage_monitor")) { logger.info("data_leakage_monitor cron devre dışı, atlanıyor"); return 0; }
      const { runLeakageMonitoring } = await import("./services/dataLeakage/leakageOrchestrator");
      const result = await runLeakageMonitoring();
      logger.info(result, "data_leakage_monitor tamamlandı");
      return result.new_incidents;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Data leakage monitor cron kayıtlandı (her Çarşamba 04:30 Istanbul)");

    cron.schedule("0 9 * * 1", wrapCron("ecosystem_report", "0 9 * * 1", async () => {
      if (!await cronIsEnabled("ecosystem_report")) { return 0; }
      const report = await generateEcosystemReport(30);
      logger.info({ totalScanned: report.intake.totalScanned, dmarcMissingPct: report.security.dmarcMissingPct }, "Haftalık ekosistem raporu üretildi");
      return 1;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Ekosistem raporu cron scheduled (Pazartesi 09:00 Istanbul)");

    // ─── VulnCheck KEV — her gece 01:00 Istanbul ──────────────────────────────
    cron.schedule("0 1 * * *", wrapCron("vulncheck_kev", "0 1 * * *", async () => {
      if (!await cronIsEnabled("vulncheck_kev")) { logger.info("VulnCheck KEV cron devre dışı, atlanıyor"); return 0; }
      const result = await fetchVulnCheckKEV();
      return result.upserted;
    }), { timezone: "Europe/Istanbul" });
    logger.info("VulnCheck KEV cron kayıtlandı (gece 01:00 Istanbul)");

    // ─── CTI Intel Feeds — her 6 saatte bir ──────────────────────────────────
    cron.schedule("0 */6 * * *", wrapCron("intel_feeds", "0 */6 * * *", async () => {
      if (!await cronIsEnabled("intel_feeds")) { logger.info("Intel feeds cron devre dışı, atlanıyor"); return 0; }
      const result = await checkIntelFeeds();
      return result.newItems;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Intel feeds cron kayıtlandı (her 6 saatte bir)");

    // ─── Yıllık rapor takvim hatırlatması — her ayın 1'i 09:00 Istanbul ──────
    cron.schedule("0 9 1 * *", wrapCron("annual_report_reminder", "0 9 1 * *", async () => {
      await sendMonthlyReportReminder();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Yıllık rapor hatırlatma cron kayıtlandı (ayın 1'i 09:00 Istanbul)");

    // ─── CT Log phishing izleme — her 4 saatte ────────────────────────────────
    cron.schedule("0 */4 * * *", wrapCron("ct_phishing_monitor", "0 */4 * * *", async () => {
      const count = await checkPhishingCertificates();
      logger.info({ count }, "CT phishing monitor tamamlandı");
      return count;
    }), { timezone: "Europe/Istanbul" });
    logger.info("CT phishing monitor cron scheduled (every 4h Istanbul)");

    // ─── Abonelik bitiş hatırlatmaları — her gün 10:00 İstanbul ──────────────
    cron.schedule("40 10 * * *", wrapCron("subscription_reminders", "40 10 * * *", async () => {
      await checkSubscriptionExpiryReminders();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Subscription expiry reminder cron scheduled (daily 10:00 Istanbul)");

    // ─── CVE feed check — her 2 saatte bir ───────────────────────────────────
    cron.schedule("0 */2 * * *", wrapCron("cve_feed_check", "0 */2 * * *", async () => {
      await runCVEFeedCheck();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("CVE feed check cron scheduled (every 2 hours)");

    // ─── Kritik CVE müşteri bildirimi (CVSS 9+) — her 4 saatte ──────────────
    cron.schedule("0 */4 * * *", wrapCron("cve_customer_notification", "0 */4 * * *", async () => {
      const { runCveCustomerNotification } = await import("./services/cve/cveHighCvssNotifier");
      return await runCveCustomerNotification();
    }), { timezone: "Europe/Istanbul" });
    logger.info("CVE customer notification sweep cron scheduled (every 4 hours)");

    // ─── CVE patch recheck — patch_available=false, son 60 gün, günlük 06:00 ──
    // Yeni CVE'lerde patch ilk haftalar içinde çıkıyor; 60 gün sonra ihtimal düşüyor.
    cron.schedule("0 6 * * *", wrapCron("cve_patch_recheck", "0 6 * * *", async () => {
      const { recheckPatchStatus } = await import("./services/cve/cvePatchRecheck");
      const r = await recheckPatchStatus({ maxAgeDays: 60, maxItems: 50 });
      return r.updated;
    }), { timezone: "Europe/Istanbul" });
    logger.info("CVE patch recheck cron kayıtlandı (günlük 06:00, 60 günlük pencere)");

    // ─── CVE domain retroaktif re-match — Her gece 03:00 Istanbul ────────────
    // Günlük yeni eklenen domain_scans kayıtlarını mevcut CVE'lerle eşleştirir.
    // Bu cron olmadan CVE Raporu'nda etkilenen domain sayısı artmaz.
    cron.schedule("0 3 * * *", wrapCron("cve_rematch_domains", "0 3 * * *", async () => {
      const { rematchCveDomains } = await import("./services/cve/turkeyImpactAnalyzer");
      const r = await rematchCveDomains();
      return r.newMatches;
    }), { timezone: "Europe/Istanbul" });
    logger.info("CVE domain re-match cron kayıtlandı (günlük 03:00)");

    // ─── EPSS + CISA KEV Intelligence Sync — Her gece 03:15 Istanbul ─────────
    cron.schedule("15 3 * * *", wrapCron("sync_vuln_intel", "15 3 * * *", async () => {
      const { syncVulnIntelligence } = await import("./services/cve/vulnIntelSync");
      await syncVulnIntelligence();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("EPSS + KEV intelligence sync cron kayıtlandı (03:15 günlük)");

    // Her Cuma 08:00 Istanbul — haftalık bülten üret
    cron.schedule("0 8 * * 5", wrapCron("haftalik_bulten", "0 8 * * 5", async () => {
      const { collectWeeklyData } = await import("./services/bulletin/weeklyDataCollector");
      const { generateBulletinContent } = await import("./services/bulletin/bulletinWriter");
      const { weeklyBulletinsTable, bulletinSubscribersTable } = await import("@workspace/db");
      const { eq } = await import("drizzle-orm");
      const { getISOWeek } = await import("./services/discoveryPipeline");

      // Abone kontrolü — sıfır abone varsa içerik üretmeye değmez
      const subRows = await db.select({ id: bulletinSubscribersTable.id }).from(bulletinSubscribersTable).limit(1);
      if (subRows.length === 0) {
        logger.info("Haftalık bülten atlandı: hiç abone yok");
        return 0;
      }

      const now = new Date();
      const weekNumber = getISOWeek(now);
      const year = now.getFullYear();
      const slug = `tr-${year}-w${weekNumber}`;
      const existing = await db.select({ id: weeklyBulletinsTable.id })
        .from(weeklyBulletinsTable).where(eq(weeklyBulletinsTable.weekSlug, slug)).limit(1);
      if (existing[0]) { logger.info({ weekNumber }, "Haftalik bulten zaten mevcut"); return 0; }
      const weekEnd = now;
      const weekStart = new Date(now.getTime() - 7 * 24 * 3600 * 1000);
      const data = await collectWeeklyData(weekStart, weekEnd);
      const content = await generateBulletinContent(data, weekNumber, year);
      await db.insert(weeklyBulletinsTable).values({
        countryCode: "TR", weekNumber, year, weekSlug: slug,
        dateRangeStart: weekStart.toISOString().slice(0, 10),
        dateRangeEnd: weekEnd.toISOString().slice(0, 10),
        totalScansThisWeek: data.totalScans,
        newCriticalCves: data.newCriticalCVEs.length,
        topFindingType: data.topFindingType,
        notableSector: data.topSector ?? undefined,
        headline: content.headline, introText: content.introText,
        threatRadar: content.threatRadar, turkeyData: content.turkeyData,
        regulationSection: content.regulationSection, weeklyTip: content.weeklyTip,
        toolResource: content.toolResource, emailSubject: content.emailSubject,
        emailPreview: content.emailPreview, emailHtml: content.emailHtml,
        linkedinMiniPost: content.linkedinMiniPost, status: "review",
      });
      logger.info({ weekNumber, year }, "Haftalık bülten cron tamamlandı");
      return 1;
    }), { timezone: "Europe/Istanbul" });
    logger.info("Haftalık bülten cron kayıtlandı (Cuma 08:00 Istanbul)");

    // ─── Günlük DB Yedeği — Her gece 03:00 Istanbul ─────────────────────────
    cron.schedule("0 3 * * *", wrapCron("daily_db_backup", "0 3 * * *", async () => {
      const { runDbBackup } = await import("./services/dbBackup");
      return await runDbBackup();
    }), { timezone: "Europe/Istanbul" });
    logger.info("Günlük DB yedek cron kayıtlandı (Her gece 03:00 Istanbul)");

    // ─── Haftalık DB Yedeği — Her Pazar 04:00 Istanbul ──────────────────────
    cron.schedule("0 4 * * 0", wrapCron("weekly_db_backup", "0 4 * * 0", async () => {
      const { runDbBackup } = await import("./services/dbBackup");
      return await runDbBackup();
    }), { timezone: "Europe/Istanbul" });
    logger.info("Haftalık DB yedek cron kayıtlandı (Pazar 04:00 Istanbul)");

    // ─── CISO Asistan: Aylık Board Raporu — Her ayın 25'i 09:00 Istanbul ────
    cron.schedule("0 9 25 * *", wrapCron("ciso_board_report", "0 9 25 * *", async () => {
      const { db: cisoDb } = await import("@workspace/db");
      const { cisoAssistantSubscriptionsTable: cisoSubsTable } = await import("@workspace/db");
      const { eq: eqFn } = await import("drizzle-orm");
      const { generateBoardReport } = await import("./services/ciso/boardReportGenerator");
      const subs = await cisoDb.select().from(cisoSubsTable).where(eqFn(cisoSubsTable.isActive, true));
      logger.info({ count: subs.length }, "CISO board raporu cron başladı");
      for (const sub of subs) {
        try { await generateBoardReport(sub.customerId!); await new Promise(r => setTimeout(r, 5000)); }
        catch (err) { logger.error({ err, customerId: sub.customerId }, "Board raporu hatası"); }
      }
      return subs.length;
    }), { timezone: "Europe/Istanbul" });
    logger.info("CISO board raporu cron kayıtlandı (ayın 25'i 09:00 Istanbul)");

    // ─── CISO Asistan: Haftalık Tehdit Özeti — Her Cuma 09:30 Istanbul (09:00'da market_weekly_summary var) ───
    cron.schedule("30 9 * * 5", wrapCron("ciso_weekly_threat", "30 9 * * 5", async () => {
      const { db: cisoDb } = await import("@workspace/db");
      const { cisoAssistantSubscriptionsTable: cisoSubsTable, customersTable: custTable, domainScansTable: scanTable, weeklyBulletinsTable } = await import("@workspace/db");
      const { eq: eqFn, desc: descFn } = await import("drizzle-orm");
      const { sendMail: sendMailFn } = await import("./services/email");
      const { anthropic: anthropicClient } = await import("@workspace/integrations-anthropic-ai");
      const subs = await cisoDb.select().from(cisoSubsTable).where(eqFn(cisoSubsTable.isActive, true));
      const [latestBulletin] = await cisoDb.select().from(weeklyBulletinsTable).where(eqFn(weeklyBulletinsTable.status, "published")).orderBy(descFn(weeklyBulletinsTable.id)).limit(1);
      logger.info({ count: subs.length, hasBulletin: !!latestBulletin }, "CISO haftalık tehdit cron başladı");
      for (const sub of subs) {
        if (!sub.customerId) continue;
        try {
          const [customer] = await cisoDb.select().from(custTable).where(eqFn(custTable.id, sub.customerId)).limit(1);
          if (!customer) continue;
          const [scan] = await cisoDb.select().from(scanTable).where(eqFn(scanTable.email, customer.email)).orderBy(descFn(scanTable.id)).limit(1);
          const scoreText = scan ? `Güvenlik skoru: ${scan.overallScore}/100` : "";
          const { callModel: callAiModel } = await import("@workspace/ai");
          const intro = await callAiModel({
            task: "ciso-weekly-digest",
            system: "Türk KOBİ için kişiselleştirilmiş siber güvenlik haftalık özeti yaz. Kısa, akıcı Türkçe.",
            messages: [{ role: "user", content: `${customer.companyName ?? customer.email} için haftalık tehdit özeti. ${scoreText}. Bu hafta yapılması gereken 1 şeyi belirt.` }],
            maxTokens: 200,
          });
          const introSafe = intro.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
          await sendMailFn({
            to: customer.email,
            subject: `Haftalık Siber Tehdit Özeti — ${new Date().toLocaleDateString("tr-TR", { day: "numeric", month: "long" })}`,
            html: `<p>Merhaba ${customer.companyName ?? ""},</p><p>${introSafe}</p>${latestBulletin?.emailHtml ? `<hr style="margin:16px 0">${latestBulletin.emailHtml}` : ""}<br><small style="color:#888">CyberStep CISO Asistan — <a href="mailto:info@cyberstep.io">info@cyberstep.io</a></small>`,
          });
          await new Promise(r => setTimeout(r, 2000));
        } catch (err) { logger.error({ err, customerId: sub.customerId }, "Haftalık tehdit özeti hatası"); }
      }
      return subs.length;
    }), { timezone: "Europe/Istanbul" });
    logger.info("CISO haftalık tehdit cron kayıtlandı (Cuma 09:30 Istanbul)");

    // ─── CISO Asistan: Aylık Uyum Skoru — Her ayın 1'i 08:00 Istanbul ────────
    cron.schedule("0 8 1 * *", wrapCron("ciso_compliance_monthly", "0 8 1 * *", async () => {
      const { db: cisoDb } = await import("@workspace/db");
      const { cisoAssistantSubscriptionsTable: cisoSubsTable } = await import("@workspace/db");
      const { eq: eqFn } = await import("drizzle-orm");
      const { calculateComplianceScore } = await import("./services/ciso/complianceCalculator");
      const subs = await cisoDb.select().from(cisoSubsTable).where(eqFn(cisoSubsTable.isActive, true));
      for (const sub of subs) {
        if (!sub.customerId) continue;
        try { await calculateComplianceScore(sub.customerId); await new Promise(r => setTimeout(r, 1000)); }
        catch (err) { logger.error({ err, customerId: sub.customerId }, "Uyum skoru güncelleme hatası"); }
      }
      return subs.length;
    }), { timezone: "Europe/Istanbul" });
    logger.info("CISO uyum skoru cron kayıtlandı (ayın 1'i 08:00 Istanbul)");

    // ─── IOC Sorgu: Aylık Kredi Sıfırlama — Her ayın 1'i 08:30 Istanbul (08:00'da ciso_compliance_monthly var) ─────
    cron.schedule("30 8 1 * *", wrapCron("ioc_credit_reset", "30 8 1 * *", async () => {
      const { resetMonthlyCredits } = await import("./services/iocCreditManager");
      return await resetMonthlyCredits();
    }), { timezone: "Europe/Istanbul" });
    logger.info("IOC kredi sıfırlama cron kayıtlandı (ayın 1'i 08:30 Istanbul)");

    // ─── Demo Rapor Yenileme — Her ayın 1'i 10:00 Istanbul ──────────────────
    cron.schedule("0 10 1 * *", wrapCron("demo_report_refresh", "0 10 1 * *", async () => {
      const { generateAllDemoReports } = await import("./services/demoReportGenerator");
      await generateAllDemoReports();
    }), { timezone: "Europe/Istanbul" });
    logger.info("Demo rapor yenileme cron kayıtlandı (ayın 1'i 10:00 Istanbul)");

    // ─── HITL Approval Queue: Süresi Dolmuş Onayları İşle — Her 15 dakika ──
    cron.schedule("*/15 * * * *", wrapCron("hitl_expire", "*/15 * * * *", async () => {
      const { processExpiredApprovals } = await import("./services/approvalQueue");
      await processExpiredApprovals();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("HITL approval expire cron kayıtlandı (her 15 dakika)");

    // ─── TPRM Vendor Nightly Rescan: Her gece 02:00 ──────────────────────────
    cron.schedule("0 2 * * *", wrapCron("tprm_vendor_rescan", "0 2 * * *", async () => {
      const { runVendorRescanCron } = await import("./routes/tprm/index");
      await runVendorRescanCron();
      return 0;
    }), { timezone: "Europe/Istanbul" });
    logger.info("TPRM vendor rescan cron kayıtlandı (gece 02:00 Istanbul)");

    // ─── Startup: Stale "running" kayıtları temizle ─────────────────────────
    // Server restart sırasında tamamlanamayan "running" durumundaki cron kayıtlarını düzelt.
    void cleanupStaleRunningJobs();
    startCronWatchdog();
    void cleanupStaleDiscoveryRuns();

    // ─── Startup: Yarım kalan "scanning" / "prescreening" lead adaylarını sıfırla ─
    // Server restart sırasında:
    //   • "scanning"     → lead_qual tarafından alınmış ama bitirilememiş
    //   • "prescreening" → preScreen tarafından claim edilmiş, tier2'ye terfi etmiş
    //                       ama scanStatus='pending' yazılmamış (promotion bug recovery)
    // Her iki durumda da lead_qual sorgusu yalnızca "pending" çektiğinden
    // bunlar hiç işlenmez. Restart'ta hepsini "pending"e döndür.
    void (async () => {
      try {
        const { rowCount } = await db.execute(
          sql`UPDATE lead_candidates SET scan_status = 'pending', updated_at = now()
              WHERE scan_status IN ('scanning', 'prescreening')`
        );
        if ((rowCount ?? 0) > 0) {
          logger.warn({ count: rowCount }, "Startup: stale 'scanning'/'prescreening' lead adayları 'pending'e döndürüldü");
        }
      } catch (e) {
        logger.error({ err: String(e) }, "Startup: stale scanning/prescreening lead cleanup başarısız");
      }
    })();

    // ─── Startup Catch-up: Kaçırılan Gece Cron'larını Çalıştır ──────────────
    // Deployment restart sırasında pencereyi kaçıran gece cron'larını telafi eder.
    // Her cron için son çalışma DB'den okunur; >25 saat geçmişse 30s delay ile çalıştırılır.
    setImmediate(async () => {
      const CATCH_UP_CRONS = [
        // External scan / enrichment — missed = stale threat intel
        { name: "crtsh",                    thresholdHours: 5   },  // her 4h → 5h buffer
        { name: "ripe_dns",                 thresholdHours: 25  },
        { name: "netcraft_discovery",       thresholdHours: 25  },
        { name: "bgptools_discovery",       thresholdHours: 25  },
        { name: "shodan",                   thresholdHours: 25  },
        { name: "usom_refresh",             thresholdHours: 25  },
        { name: "vulncheck_kev",            thresholdHours: 25  },
        { name: "intel_feeds",              thresholdHours: 7   },
        { name: "attack_path_analysis",     thresholdHours: 25  },
        { name: "cve_feed_check",           thresholdHours: 3   },
        { name: "cve_customer_notification", thresholdHours: 5  },
        { name: "cve_patch_recheck",         thresholdHours: 25 },
        { name: "cve_rematch_domains",       thresholdHours: 25 },
        { name: "sync_vuln_intel",           thresholdHours: 25 },
        { name: "free_scan_followup",        thresholdHours: 2  },
        { name: "cloud_cspm",               thresholdHours: 25  },
        { name: "fabric_fm_health",         thresholdHours: 25  },
        { name: "fabric_block_verify",      thresholdHours: 7   },
        // Hourly (2h threshold)
        { name: "certstream_dispatch",       thresholdHours: 2   },
        { name: "lead_prescreen",            thresholdHours: 1   },
        { name: "lead_qual",                thresholdHours: 2   },
        { name: "ecosystem_report",         thresholdHours: 200 },
        { name: "verification_queue",       thresholdHours: 2   },
        { name: "platform_smoke_test",      thresholdHours: 2   },
        { name: "sla_proactive_warning",    thresholdHours: 1   },
        { name: "ct_phishing_monitor",      thresholdHours: 5   },
        { name: "scan_lead_drip",           thresholdHours: 2   },
        { name: "lead_web_enrich",           thresholdHours: 25  },
        { name: "lead_tr_enrich",           thresholdHours: 25  },
        { name: "censys_discovery",         thresholdHours: 25  },
        { name: "search_dorking",           thresholdHours: 25  },
        { name: "servicenow_health",        thresholdHours: 2   },
        { name: "noc_baseline",             thresholdHours: 2   },
        // Lead & pipeline (daily)
        { name: "growth_ssl_expiry",        thresholdHours: 25  },
        { name: "growth_cve_alert",         thresholdHours: 25  },
        // Revenue / customer lifecycle (daily)
        { name: "upsell_engine",            thresholdHours: 25  },
        { name: "platform_cost_check",      thresholdHours: 25  },
        { name: "dunning_check",            thresholdHours: 25  },
        { name: "subscription_renewal",     thresholdHours: 25  },
        { name: "subscription_reminders",   thresholdHours: 25  },
        { name: "collection_reminder",      thresholdHours: 25  },
        { name: "health_score",             thresholdHours: 25  },
        // Customer comms (daily)
        { name: "reminder_30day",           thresholdHours: 25  },
        { name: "onboarding_day1_email",    thresholdHours: 25  },
        { name: "onboarding_d3d7",          thresholdHours: 25  },
        { name: "domain_rescan",            thresholdHours: 25  },
        { name: "sla_breach_check",           thresholdHours: 25  },
        { name: "churn_auto_intervention",     thresholdHours: 25  },
        { name: "customer_activation_monitor", thresholdHours: 25  },
        { name: "ai_quality_monitor",          thresholdHours: 25  },
        { name: "auto_invoice_generate",       thresholdHours: 25  },
        { name: "haiku_enrichment",         thresholdHours: 25  },
        { name: "blacklist_monitor",          thresholdHours: 25  },
        { name: "ssl_monitor",              thresholdHours: 25  },
        { name: "mail_monitor",             thresholdHours: 25  },
        { name: "reputation_orchestrator",  thresholdHours: 25  },
        // Weekly brand monitoring
        { name: "brand_monitor",            thresholdHours: 169 },
        // Internal / data (daily)
        { name: "daily_summary",            thresholdHours: 25  },
        { name: "daily_cron_report",        thresholdHours: 25  },
        { name: "market_watcher",           thresholdHours: 5   },
        { name: "digest_rss_collect",       thresholdHours: 25  },
        { name: "digest_enrich",            thresholdHours: 25  },
        { name: "kvkk_scheduled_deletion",  thresholdHours: 25  },
        { name: "auto_tag",                 thresholdHours: 25  },
        { name: "task_reminder",            thresholdHours: 25  },
        // Weekly (169h ≈ 7 days + 1h buffer)
        { name: "weekly_delta",             thresholdHours: 169 },
        { name: "haftalik_bulten",          thresholdHours: 169 },
        { name: "market_weekly_summary",    thresholdHours: 169 },
        { name: "soc_weekly_report",        thresholdHours: 169 },
        { name: "fabric_weekly_report",     thresholdHours: 169 },
        { name: "github_secrets_scan",      thresholdHours: 169 },
        { name: "ai_tool_monitor",          thresholdHours: 169 },
        { name: "blog_autopilot_mon",       thresholdHours: 169 },
        { name: "blog_autopilot_thu",       thresholdHours: 169 },
        { name: "ciso_weekly_threat",       thresholdHours: 169 },
        { name: "digest_weekly_generate",   thresholdHours: 169 },
        { name: "growth_port_change",       thresholdHours: 169 },
        { name: "inflation_reminder",       thresholdHours: 169 },
        { name: "price_auto_update",        thresholdHours: 8785 },
        { name: "annual_security_report",  thresholdHours: 8785 },
        { name: "nps_send",                 thresholdHours: 169 },
        { name: "social_media_weekly",      thresholdHours: 169 },
        { name: "weekly_db_backup",         thresholdHours: 169 },
        // Monthly (745h ≈ 31 days + 1h buffer)
        { name: "annual_report_reminder",   thresholdHours: 745 },
        { name: "ciso_board_report",        thresholdHours: 745 },
        { name: "ciso_compliance_monthly",  thresholdHours: 745 },
        { name: "demo_report_refresh",      thresholdHours: 745 },
        { name: "ioc_credit_reset",         thresholdHours: 745 },
        { name: "kvkk_data_retention",      thresholdHours: 745 },
        { name: "soc_monthly_ai_cost",      thresholdHours: 745 },
        { name: "report_auto_submit",       thresholdHours: 745 },
        { name: "executive_report_monthly", thresholdHours: 745 },
        // Weekly (169h ≈ 7 days + 1h buffer)
        { name: "data_leakage_monitor",     thresholdHours: 169 },
        // Quarterly (2200h ≈ 90 days + 1h buffer)
        { name: "quarterly_policy_update",  thresholdHours: 2200 },
      ];
      try {
        const { rows } = await pool.query<{ job_name: string; last_run: string }>(
          `SELECT job_name, MAX(started_at) AS last_run
           FROM cron_job_runs
           WHERE job_name = ANY($1) AND status IN ('ok','error')
           GROUP BY job_name`,
          [CATCH_UP_CRONS.map((c) => c.name)],
        );
        const lastRunMap = Object.fromEntries(rows.map((r) => [r.job_name, new Date(r.last_run)]));

        let delayMs = 30_000;
        for (const { name, thresholdHours } of CATCH_UP_CRONS) {
          const lastRun = lastRunMap[name];
          const hoursAgo = lastRun ? (Date.now() - lastRun.getTime()) / 3_600_000 : 999;
          if (hoursAgo < thresholdHours) continue;

          const fn = getCronFn(name);
          if (!fn) continue;

          logger.warn({ name, hoursAgo: Math.round(hoursAgo), delayMs }, `Startup catch-up: ${name} kaçırılmış — ${delayMs / 1000}s sonra çalıştırılacak`);
          const capturedFn = fn;
          const capturedDelay = delayMs;
          setTimeout(() => {
            capturedFn().catch((err: unknown) => logger.error({ err, name }, `Catch-up ${name} başarısız`));
          }, capturedDelay);
          delayMs += 90_000; // Aynı anda çakışmayı önlemek için 90s aralıklı başlat
        }
      } catch (err) {
        logger.warn({ err }, "Startup catch-up kontrolü başarısız");
      }
    });

    const server = app.listen(port, (err) => {
      if (err) {
        logger.error({ err }, "Error listening on port");
        process.exit(1);
      }
      logger.info({ port }, "Server listening");
    });
    initSOCWebSocket(server);
  })
  .catch((err: unknown) => {
    logger.error({ err }, "Startup error");
    process.exit(1);
  });
