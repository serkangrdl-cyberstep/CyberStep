import {
  pgTable, serial, integer, varchar, text, boolean,
  timestamp, jsonb, index,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const discoveryRunsTable = pgTable("discovery_runs", {
  id: serial("id").primaryKey(),
  source: varchar("source", { length: 50 }).notNull(),
  runParams: jsonb("run_params"),
  status: varchar("status", { length: 20 }).notNull().default("running"),
  totalFound: integer("total_found").notNull().default(0),
  totalAdded: integer("total_added").notNull().default(0),
  startedAt: timestamp("started_at").notNull().defaultNow(),
  completedAt: timestamp("completed_at"),
  errorMessage: text("error_message"),
}, (t) => [
  index("idx_discovery_runs_source").on(t.source),
]);

export const leadCandidatesTable = pgTable("lead_candidates", {
  id: serial("id").primaryKey(),
  domain: varchar("domain", { length: 255 }).unique().notNull(),
  companyName: varchar("company_name", { length: 255 }),
  sector: varchar("sector", { length: 100 }),
  subSector: varchar("sub_sector", { length: 150 }),
  sourceList: varchar("source_list", { length: 100 }),
  listRank: varchar("list_rank", { length: 50 }),
  city: varchar("city", { length: 100 }),
  source: varchar("source", { length: 50 }).notNull(),
  sourceData: jsonb("source_data"),
  hasFortigate: boolean("has_fortigate").notNull().default(false),
  scanStatus: varchar("scan_status", { length: 30 }).notNull().default("pending"),
  scanId: integer("scan_id"),
  riskScore: integer("risk_score"),
  criticalFindings: integer("critical_findings").notNull().default(0),
  findingHighlights: text("finding_highlights").array(),
  isQualified: boolean("is_qualified").notNull().default(false),
  contactName: varchar("contact_name", { length: 255 }),
  contactTitle: varchar("contact_title", { length: 255 }),
  contactEmail: varchar("contact_email", { length: 255 }),
  contactEmailConfidence: integer("contact_email_confidence"),
  contactSource: varchar("contact_source", { length: 50 }),
  teaserSubject: varchar("teaser_subject", { length: 500 }),
  teaserBody: text("teaser_body"),
  teaserGeneratedAt: timestamp("teaser_generated_at"),
  teaserSentAt: timestamp("teaser_sent_at"),
  isrLeadId: integer("isr_lead_id"),
  notes: text("notes"),
  officerName: varchar("officer_name", { length: 255 }),
  officerTitle: varchar("officer_title", { length: 100 }),
  isrNotes: text("isr_notes"),
  httpStatus: integer("http_status"),
  isAlive: boolean("is_alive"),
  responseTimeMs: integer("response_time_ms"),
  scrapedPhone: varchar("scraped_phone", { length: 50 }),
  scrapedAddress: text("scraped_address"),
  scrapedCompanyName: varchar("scraped_company_name", { length: 255 }),
  webScrapedAt: timestamp("web_scraped_at"),
  tier: varchar("tier", { length: 20 }).default("tier3"),
  lastScannedAt: timestamp("last_scanned_at"),
  scanDepth: varchar("scan_depth", { length: 20 }).default("lightweight"),
  needsManualContact: boolean("needs_manual_contact").default(false),
  ispOrganization: text("isp_organization"),
  isrPromotedAt: timestamp("isr_promoted_at"),
  isrCustomerId: integer("isr_customer_id"),
  isrFollowupD3SentAt: timestamp("isr_followup_d3_sent_at"),
  isrFollowupD7SentAt: timestamp("isr_followup_d7_sent_at"),
  hasKevMatch: boolean("has_kev_match").notNull().default(false),
  // ─── WAF Post-Qualification Enrichment ───────────────────────────────────
  // Atomic claim lock: SET before processing, cleared on completion or timeout-retry
  wafEnrichingStartedAt: timestamp("waf_enriching_started_at"),
  // Set ONLY when a real result is obtained (not on timeout). null = pending/unknown.
  wafEnrichedAt: timestamp("waf_enriched_at"),
  wafDetected: boolean("waf_detected"),
  wafProvider: varchar("waf_provider", { length: 100 }),
  wafConfidence: integer("waf_confidence"),
  // Incremented on each timeout. After MAX_ATTEMPTS, status = 'unknown_timeout'.
  wafEnrichmentAttempts: integer("waf_enrichment_attempts").notNull().default(0),
  // null=pending | 'enriched'=real result | 'unknown_timeout'=max retries exceeded
  wafEnrichmentStatus: varchar("waf_enrichment_status", { length: 30 }),
  isMunicipality: boolean("is_municipality").notNull().default(false),
  // ─── Sector Enrichment ───────────────────────────────────────────────────────
  // Confidence: 'tld_rule' > 'keyword_multi' > 'keyword_single'. null = no match found.
  sectorConfidence: varchar("sector_confidence", { length: 30 }),
  sectorEnrichedAt: timestamp("sector_enriched_at"),
  // ─── AI Enrichment (Haiku) ───────────────────────────────────────────────────
  // 'pending' | 'enriched' | 'no_match' | 'failed'
  enrichmentStatus: varchar("enrichment_status", { length: 20 }).default("pending"),
  // 'haiku_inference' | 'tld_pattern' | 'keyword' | 'manual' | 'import'
  enrichmentMethod: varchar("enrichment_method", { length: 50 }),
  // 'high' | 'medium' | 'low'
  enrichmentConfidence: varchar("enrichment_confidence", { length: 10 }),
  enrichmentAttemptedAt: timestamp("enrichment_attempted_at"),
  enrichmentCompletedAt: timestamp("enrichment_completed_at"),
  // ─── Geo Enrichment (Katman 1) ───────────────────────────────────────────────
  // domain → DNS A → ip-api.com batch → city (var), region (il), isp_organization (var)
  region: varchar("region", { length: 100 }),
  geoEnrichedAt: timestamp("geo_enriched_at"),
  // ─── BIST / KAP ──────────────────────────────────────────────────────────────
  ticker: varchar("ticker", { length: 20 }),
  bistIndexes: text("bist_indexes"),
  bistMarket: varchar("bist_market", { length: 150 }),
  companyEmail: varchar("company_email", { length: 255 }),
  isPublicCompany: boolean("is_public_company").notNull().default(false),
  isBist30: boolean("is_bist30").notNull().default(false),
  isBist100: boolean("is_bist100").notNull().default(false),
  isBist500: boolean("is_bist500").notNull().default(false),
  // ─── Web Contact & Company Intelligence Scraper ───────────────────────────
  // null=bekliyor | 'scraping'=işleniyor | 'scraped'=tamamlandı | 'no_data'=veri yok | 'failed'=hata | 'blocked'=WAF/bot engeli
  webScrapeStatus: varchar("web_scrape_status", { length: 20 }),
  // web_scraped_at already exists (line 60) — reused as completion timestamp
  webScrapeEmail: varchar("web_scrape_email", { length: 255 }),
  webScrapeSourceUrl: varchar("web_scrape_source_url", { length: 500 }),
  // Şirket Profili
  companyAboutSummary: text("company_about_summary"),
  companyServices: jsonb("company_services"),        // string[]
  companyFoundedYear: integer("company_founded_year"),
  isB2b: boolean("is_b2b"),
  hasEcommerce: boolean("has_ecommerce"),
  hasKvkkPage: boolean("has_kvkk_page"),
  hasCareersPage: boolean("has_careers_page"),
  cmsDetected: varchar("cms_detected", { length: 100 }),
  socialLinkedinUrl: varchar("social_linkedin_url", { length: 500 }),
  socialInstagramUrl: varchar("social_instagram_url", { length: 500 }),
  // ─── KVKK / PII Accountability ───────────────────────────────────────────────
  // 'corporate' | 'personal' | 'unknown'  (web scraper'dan sınıflandırılır)
  piiClassification: varchar("pii_classification", { length: 20 }).default("unknown"),
  // Veri sahibi itirazı sonrası PII alanları NULL'lanır, domain/sektör/güvenlik verisi kalır
  piiAnonymized: boolean("pii_anonymized").default(false),
  piiAnonymizedAt: timestamp("pii_anonymized_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
}, (t) => [
  index("idx_lead_candidates_status").on(t.scanStatus),
  index("idx_lead_candidates_qualified").on(t.isQualified),
  index("idx_lead_candidates_tier").on(t.tier),
  index("idx_lead_candidates_isp").on(t.ispOrganization),
  index("idx_lead_candidates_web_scrape_status").on(t.webScrapeStatus),
]);

// ─── KVKK İşleme Kaydı (Accountability) ──────────────────────────────────────
// Her PII yakalayan scrape için bir satır yazılır.
// Yasal dayanak: KVKK m.5/2-f (meşru menfaat) — iş geliştirme amaçlı B2B işleme.
export const dataProcessingLogTable = pgTable("data_processing_log", {
  id: serial("id").primaryKey(),
  leadCandidateId: integer("lead_candidate_id").references(() => leadCandidatesTable.id),
  domain: varchar("domain", { length: 255 }).notNull(),
  // Hangi PII alanları yakalandı: { email: true, phone: false, address: true }
  dataCollected: jsonb("data_collected"),
  legalBasis: varchar("legal_basis", { length: 60 }).default("legitimate_interest_kvkk_5_2_f"),
  piiClassification: varchar("pii_classification", { length: 20 }),
  sourceUrl: varchar("source_url", { length: 500 }),
  collectedAt: timestamp("collected_at").notNull().defaultNow(),
}, (t) => [
  index("idx_data_processing_log_domain").on(t.domain),
]);

// ─── KVKK İtiraz / Silme Başvuruları ─────────────────────────────────────────
// Veri sahibi başvurusu: silme/anonimleştirme talepleri kayıt altına alınır.
export const kvkkObjectionsTable = pgTable("kvkk_objections", {
  id: serial("id").primaryKey(),
  identifier: varchar("identifier", { length: 255 }).notNull(), // domain veya e-posta
  requesterContact: varchar("requester_contact", { length: 255 }),
  requestType: varchar("request_type", { length: 20 }).default("objection"), // 'objection' | 'deletion'
  receivedAt: timestamp("received_at").notNull().defaultNow(),
  processedAt: timestamp("processed_at"),
  actionTaken: varchar("action_taken", { length: 30 }),     // 'anonymized' | 'rejected' | 'not_found'
  affectedRowCount: integer("affected_row_count").default(0),
  notes: text("notes"),
});

export const subdomainScoringRulesTable = pgTable("subdomain_scoring_rules", {
  id: serial("id").primaryKey(),
  pattern: varchar("pattern", { length: 100 }).unique().notNull(),
  corporateScore: integer("corporate_score").notNull(),
  subdomainType: varchar("subdomain_type", { length: 50 }),
  description: varchar("description", { length: 255 }),
  isActive: boolean("is_active").notNull().default(true),
});

// ─── ISP Partners ─────────────────────────────────────────────────────────────
// Türk ISP/hosting operatörleri için normalize mapping + iş ortaklığı durumu
export const ispPartnersTable = pgTable("isp_partners", {
  id: serial("id").primaryKey(),
  // Shodan org field'ından gelen raw değerle eşleştirilecek ILIKE pattern (% wildcard destekler)
  organizationNamePattern: text("organization_name_pattern").notNull(),
  // Normalize edilmiş görünen isim (örn. "Türk Telekom")
  partnerName: varchar("partner_name", { length: 255 }).notNull(),
  partnerContact: varchar("partner_contact", { length: 255 }),
  isActivePartnership: boolean("is_active_partnership").notNull().default(false),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
}, (t) => [
  index("idx_isp_partners_pattern").on(t.organizationNamePattern),
  index("idx_isp_partners_name").on(t.partnerName),
]);

export const insertIspPartnerSchema = createInsertSchema(ispPartnersTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertIspPartner = z.infer<typeof insertIspPartnerSchema>;

export type DiscoveryRun = typeof discoveryRunsTable.$inferSelect;
export type LeadCandidate = typeof leadCandidatesTable.$inferSelect;
export type SubdomainScoringRule = typeof subdomainScoringRulesTable.$inferSelect;
export type IspPartner = typeof ispPartnersTable.$inferSelect;
export type DataProcessingLog = typeof dataProcessingLogTable.$inferSelect;
export type KvkkObjection = typeof kvkkObjectionsTable.$inferSelect;
