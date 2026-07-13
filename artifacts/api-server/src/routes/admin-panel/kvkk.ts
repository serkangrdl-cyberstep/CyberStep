import { Router } from "express";
import { pool } from "@workspace/db";
import { requireAdmin } from "./middleware";
import { logger } from "../../lib/logger";

const router = Router();

// GET /api/admin-panel/kvkk/summary
router.get("/admin-panel/kvkk/summary", requireAdmin, async (_req, res) => {
  try {
    const { rows: [total] } = await pool.query<{ cnt: string }>(
      `SELECT count(*)::int AS cnt FROM kvkk_notifications WHERE status NOT IN ('closed')`
    );
    const { rows: [expiring] } = await pool.query<{ cnt: string }>(
      `SELECT count(*)::int AS cnt FROM kvkk_notifications
       WHERE status NOT IN ('closed')
         AND deadline_72h <= NOW() + INTERVAL '24 hours'
         AND deadline_72h > NOW()`
    );
    const { rows: [overdue] } = await pool.query<{ cnt: string }>(
      `SELECT count(*)::int AS cnt FROM kvkk_notifications
       WHERE status NOT IN ('closed', 'sent', 'tracking')
         AND deadline_72h <= NOW()`
    );
    const { rows: [closed30d] } = await pool.query<{ cnt: string }>(
      `SELECT count(*)::int AS cnt FROM kvkk_notifications
       WHERE status = 'closed'
         AND updated_at >= NOW() - INTERVAL '30 days'`
    );
    res.json({
      active: Number(total?.cnt ?? 0),
      expiringIn24h: Number(expiring?.cnt ?? 0),
      overdue: Number(overdue?.cnt ?? 0),
      closedLast30d: Number(closed30d?.cnt ?? 0),
    });
  } catch (err) {
    logger.error({ err }, "GET /api/admin-panel/kvkk/summary error");
    res.status(500).json({ error: "Sunucu hatası" });
  }
});

// GET /api/admin-panel/kvkk/notifications
router.get("/admin-panel/kvkk/notifications", requireAdmin, async (req, res) => {
  const statusFilter = req.query["status"] as string | undefined;
  try {
    const whereClause = statusFilter
      ? `WHERE kn.status = '${statusFilter.replace(/'/g, "''")}'`
      : "WHERE kn.status NOT IN ('closed')";

    const { rows } = await pool.query(
      `SELECT kn.id, kn.customer_id AS "customerId", c.email AS "customerEmail",
              c.company_name AS "companyName",
              sc.case_number AS "caseNumber", sc.title AS "caseTitle", sc.severity,
              ka.requires_notification AS "requiresNotification",
              ka.severity_category AS "severityCategory",
              ka.urgency, ka.ai_reasoning AS "aiReasoning",
              kn.status, kn.btk_reference_no AS "btkReferenceNo",
              kn.deadline_72h AS "deadline72h", kn.sent_at AS "sentAt",
              kn.created_at AS "createdAt"
       FROM kvkk_notifications kn
       JOIN kvkk_assessments ka ON ka.id = kn.assessment_id
       JOIN soc_cases sc ON sc.id = kn.soc_case_id
       JOIN customers c ON c.id = kn.customer_id
       ${whereClause}
       ORDER BY kn.deadline_72h ASC
       LIMIT 200`
    );
    res.json({ notifications: rows });
  } catch (err) {
    logger.error({ err }, "GET /api/admin-panel/kvkk/notifications error");
    res.status(500).json({ error: "Sunucu hatası" });
  }
});

// GET /api/admin-panel/kvkk/assessments
router.get("/admin-panel/kvkk/assessments", requireAdmin, async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT ka.id, ka.customer_id AS "customerId", c.email AS "customerEmail",
              c.company_name AS "companyName",
              sc.case_number AS "caseNumber", sc.title AS "caseTitle",
              ka.requires_notification AS "requiresNotification",
              ka.severity_category AS "severityCategory",
              ka.urgency, ka.status, ka.assessed_at AS "assessedAt",
              ka.created_at AS "createdAt"
       FROM kvkk_assessments ka
       JOIN soc_cases sc ON sc.id = ka.soc_case_id
       JOIN customers c ON c.id = ka.customer_id
       ORDER BY ka.created_at DESC
       LIMIT 100`
    );
    res.json({ assessments: rows });
  } catch (err) {
    logger.error({ err }, "GET /api/admin-panel/kvkk/assessments error");
    res.status(500).json({ error: "Sunucu hatası" });
  }
});

// ─── POST /api/admin-panel/kvkk/anonymize ─────────────────────────────────────
// Veri sahibi itirazı veya silme talebi geldiğinde PII alanlarını NULL'lar.
// Domain/sektör/güvenlik verisi korunur — sadece kişisel iletişim bilgisi silinir.
router.post("/admin-panel/kvkk/anonymize", requireAdmin, async (req, res) => {
  const { identifier, request_type = "objection", requester_contact, notes } = req.body ?? {};
  if (!identifier || typeof identifier !== "string") {
    return res.status(400).json({ error: "identifier alanı zorunlu (domain veya e-posta)" });
  }

  try {
    const id = identifier.trim().toLowerCase();

    // 1. Eşleşen satırları bul (domain VEYA web_scrape_email)
    const { rows: matches } = await pool.query<{ id: number }>(
      `SELECT id FROM lead_candidates
       WHERE (domain = $1 OR web_scrape_email = $1)
         AND pii_anonymized IS NOT TRUE`,
      [id]
    );

    let action_taken: string;
    const affectedIds = matches.map(r => r.id);

    if (affectedIds.length === 0) {
      action_taken = "not_found";
    } else {
      // 2. PII alanlarını NULL'la — domain/şehir/sektör/güvenlik verisi kalır
      await pool.query(
        `UPDATE lead_candidates
         SET web_scrape_email    = NULL,
             scraped_phone       = NULL,
             scraped_address     = NULL,
             pii_anonymized      = TRUE,
             pii_anonymized_at   = NOW()
         WHERE id = ANY($1)`,
        [affectedIds]
      );
      action_taken = "anonymized";
    }

    // 3. Başvuru kaydını yaz
    await pool.query(
      `INSERT INTO kvkk_objections
         (identifier, requester_contact, request_type, processed_at, action_taken, affected_row_count, notes)
       VALUES ($1, $2, $3, NOW(), $4, $5, $6)`,
      [id, requester_contact ?? null, request_type, action_taken, affectedIds.length, notes ?? null]
    );

    logger.info({ identifier: id, action_taken, affected: affectedIds.length }, "KVKK anonymize işlemi");
    return res.json({
      success: true,
      action_taken,
      affected_row_count: affectedIds.length,
    });
  } catch (err) {
    logger.error({ err }, "POST /api/admin-panel/kvkk/anonymize error");
    return res.status(500).json({ error: "Sunucu hatası" });
  }
});

// ─── GET /api/admin-panel/kvkk/lookup ─────────────────────────────────────────
// "Hakkımda ne tutuyorsunuz?" sorusunu yanıtlamak için read-only veri sorgulama.
// Değerleri değil, hangi alanların dolu olduğunu döndürür (boole flag'ler).
router.get("/admin-panel/kvkk/lookup", requireAdmin, async (req, res) => {
  const identifier = (req.query["identifier"] as string | undefined)?.trim().toLowerCase();
  if (!identifier) {
    return res.status(400).json({ error: "identifier query param zorunlu" });
  }

  try {
    const { rows: candidates } = await pool.query(
      `SELECT
         id, domain,
         pii_classification   AS "piiClassification",
         pii_anonymized       AS "piiAnonymized",
         pii_anonymized_at    AS "piiAnonymizedAt",
         (web_scrape_email IS NOT NULL)  AS "hasEmail",
         (scraped_phone IS NOT NULL)     AS "hasPhone",
         (scraped_address IS NOT NULL)   AS "hasAddress"
       FROM lead_candidates
       WHERE domain = $1 OR web_scrape_email = $1
       LIMIT 50`,
      [identifier]
    );

    const { rows: logs } = await pool.query(
      `SELECT domain, data_collected AS "dataCollected",
              pii_classification AS "piiClassification",
              source_url AS "sourceUrl",
              collected_at AS "collectedAt"
       FROM data_processing_log
       WHERE domain = $1 OR $1 = ANY(
         SELECT web_scrape_email FROM lead_candidates WHERE domain = $1 LIMIT 1
       )
       ORDER BY collected_at DESC
       LIMIT 20`,
      [identifier]
    );

    return res.json({
      identifier,
      matches: candidates,
      processingLog: logs,
    });
  } catch (err) {
    logger.error({ err }, "GET /api/admin-panel/kvkk/lookup error");
    return res.status(500).json({ error: "Sunucu hatası" });
  }
});

// ─── GET /api/admin-panel/kvkk/objections ────────────────────────────────────
router.get("/admin-panel/kvkk/objections", requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, identifier, requester_contact AS "requesterContact",
              request_type AS "requestType", received_at AS "receivedAt",
              processed_at AS "processedAt", action_taken AS "actionTaken",
              affected_row_count AS "affectedRowCount", notes
       FROM kvkk_objections
       ORDER BY received_at DESC
       LIMIT 500`
    );
    return res.json({ objections: rows });
  } catch (err) {
    logger.error({ err }, "GET /api/admin-panel/kvkk/objections error");
    return res.status(500).json({ error: "Sunucu hatası" });
  }
});

export default router;
