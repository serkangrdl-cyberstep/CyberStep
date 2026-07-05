import { db, siteSettingsTable, discoveryRunsTable } from "@workspace/db";
import { pool } from "@workspace/db";
import { eq, and, lt } from "drizzle-orm";
import { logger } from "../lib/logger";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface CronState {
  lastRunAt: string | null;
  lastRunStatus: "ok" | "error" | "running" | "never";
  lastRunDurationMs: number | null;
  lastError: string | null;
  lastProcessedCount: number | null;
  isRunning: boolean;
}

export interface CronRun {
  id: number;
  job_name: string;
  schedule_expr: string | null;
  started_at: string;
  ended_at: string | null;
  status: "running" | "ok" | "error" | "skipped";
  processed_count: number | null;
  error_message: string | null;
  duration_ms: number | null;
}

const DEFAULT_STATE: CronState = {
  lastRunAt: null,
  lastRunStatus: "never",
  lastRunDurationMs: null,
  lastError: null,
  lastProcessedCount: null,
  isRunning: false,
};

// In-memory state + map of wrapped cron functions for manual trigger
const registry = new Map<string, { state: CronState; startedAt: number }>();
const cronFns = new Map<string, () => Promise<void>>();

// ─── Next run calculator (handles common cron patterns) ───────────────────────

export function nextCronDate(expr: string): Date | null {
  const parts = expr.trim().split(/\s+/);
  if (parts.length !== 5) return null;
  const [rawMin, rawHour, , , rawDow] = parts;

  // Iterate minute-by-minute for up to 1 week (10080 min)
  const candidate = new Date();
  candidate.setSeconds(0, 0);
  candidate.setMilliseconds(0);
  candidate.setMinutes(candidate.getMinutes() + 1);

  // Extract time components in Istanbul timezone (crons run in Europe/Istanbul)
  const TZ = "Europe/Istanbul";
  const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const getIstanbulParts = (d: Date): { h: number; m: number; dow: number } => {
    const fmtParts = new Intl.DateTimeFormat("en-US", {
      timeZone: TZ,
      hour: "2-digit",
      minute: "2-digit",
      weekday: "short",
      hour12: false,
    }).formatToParts(d);
    const get = (type: string) => parseInt(fmtParts.find(p => p.type === type)?.value ?? "0", 10);
    const wdStr = fmtParts.find(p => p.type === "weekday")?.value ?? "Sun";
    return { h: get("hour") % 24, m: get("minute"), dow: WEEKDAYS.indexOf(wdStr) };
  };

  const matchField = (field: string, value: number): boolean => {
    if (field === "*") return true;
    if (field.startsWith("*/")) {
      const step = parseInt(field.slice(2), 10);
      return step > 0 && value % step === 0;
    }
    if (field.includes(",")) {
      return field.split(",").some(f => parseInt(f.trim(), 10) === value);
    }
    return parseInt(field, 10) === value;
  };

  for (let i = 0; i < 10080; i++) {
    const { h, m, dow } = getIstanbulParts(candidate);
    if (matchField(rawMin!, m) && matchField(rawHour!, h) && matchField(rawDow!, dow)) {
      return new Date(candidate);
    }
    candidate.setMinutes(candidate.getMinutes() + 1);
  }
  return null;
}

// ─── Startup: stale "running" entries cleanup ────────────────────────────────
// Call once on server start. Any entry stuck in "running" for >2h was left over
// from a previous process that died without finalising the record.
export async function cleanupStaleRunningJobs(): Promise<void> {
  try {
    // On startup ALL "running" records are stale — this is a single-process app,
    // so any in-flight run from the previous process is definitively dead.
    // No time guard: even a 30-second-old "running" record is unreachable.
    const result = await pool.query(
      `UPDATE cron_job_runs
       SET ended_at = NOW(), status = 'error',
           error_message = 'Sunucu yeniden başlatıldı (stale running)',
           duration_ms = EXTRACT(EPOCH FROM (NOW() - started_at)) * 1000
       WHERE status = 'running'`,
    );
    const count = (result as { rowCount?: number }).rowCount ?? 0;
    if (count > 0) {
      logger.warn({ count }, "Startup: stale running cron entries cleaned up");
    }
  } catch (err) {
    logger.warn({ err }, "Startup: stale cron cleanup failed");
  }
}

// ─── Startup: stale "running" discovery_runs kayıtları ──────────────────────
// crt.sh ve diğer discovery kaynakları (shodan, ripe, bgptools, vb.) bir run
// başlatıp process crash/restart nedeniyle hiç sonlandıramazsa, satır kalıcı
// olarak status='running'de kalır — 12 Haziran 2026'da bu şekilde takılı kalan
// 3 crt.sh run'ı elle SQL ile temizlenmişti. Bu, o temizliği otomatikleştirir.
const DISCOVERY_RUN_STALE_THRESHOLD_MS = 30 * 60 * 1000; // 30 dakika

export async function cleanupStaleDiscoveryRuns(): Promise<void> {
  try {
    const cutoff = new Date(Date.now() - DISCOVERY_RUN_STALE_THRESHOLD_MS);
    const updated = await db.update(discoveryRunsTable)
      .set({ status: "failed", errorMessage: "Stale on restart — cleaned up", completedAt: new Date() })
      .where(and(eq(discoveryRunsTable.status, "running"), lt(discoveryRunsTable.startedAt, cutoff)))
      .returning({ id: discoveryRunsTable.id, source: discoveryRunsTable.source });

    if (updated.length > 0) {
      logger.warn(
        { count: updated.length, sources: [...new Set(updated.map((u) => u.source))] },
        "Startup: stale 'running' discovery_runs kayıtları temizlendi",
      );
    }
  } catch (err) {
    logger.warn({ err }, "Startup: discovery_runs stale cleanup failed");
  }
}

// ─── Core: wrapCron ───────────────────────────────────────────────────────────
// Returns a zero-arg async fn suitable for cron.schedule().
// Handles: overlap prevention, DB persistence, failure alerting, count tracking.

export function wrapCron(
  name: string,
  scheduleExpr: string,
  fn: () => Promise<number | void>,
): () => Promise<void> {
  const wrapped = async (): Promise<void> => {
    const current = registry.get(name);
    if (current?.state.isRunning) {
      logger.warn({ name }, `Cron ${name}: overlapping run — skipped`);
      // Persist skipped run (non-blocking)
      pool.query(
        "INSERT INTO cron_job_runs(job_name,schedule_expr,started_at,ended_at,status,duration_ms) VALUES($1,$2,NOW(),NOW(),'skipped',0)",
        [name, scheduleExpr],
      ).catch(() => {});
      return;
    }

    // Mark running in memory
    registry.set(name, {
      state: {
        ...DEFAULT_STATE,
        lastRunAt: new Date().toISOString(),
        lastRunStatus: "running",
        isRunning: true,
      },
      startedAt: Date.now(),
    });

    // Insert DB record
    let runId: number | null = null;
    try {
      const { rows } = await pool.query<{ id: number }>(
        "INSERT INTO cron_job_runs(job_name,schedule_expr,started_at,status) VALUES($1,$2,NOW(),'running') RETURNING id",
        [name, scheduleExpr],
      );
      runId = rows[0]?.id ?? null;
    } catch (dbErr) {
      logger.warn({ dbErr, name }, "Cron registry: failed to insert run record");
    }

    const startedAt = Date.now();
    logger.info({ name, scheduleExpr }, `Cron ${name} started`);

    try {
      const result = await fn();
      const count = typeof result === "number" ? result : null;
      const duration = Date.now() - startedAt;

      const entry = registry.get(name);
      if (entry) {
        entry.state.isRunning = false;
        entry.state.lastRunStatus = "ok";
        entry.state.lastRunDurationMs = duration;
        entry.state.lastError = null;
        entry.state.lastProcessedCount = count;
      }

      if (runId !== null) {
        pool.query(
          "UPDATE cron_job_runs SET ended_at=NOW(),status='ok',processed_count=$1,duration_ms=$2 WHERE id=$3",
          [count, duration, runId],
        ).catch(() => {});
      }

      logger.info({ name, count, duration }, `Cron ${name} completed OK`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const duration = Date.now() - startedAt;

      const entry = registry.get(name);
      if (entry) {
        entry.state.isRunning = false;
        entry.state.lastRunStatus = "error";
        entry.state.lastRunDurationMs = duration;
        entry.state.lastError = msg.slice(0, 500);
        entry.state.lastProcessedCount = null;
      }

      if (runId !== null) {
        pool.query(
          "UPDATE cron_job_runs SET ended_at=NOW(),status='error',error_message=$1,duration_ms=$2 WHERE id=$3",
          [msg.slice(0, 500), duration, runId],
        ).catch(() => {});
      }

      logger.error({ err, name }, `Cron ${name} FAILED`);

      // Fire-and-forget admin alert
      setImmediate(async () => {
        try {
          const { sendMail } = await import("./email");
          const to = process.env["SOC_ADMIN_EMAIL"] ?? process.env["SMTP_USER"];
          if (!to) return;
          await sendMail({
            to,
            subject: `[CyberStep] Cron Hatasi: ${name}`,
            html: `
              <p>Cron job <strong>${name}</strong> başarısız oldu.</p>
              <p><strong>Zamanlama:</strong> ${scheduleExpr}</p>
              <p><strong>Hata:</strong> ${msg.slice(0, 500)}</p>
              <p><strong>Zaman:</strong> ${new Date().toISOString()}</p>
              <p><a href="https://cyberstep.io/panel/cron-ayarlari">Cron paneline git</a></p>
            `,
          });
        } catch { /* alert failure must not propagate */ }
      });
    }
  };

  cronFns.set(name, wrapped);
  return wrapped;
}

// ─── Legacy cronStart (kept for backward compat with manual trigger) ──────────

export function cronStart(name: string): (ok: boolean, err?: string) => void {
  const startedAt = Date.now();
  registry.set(name, {
    state: {
      ...DEFAULT_STATE,
      lastRunAt: new Date().toISOString(),
      lastRunStatus: "running",
      isRunning: true,
    },
    startedAt,
  });
  return (ok: boolean, err?: string) => {
    const entry = registry.get(name);
    if (!entry) return;
    entry.state.isRunning = false;
    entry.state.lastRunStatus = ok ? "ok" : "error";
    entry.state.lastRunDurationMs = Date.now() - startedAt;
    entry.state.lastError = err ?? null;
  };
}

// ─── Manual trigger helper: run the registered wrapCron fn ───────────────────

export function getCronFn(name: string): (() => Promise<void>) | undefined {
  return cronFns.get(name);
}

// ─── Watchdog: force-clear a wedged isRunning flag ────────────────────────────
// If a cron's async fn() (or a step before its own "started" log, e.g. an
// initial pool.query that hangs on a stuck connection/lock rather than
// rejecting) never resolves, isRunning stays true in-memory forever and every
// future tick silently hits the overlap-skip branch — with no further log
// line, since the skip path only logs once per call and nothing re-attempts
// after that. This starves the cron indefinitely without any crash or error
// surfacing. Run this once at startup: it periodically force-resets any entry
// stuck "running" past MAX_RUN_MS so the next scheduled tick can proceed.
const MAX_RUN_MS = 25 * 60 * 1000; // generous vs. longest known job (~13 min)

export function startCronWatchdog(intervalMs = 60_000): void {
  setInterval(() => {
    const now = Date.now();
    for (const [name, entry] of registry.entries()) {
      if (entry.state.isRunning && now - entry.startedAt > MAX_RUN_MS) {
        const stuckForMs = now - entry.startedAt;
        logger.warn(
          { name, stuckForMs },
          `Cron watchdog: ${name} isRunning ${Math.round(stuckForMs / 1000)}s'dir takılı — zorla temizleniyor`,
        );
        entry.state.isRunning = false;
        entry.state.lastRunStatus = "error";
        entry.state.lastError = `Watchdog: run exceeded ${MAX_RUN_MS / 1000}s and was force-cleared`;
        // Mark any orphaned "running" DB row for this job as errored too.
        pool.query(
          `UPDATE cron_job_runs SET ended_at=NOW(), status='error',
             error_message='Watchdog: run exceeded max duration, force-cleared',
             duration_ms=EXTRACT(EPOCH FROM (NOW()-started_at))*1000
           WHERE job_name=$1 AND status='running'`,
          [name],
        ).catch(() => {});
      }
    }
  }, intervalMs).unref();
}

// ─── Read helpers ─────────────────────────────────────────────────────────────

export function cronGetState(name: string): CronState {
  return registry.get(name)?.state ?? { ...DEFAULT_STATE };
}

export function cronGetAll(): Record<string, CronState> {
  const result: Record<string, CronState> = {};
  for (const [name, entry] of registry.entries()) {
    result[name] = entry.state;
  }
  return result;
}

export async function cronGetHistory(name?: string, limit = 30): Promise<CronRun[]> {
  try {
    if (name) {
      const { rows } = await pool.query<CronRun>(
        "SELECT * FROM cron_job_runs WHERE job_name=$1 ORDER BY started_at DESC LIMIT $2",
        [name, limit],
      );
      return rows;
    }
    const { rows } = await pool.query<CronRun>(
      "SELECT * FROM cron_job_runs ORDER BY started_at DESC LIMIT $1",
      [limit],
    );
    return rows;
  } catch {
    return [];
  }
}

export async function cronGetStats(): Promise<Array<{
  job_name: string;
  total_runs: number;
  ok_runs: number;
  error_runs: number;
  avg_duration_ms: number | null;
  last_run_at: string | null;
  last_status: string | null;
  last_error: string | null;
  last_count: number | null;
}>> {
  try {
    const { rows } = await pool.query(`
      SELECT
        job_name,
        COUNT(*) FILTER (WHERE status != 'skipped') AS total_runs,
        COUNT(*) FILTER (WHERE status = 'ok') AS ok_runs,
        COUNT(*) FILTER (WHERE status = 'error') AS error_runs,
        ROUND(AVG(duration_ms) FILTER (WHERE status IN ('ok','error')))::int AS avg_duration_ms,
        MAX(started_at) AS last_run_at,
        (ARRAY_AGG(status ORDER BY started_at DESC))[1] AS last_status,
        CASE
          WHEN (ARRAY_AGG(status ORDER BY started_at DESC))[1] IN ('ok', 'skipped')
          THEN NULL
          ELSE (ARRAY_AGG(error_message ORDER BY started_at DESC) FILTER (WHERE error_message IS NOT NULL))[1]
        END AS last_error,
        (ARRAY_AGG(processed_count ORDER BY started_at DESC) FILTER (WHERE processed_count IS NOT NULL))[1] AS last_count
      FROM cron_job_runs
      GROUP BY job_name
      ORDER BY last_run_at DESC NULLS LAST
    `);
    return rows;
  } catch {
    return [];
  }
}

// ─── Settings helpers ─────────────────────────────────────────────────────────

export async function cronIsEnabled(name: string, defaultVal = true): Promise<boolean> {
  try {
    const [row] = await db.select().from(siteSettingsTable).where(eq(siteSettingsTable.key, `cron.${name}.enabled`));
    if (!row) return defaultVal;
    return row.value !== "false";
  } catch {
    return defaultVal;
  }
}

export async function cronGetLimit(name: string, defaultVal: number): Promise<number> {
  try {
    const [row] = await db.select().from(siteSettingsTable).where(eq(siteSettingsTable.key, `cron.${name}.limit`));
    return row ? (parseInt(row.value) || defaultVal) : defaultVal;
  } catch {
    return defaultVal;
  }
}
