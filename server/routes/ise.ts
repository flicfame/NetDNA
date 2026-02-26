import { Router } from "express";
import { db } from "../db";
import { iseSyncLog, shimViolations } from "@shared/schema";
import { eq, desc, gte, count, sql } from "drizzle-orm";
import { authMiddleware, requirePermission } from "../auth";
import { toSnakeCaseArray } from "../utils";

const router = Router();

router.get("/ise/status", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const [lastSync] = await db
      .select()
      .from(iseSyncLog)
      .orderBy(desc(iseSyncLog.ts))
      .limit(1);

    const cutoff24h = new Date(Date.now() - 86400 * 1000).toISOString();

    const [syncStats] = await db
      .select({
        total: count(),
        succeeded: sql<number>`sum(case when ${iseSyncLog.success} = true then 1 else 0 end)`,
        failed: sql<number>`sum(case when ${iseSyncLog.success} = false then 1 else 0 end)`,
      })
      .from(iseSyncLog)
      .where(gte(iseSyncLog.ts, cutoff24h));

    res.json({
      connected: false,
      ise_host: "not configured",
      ise_version: null,
      last_sync: lastSync ? {
        id: lastSync.id,
        ts: lastSync.ts,
        action: lastSync.action,
        mac: lastSync.mac,
        ise_endpoint_id: lastSync.iseEndpointId,
        ise_group: lastSync.iseGroup,
        success: lastSync.success,
        detail: lastSync.detail,
      } : null,
      syncs_24h: syncStats ? {
        total: syncStats.total,
        succeeded: syncStats.succeeded || 0,
        failed: syncStats.failed || 0,
      } : null,
      checked_at: new Date().toISOString(),
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/ise/log", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const limit = parseInt((req.query.limit as string) || "100");

    const rows = await db
      .select()
      .from(iseSyncLog)
      .orderBy(desc(iseSyncLog.ts))
      .limit(limit);

    res.json(toSnakeCaseArray(rows as any));
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.post("/ise/sync", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    res.status(503).json({
      detail: "ISE not configured or unreachable",
      message: "ISE integration is not configured in simulation mode. Configure ISE_HOST to enable.",
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/violations/summary", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const cutoff24h = new Date(Date.now() - 86400 * 1000).toISOString();

    const [totalCount] = await db
      .select({ total: count() })
      .from(shimViolations)
      .where(gte(shimViolations.ts, cutoff24h));

    const bySeverity = await db
      .select({
        severity: shimViolations.severity,
        count: count(),
      })
      .from(shimViolations)
      .where(gte(shimViolations.ts, cutoff24h))
      .groupBy(shimViolations.severity);

    const byAction = await db
      .select({
        action: shimViolations.action,
        count: count(),
      })
      .from(shimViolations)
      .where(gte(shimViolations.ts, cutoff24h))
      .groupBy(shimViolations.action);

    const topRules = await db
      .select({
        ruleName: shimViolations.ruleName,
        count: count(),
      })
      .from(shimViolations)
      .where(gte(shimViolations.ts, cutoff24h))
      .groupBy(shimViolations.ruleName)
      .orderBy(desc(count()))
      .limit(10);

    res.json({
      total_24h: totalCount?.total || 0,
      by_severity: bySeverity.map((r) => ({ severity: r.severity, count: r.count })),
      by_action: byAction.map((r) => ({ action: r.action, count: r.count })),
      top_rules: topRules.map((r) => ({ rule_name: r.ruleName, count: r.count })),
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.post("/ise/writeback/:deviceId", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    res.status(503).json({
      detail: "ISE not configured",
      message: "ISE integration is not configured in simulation mode. Configure ISE_HOST to enable writeback.",
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

export default router;
