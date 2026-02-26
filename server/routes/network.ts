import { Router } from "express";
import { db } from "../db";
import { flows, entities, anomalies } from "@shared/schema";
import { eq, desc, and, count, gt } from "drizzle-orm";
import { authMiddleware, requirePermission } from "../auth";
import { vpnSessions, wirelessClients } from "@shared/schema";
import { toSnakeCase, toSnakeCaseArray } from "../utils";

const router = Router();

router.get("/dashboard", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const oneHrAgo = new Date(Date.now() - 3600000).toISOString();
    const [flowCount] = await db.select({ cnt: count() }).from(flows).where(gt(flows.timestamp, oneHrAgo));
    const [entityCount] = await db.select({ cnt: count() }).from(entities);
    const [openAnoms] = await db.select({ cnt: count() }).from(anomalies).where(eq(anomalies.status, "open"));
    const [critAnoms] = await db.select({ cnt: count() }).from(anomalies).where(and(eq(anomalies.status, "open"), eq(anomalies.severity, "critical")));
    const [highAnoms] = await db.select({ cnt: count() }).from(anomalies).where(and(eq(anomalies.status, "open"), eq(anomalies.severity, "high")));
    const [vpnCount] = await db.select({ cnt: count() }).from(vpnSessions).where(eq(vpnSessions.status, "active"));
    const [wifiCount] = await db.select({ cnt: count() }).from(wirelessClients).where(eq(wirelessClients.status, "connected"));

    const fps = (flowCount.cnt || 0) / 3600;
    res.json({
      flows_per_sec: parseFloat(fps.toFixed(1)),
      total_flows: flowCount.cnt || 0,
      entities_monitored: entityCount.cnt || 0,
      open_anomalies: openAnoms.cnt || 0,
      critical_anomalies: critAnoms.cnt || 0,
      high_anomalies: highAnoms.cnt || 0,
      vpn_active: vpnCount.cnt || 0,
      wireless_active: wifiCount.cnt || 0,
      mttd_minutes: 4.2,
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/anomalies", authMiddleware, requirePermission("view_alerts"), async (req, res) => {
  try {
    const statusFilter = (req.query.status_filter as string) || "open";
    const limit = parseInt((req.query.limit as string) || "50");
    const where = statusFilter === "all" ? undefined : eq(anomalies.status, statusFilter);
    const rows = await db.select().from(anomalies).where(where).orderBy(desc(anomalies.detectedAt)).limit(limit);
    const result = toSnakeCaseArray(rows);
    res.json({ anomalies: result, count: result.length });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/anomalies/:id", authMiddleware, requirePermission("view_alerts"), async (req, res) => {
  try {
    const id = parseInt(req.params.id as string);
    const [row] = await db.select().from(anomalies).where(eq(anomalies.id, id));
    if (!row) return res.status(404).json({ detail: "Anomaly not found" });
    res.json(toSnakeCase(row));
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.post("/anomalies/:id/status", authMiddleware, requirePermission("update_alerts"), async (req, res) => {
  try {
    const id = parseInt(req.params.id as string);
    const { status: newStatus, assigned_to } = req.body;
    const now = new Date().toISOString();
    await db.update(anomalies).set({
      status: newStatus,
      assignedTo: assigned_to || (req as any).user?.sub,
      resolvedAt: newStatus === "closed" ? now : null,
    }).where(eq(anomalies.id, id));
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/entities", authMiddleware, requirePermission("view_entities"), async (req, res) => {
  try {
    const limit = parseInt((req.query.limit as string) || "50");
    const connType = req.query.connection_type as string | undefined;
    const where = connType ? eq(entities.connectionType, connType) : undefined;
    const rows = await db.select().from(entities).where(where).orderBy(desc(entities.riskScore)).limit(limit);
    const result = rows.map(r => {
      const snake = toSnakeCase(r);
      snake.is_quarantined = r.isQuarantined ? 1 : 0;
      return snake;
    });
    res.json({ entities: result, count: result.length });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/entities/:ip", authMiddleware, requirePermission("view_entities"), async (req, res) => {
  try {
    const ip = decodeURIComponent(req.params.ip as string);
    const [entity] = await db.select().from(entities).where(eq(entities.ipAddress, ip));
    if (!entity) return res.status(404).json({ detail: "Entity not found" });

    const entityAnoms = await db.select().from(anomalies)
      .where(and(eq(anomalies.entityIp, ip), eq(anomalies.status, "open")))
      .orderBy(desc(anomalies.detectedAt)).limit(10);

    const entityFlows = await db.select().from(flows)
      .where(eq(flows.srcIp, ip))
      .orderBy(desc(flows.timestamp)).limit(20);

    const vpn = entity.username ? await db.select().from(vpnSessions)
      .where(eq(vpnSessions.username, entity.username))
      .orderBy(desc(vpnSessions.timestamp)).limit(5) : [];

    const wifi = entity.username ? await db.select().from(wirelessClients)
      .where(eq(wirelessClients.username, entity.username))
      .orderBy(desc(wirelessClients.timestamp)).limit(5) : [];

    res.json({ entity, anomalies: entityAnoms, flows: entityFlows, vpn_sessions: vpn, wireless_sessions: wifi });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

export default router;
