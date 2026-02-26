import { Router } from "express";
import { db } from "../db";
import { otDevices, otEvents, otProcessValues } from "@shared/schema";
import { eq, sql, desc, asc, and, count, gt } from "drizzle-orm";
import { authMiddleware, requirePermission } from "../auth";

const router = Router();

router.get("/stats", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const [total] = await db.select({ cnt: count() }).from(otDevices);
    const [online] = await db.select({ cnt: count() }).from(otDevices).where(eq(otDevices.status, "online"));
    const [flagged] = await db.select({ cnt: count() }).from(otDevices).where(sql`${otDevices.anomalyFlag} IS NOT NULL`);
    const [openEv] = await db.select({ cnt: count() }).from(otEvents).where(eq(otEvents.status, "open"));
    const fiveMinAgo = new Date(Date.now() - 300000).toISOString();
    const [alarmsCount] = await db.select({ cnt: count() }).from(otProcessValues)
      .where(and(eq(otProcessValues.isAlarm, true), gt(otProcessValues.timestamp, fiveMinAgo)));

    const byLevel = await db.execute(sql`
      SELECT purdue_level, COUNT(*)::int as cnt
      FROM ${otDevices} GROUP BY purdue_level ORDER BY purdue_level
    `);

    const byRisk = await db.execute(sql`
      SELECT cisco_risk, COUNT(*)::int as cnt
      FROM ${otEvents} WHERE status = 'open' AND cisco_risk IS NOT NULL
      GROUP BY cisco_risk ORDER BY cnt DESC
    `);

    res.json({
      total_devices: total.cnt,
      online_devices: online.cnt,
      flagged_devices: flagged.cnt,
      open_events: openEv.cnt,
      process_alarms: alarmsCount.cnt,
      devices_by_level: byLevel.rows,
      risk_categories: byRisk.rows,
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/events", authMiddleware, requirePermission("view_alerts"), async (req, res) => {
  try {
    const limit = parseInt((req.query.limit as string) || "50");
    const rows = await db.select().from(otEvents).orderBy(desc(otEvents.timestamp)).limit(limit);
    const result = rows.map(r => ({
      ...r,
      device_name: r.deviceName, device_ip: r.deviceIp,
      event_type: r.eventType, mitre_technique: r.mitreTechnique,
      mitre_tactic: r.mitreTactic, cisco_risk: r.ciscoRisk,
      src_ip: r.srcIp, dst_ip: r.dstIp,
    }));
    res.json({ events: result });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/process-values", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const rows = await db.execute(sql`
      SELECT pv.*
      FROM ${otProcessValues} pv
      INNER JOIN (
        SELECT device_name, tag_name, MAX(timestamp) as ts
        FROM ${otProcessValues}
        GROUP BY device_name, tag_name
      ) latest ON pv.device_name = latest.device_name
               AND pv.tag_name = latest.tag_name
               AND pv.timestamp = latest.ts
      ORDER BY pv.device_name, pv.tag_name
    `);
    res.json({ values: rows.rows });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/purdue-map", authMiddleware, requirePermission("view_topology"), async (_req, res) => {
  try {
    const rows = await db.select().from(otDevices).orderBy(asc(otDevices.purdueLevel), asc(otDevices.name));
    const result = rows.map(r => ({
      name: r.name, ip_address: r.ipAddress,
      device_type: r.deviceType, vendor: r.vendor,
      purdue_level: r.purdueLevel, protocol: r.protocol,
      status: r.status, firmware_ver: r.firmwareVer,
      risk_score: r.riskScore, anomaly_flag: r.anomalyFlag,
    }));
    res.json({ devices: result });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

export default router;
