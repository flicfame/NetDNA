import { Router } from "express";
import { db } from "../db";
import { vpnSessions, wirelessClients, accessPoints } from "@shared/schema";
import { eq, sql, desc, count } from "drizzle-orm";
import { authMiddleware, requirePermission } from "../auth";

const router = Router();

router.get("/vpn", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const limit = parseInt((req.query.limit as string) || "50");
    const rows = await db.select().from(vpnSessions)
      .where(eq(vpnSessions.status, "active"))
      .orderBy(desc(vpnSessions.timestamp)).limit(limit);
    const result = rows.map(r => ({
      ...r,
      vpn_ip: r.vpnIp, public_ip: r.publicIp,
      country_code: r.countryCode, country_name: r.countryName,
      device_type: r.deviceType, auth_method: r.authMethod,
      bytes_in: r.bytesIn, bytes_out: r.bytesOut,
      duration_sec: r.durationSec, risk_flag: r.riskFlag,
    }));
    res.json({ sessions: result, count: result.length });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/wireless", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const limit = parseInt((req.query.limit as string) || "50");
    const rows = await db.select().from(wirelessClients)
      .where(eq(wirelessClients.status, "connected"))
      .orderBy(desc(wirelessClients.timestamp)).limit(limit);
    const result = rows.map(r => ({
      ...r,
      mac_address: r.macAddress, ip_address: r.ipAddress,
      device_type: r.deviceType, os_type: r.osType,
      ap_name: r.apName, ap_location: r.apLocation,
      signal_dbm: r.signalDbm, bytes_in: r.bytesIn,
      bytes_out: r.bytesOut, risk_flag: r.riskFlag,
    }));
    res.json({ clients: result, count: result.length });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/stats", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const [vpnCount] = await db.select({ cnt: count() }).from(vpnSessions).where(eq(vpnSessions.status, "active"));
    const [wifiCount] = await db.select({ cnt: count() }).from(wirelessClients).where(eq(wirelessClients.status, "connected"));
    const [rogueCount] = await db.select({ cnt: count() }).from(accessPoints).where(eq(accessPoints.isRogue, true));
    const aps = await db.select().from(accessPoints).orderBy(desc(accessPoints.clientCount));
    res.json({
      vpn_active: vpnCount.cnt,
      wireless_connected: wifiCount.cnt,
      rogue_aps: rogueCount.cnt,
      access_points: aps.map(a => ({
        ap_name: a.apName, ip_address: a.ipAddress,
        location: a.location, ssid: a.ssid,
        client_count: a.clientCount, is_rogue: a.isRogue,
        last_seen: a.lastSeen, status: a.status,
      })),
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/map", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const rows = await db.execute(sql`
      SELECT country_code, country_name, city,
             COUNT(*)::int as sessions,
             MAX(risk_flag) as risk_flag
      FROM ${vpnSessions}
      WHERE status = 'active'
      GROUP BY country_code, country_name, city
      ORDER BY sessions DESC
    `);
    const COUNTRIES: Record<string, any> = {
      GB: { flag: "\u{1F1EC}\u{1F1E7}", lat: 51.5, lon: -0.12, risk: "low" },
      IE: { flag: "\u{1F1EE}\u{1F1EA}", lat: 53.3, lon: -6.26, risk: "low" },
      US: { flag: "\u{1F1FA}\u{1F1F8}", lat: 38.9, lon: -77.04, risk: "low" },
      FR: { flag: "\u{1F1EB}\u{1F1F7}", lat: 48.8, lon: 2.35, risk: "low" },
      DE: { flag: "\u{1F1E9}\u{1F1EA}", lat: 52.5, lon: 13.4, risk: "low" },
      IN: { flag: "\u{1F1EE}\u{1F1F3}", lat: 28.6, lon: 77.2, risk: "medium" },
      CN: { flag: "\u{1F1E8}\u{1F1F3}", lat: 39.9, lon: 116.4, risk: "high" },
      RU: { flag: "\u{1F1F7}\u{1F1FA}", lat: 55.7, lon: 37.6, risk: "high" },
    };
    const locations = (rows.rows as any[]).map(r => ({
      ...r,
      flag: COUNTRIES[r.country_code]?.flag || "\u{1F30D}",
      lat: COUNTRIES[r.country_code]?.lat || 0,
      lon: COUNTRIES[r.country_code]?.lon || 0,
      risk: COUNTRIES[r.country_code]?.risk || "low",
    }));
    res.json({ locations });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

export default router;
