import { Router } from "express";
import { db } from "../db";
import { flows, entities, vlans } from "@shared/schema";
import { eq, sql, desc, gt } from "drizzle-orm";
import { authMiddleware, requirePermission } from "../auth";

const router = Router();

router.get("/flows/stats", authMiddleware, requirePermission("view_flows"), async (req, res) => {
  try {
    const minutes = parseInt((req.query.minutes as string) || "60");
    const cutoff = new Date(Date.now() - minutes * 60000).toISOString();

    const tsRows = await db.execute(sql`
      SELECT to_char(${flows.timestamp}::timestamp, 'HH24:MI') as t,
             COUNT(*)::int as flows,
             COALESCE(SUM(${flows.bytesCount}), 0)::bigint as bytes
      FROM ${flows}
      WHERE ${flows.timestamp} > ${cutoff}
      GROUP BY t ORDER BY t
    `);

    const protoRows = await db.execute(sql`
      SELECT ${flows.protocolName} as protocol_name,
             COUNT(*)::int as flows,
             COALESCE(SUM(${flows.bytesCount}), 0)::bigint as bytes
      FROM ${flows}
      WHERE ${flows.timestamp} > ${cutoff}
      GROUP BY ${flows.protocolName}
      ORDER BY flows DESC LIMIT 10
    `);

    const vlanRows = await db.execute(sql`
      SELECT f.src_vlan, v.name,
             COUNT(*)::int as flows,
             COALESCE(SUM(f.bytes_count), 0)::bigint as bytes
      FROM ${flows} f
      LEFT JOIN ${vlans} v ON f.src_vlan = v.vlan_id
      WHERE f.src_vlan > 0 AND f.timestamp > ${cutoff}
      GROUP BY f.src_vlan, v.name
      ORDER BY bytes DESC
    `);

    const ctRows = await db.execute(sql`
      SELECT ${flows.connectionType} as connection_type,
             COUNT(*)::int as flows,
             COALESCE(SUM(${flows.bytesCount}), 0)::bigint as bytes,
             COUNT(DISTINCT ${flows.srcIp})::int as entities
      FROM ${flows}
      WHERE ${flows.timestamp} > ${cutoff}
      GROUP BY ${flows.connectionType}
    `);

    res.json({
      timeseries: tsRows.rows,
      protocols: protoRows.rows,
      vlans: vlanRows.rows,
      connection_types: ctRows.rows,
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/flows", authMiddleware, requirePermission("view_flows"), async (req, res) => {
  try {
    const minutes = parseInt((req.query.minutes as string) || "60");
    const limit = parseInt((req.query.limit as string) || "100");
    const cutoff = new Date(Date.now() - minutes * 60000).toISOString();
    const rows = await db.select().from(flows).where(gt(flows.timestamp, cutoff)).orderBy(desc(flows.timestamp)).limit(limit);
    const result = rows.map(r => ({
      ...r,
      src_ip: r.srcIp, dst_ip: r.dstIp,
      src_port: r.srcPort, dst_port: r.dstPort,
      protocol_name: r.protocolName, bytes_count: r.bytesCount,
      tcp_flags: r.tcpFlags, src_vlan: r.srcVlan,
      dst_vlan: r.dstVlan, exporter_ip: r.exporterIp,
      flow_version: r.flowVersion, src_username: r.srcUsername,
      src_department: r.srcDepartment, connection_type: r.connectionType,
    }));
    res.json({ flows: result, count: result.length });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/topology", authMiddleware, requirePermission("view_topology"), async (_req, res) => {
  try {
    const deviceList = [
      { hostname: "CORE-SW-01", ip: "10.1.1.1", type: "Core Switch", model: "Catalyst 9500", sw: "IOS-XE 17.9", site: "DC-1", reachability: "Reachable" },
      { hostname: "DIST-SW-01", ip: "10.1.1.2", type: "Distribution Switch", model: "Catalyst 9300", sw: "IOS-XE 17.6", site: "Building A", reachability: "Reachable" },
      { hostname: "ACCESS-SW-01", ip: "10.1.2.1", type: "Access Switch", model: "Catalyst 9200", sw: "IOS-XE 17.3", site: "Floor 1", reachability: "Reachable" },
      { hostname: "WLC-01", ip: "10.1.3.1", type: "WLC", model: "Catalyst 9800", sw: "IOS-XE 17.9", site: "DC-1", reachability: "Reachable" },
      { hostname: "FW-01", ip: "10.1.4.1", type: "Firewall", model: "Firepower 2140", sw: "FTD 7.2", site: "DC-1", reachability: "Reachable" },
      { hostname: "ISE-01", ip: "10.1.5.1", type: "ISE", model: "ISE 3.2", sw: "3.2 Patch 4", site: "DC-1", reachability: "Reachable" },
      { hostname: "ASA-VPN-01", ip: "10.1.6.1", type: "VPN Concentrator", model: "ASAv", sw: "ASA 9.18", site: "DC-1", reachability: "Reachable" },
    ];
    const links = [
      { source: "CORE-SW-01", target: "DIST-SW-01", linkType: "trunk" },
      { source: "DIST-SW-01", target: "ACCESS-SW-01", linkType: "trunk" },
      { source: "CORE-SW-01", target: "WLC-01", linkType: "trunk" },
      { source: "CORE-SW-01", target: "FW-01", linkType: "routed" },
      { source: "FW-01", target: "ISE-01", linkType: "routed" },
      { source: "FW-01", target: "ASA-VPN-01", linkType: "routed" },
    ];
    res.json({ devices: deviceList, links });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.post("/quarantine", authMiddleware, requirePermission("quarantine"), async (req, res) => {
  try {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ detail: "IP address required" });
    await db.update(entities).set({
      isQuarantined: true, vlanId: 99,
      updatedAt: new Date().toISOString(),
    }).where(eq(entities.ipAddress, ip));
    res.json({
      success: true,
      message: `Entity ${ip} quarantined to VLAN 99`,
      steps: [
        { step: 1, action: "ISE CoA Sent", status: "complete", detail: `RADIUS CoA to NAD for ${ip}` },
        { step: 2, action: "Session Terminated", status: "complete", detail: "Active 802.1X session cleared" },
        { step: 3, action: "VLAN Reassigned → 99", status: "complete", detail: "Quarantine VLAN applied" },
        { step: 4, action: "ACL Applied", status: "complete", detail: "Restrict to remediation portal only" },
        { step: 5, action: "SIEM Alert Created", status: "complete", detail: "ServiceNow INC auto-generated" },
      ],
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/heatmap", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const cutoff = new Date(Date.now() - 86400000).toISOString();
    const rows = await db.execute(sql`
      SELECT src_username as username,
             EXTRACT(HOUR FROM timestamp::timestamp)::int as hour,
             COUNT(*)::int as flow_count,
             COALESCE(SUM(bytes_count), 0)::bigint as bytes
      FROM ${flows}
      WHERE timestamp > ${cutoff} AND src_username IS NOT NULL
      GROUP BY src_username, hour
      ORDER BY src_username, hour
    `);
    res.json({ data: rows.rows });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/health", (_req, res) => {
  res.json({
    status: "running",
    version: "0.2.0",
    mode: "simulator",
    timestamp: new Date().toISOString(),
  });
});

export default router;
