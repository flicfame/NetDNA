import { Router } from "express";
import { db } from "../db";
import { anomalies, entities, flows } from "@shared/schema";
import { sql, desc, gt, eq } from "drizzle-orm";
import { authMiddleware, requirePermission } from "../auth";

const router = Router();

const KILL_CHAIN_PHASES = [
  { phase: "Reconnaissance", tactics: ["Discovery"], order: 1 },
  { phase: "Initial Access", tactics: ["Initial Access"], order: 2 },
  { phase: "Credential Access", tactics: ["Credential Access"], order: 3 },
  { phase: "Defense Evasion", tactics: ["Defense Evasion"], order: 4 },
  { phase: "Lateral Movement", tactics: ["Lateral Movement"], order: 5 },
  { phase: "Collection", tactics: ["Collection", "C2"], order: 6 },
  { phase: "Exfiltration", tactics: ["Exfiltration"], order: 7 },
  { phase: "Persistence", tactics: ["Persistence"], order: 8 },
];

function mapTacticToPhase(tactic: string): { phase: string; order: number } | null {
  for (const p of KILL_CHAIN_PHASES) {
    if (p.tactics.includes(tactic)) return { phase: p.phase, order: p.order };
  }
  return null;
}

router.get("/risk-propagation", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const allEntities = await db.select().from(entities).orderBy(desc(entities.riskScore));
    const cutoff = new Date(Date.now() - 3600000).toISOString();

    const recentAnomalies = await db.select().from(anomalies)
      .where(gt(anomalies.detectedAt, cutoff))
      .orderBy(desc(anomalies.detectedAt));

    const vlanGroups: Record<number, typeof allEntities> = {};
    for (const e of allEntities) {
      const v = e.vlanId ?? 0;
      if (!vlanGroups[v]) vlanGroups[v] = [];
      vlanGroups[v].push(e);
    }

    const anomalyByIp: Record<string, number> = {};
    for (const a of recentAnomalies) {
      if (a.entityIp) {
        anomalyByIp[a.entityIp] = (anomalyByIp[a.entityIp] || 0) + (a.riskScore || 0);
      }
    }

    const propagated: Array<{
      ip: string;
      username: string | null;
      vlanId: number | null;
      baseRisk: number;
      propagatedRisk: number;
      propagationSources: Array<{ fromIp: string; fromUser: string | null; contribution: number; reason: string }>;
      finalRisk: number;
    }> = [];

    for (const entity of allEntities) {
      const baseRisk = entity.riskScore ?? 0;
      const sources: Array<{ fromIp: string; fromUser: string | null; contribution: number; reason: string }> = [];
      let propRisk = 0;

      const vlanPeers = vlanGroups[entity.vlanId ?? 0] || [];
      for (const peer of vlanPeers) {
        if (peer.ipAddress === entity.ipAddress) continue;
        const peerRisk = peer.riskScore ?? 0;
        if (peerRisk >= 60) {
          const contribution = Math.round(peerRisk * 0.15);
          propRisk += contribution;
          sources.push({
            fromIp: peer.ipAddress,
            fromUser: peer.username,
            contribution,
            reason: `VLAN ${entity.vlanId} peer risk (${peerRisk})`,
          });
        }
      }

      const anomalyLoad = anomalyByIp[entity.ipAddress ?? ""] || 0;
      if (anomalyLoad > 100) {
        const contribution = Math.round(Math.min(anomalyLoad * 0.05, 20));
        propRisk += contribution;
        sources.push({
          fromIp: entity.ipAddress,
          fromUser: entity.username,
          contribution,
          reason: `High anomaly density (${anomalyLoad} cumulative score)`,
        });
      }

      if (entity.postureStatus === "Non-Compliant") {
        propRisk += 10;
        sources.push({
          fromIp: entity.ipAddress,
          fromUser: entity.username,
          contribution: 10,
          reason: "ISE posture: Non-Compliant",
        });
      }

      if (entity.isQuarantined) {
        propRisk += 15;
        sources.push({
          fromIp: entity.ipAddress,
          fromUser: entity.username,
          contribution: 15,
          reason: "Entity is quarantined (active incident)",
        });
      }

      const finalRisk = Math.min(100, baseRisk + propRisk);

      propagated.push({
        ip: entity.ipAddress,
        username: entity.username,
        vlanId: entity.vlanId,
        baseRisk,
        propagatedRisk: propRisk,
        propagationSources: sources,
        finalRisk,
      });
    }

    propagated.sort((a, b) => b.finalRisk - a.finalRisk);

    const vlanRisk: Record<number, { vlan: number; avgBase: number; avgFinal: number; entityCount: number; criticalCount: number }> = {};
    for (const p of propagated) {
      const v = p.vlanId ?? 0;
      if (!vlanRisk[v]) vlanRisk[v] = { vlan: v, avgBase: 0, avgFinal: 0, entityCount: 0, criticalCount: 0 };
      vlanRisk[v].avgBase += p.baseRisk;
      vlanRisk[v].avgFinal += p.finalRisk;
      vlanRisk[v].entityCount++;
      if (p.finalRisk >= 80) vlanRisk[v].criticalCount++;
    }
    for (const v of Object.values(vlanRisk)) {
      v.avgBase = Math.round(v.avgBase / v.entityCount);
      v.avgFinal = Math.round(v.avgFinal / v.entityCount);
    }

    res.json({
      entities: propagated,
      vlanRisk: Object.values(vlanRisk).sort((a, b) => b.avgFinal - a.avgFinal),
      summary: {
        totalEntities: propagated.length,
        entitiesWithPropagation: propagated.filter(p => p.propagatedRisk > 0).length,
        avgPropagationIncrease: Math.round(propagated.reduce((s, p) => s + p.propagatedRisk, 0) / Math.max(propagated.length, 1)),
        maxPropagation: Math.max(...propagated.map(p => p.propagatedRisk)),
      },
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/attack-chains", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const cutoff = new Date(Date.now() - 7200000).toISOString();
    const recentAnomalies = await db.select().from(anomalies)
      .where(gt(anomalies.detectedAt, cutoff))
      .orderBy(desc(anomalies.detectedAt))
      .limit(500);

    const byEntity: Record<string, typeof recentAnomalies> = {};
    for (const a of recentAnomalies) {
      const key = a.entityIp || a.username || "unknown";
      if (!byEntity[key]) byEntity[key] = [];
      byEntity[key].push(a);
    }

    const chains: Array<{
      chainId: string;
      entityIp: string;
      username: string | null;
      confidence: number;
      severity: string;
      killChainCoverage: number;
      phasesHit: Array<{ phase: string; order: number; technique: string; tactic: string; detectedAt: string; confidence: number }>;
      predictedNext: Array<{ phase: string; probability: number; description: string }>;
      intent: string;
      blastRadius: Array<{ vlan: number; risk: string }>;
      anomalyCount: number;
      firstSeen: string;
      lastSeen: string;
    }> = [];

    let chainIdx = 0;
    for (const [entityKey, entityAnomalies] of Object.entries(byEntity)) {
      if (entityAnomalies.length < 2) continue;

      const phasesHit: Array<{ phase: string; order: number; technique: string; tactic: string; detectedAt: string; confidence: number }> = [];
      const seenPhases = new Set<string>();

      for (const a of entityAnomalies) {
        const mapped = mapTacticToPhase(a.mitreTactic || "");
        if (mapped && !seenPhases.has(mapped.phase)) {
          seenPhases.add(mapped.phase);
          phasesHit.push({
            phase: mapped.phase,
            order: mapped.order,
            technique: a.mitreTechnique || "",
            tactic: a.mitreTactic || "",
            detectedAt: a.detectedAt || "",
            confidence: a.confidence || 70,
          });
        }
      }

      if (phasesHit.length < 2) continue;

      phasesHit.sort((a, b) => a.order - b.order);
      const coverage = phasesHit.length / KILL_CHAIN_PHASES.length;
      const avgConf = Math.round(phasesHit.reduce((s, p) => s + p.confidence, 0) / phasesHit.length);
      const maxOrder = Math.max(...phasesHit.map(p => p.order));

      const predicted: Array<{ phase: string; probability: number; description: string }> = [];
      for (const phase of KILL_CHAIN_PHASES) {
        if (phase.order > maxOrder && !seenPhases.has(phase.phase)) {
          const proximity = 1 / (phase.order - maxOrder);
          const prob = Math.round(Math.min(95, avgConf * proximity * coverage * 100));
          if (prob >= 20) {
            predicted.push({
              phase: phase.phase,
              probability: prob,
              description: getPredictionDesc(phase.phase),
            });
          }
        }
      }

      const maxSev = entityAnomalies.some(a => a.severity === "critical") ? "critical"
        : entityAnomalies.some(a => a.severity === "high") ? "high"
        : entityAnomalies.some(a => a.severity === "medium") ? "medium" : "low";

      const intent = deriveIntent(phasesHit, coverage, maxSev);

      const vlansInvolved = new Set<number>();
      for (const a of entityAnomalies) {
        if (a.srcVlan) vlansInvolved.add(a.srcVlan);
        if (a.dstVlan && a.dstVlan !== 0) vlansInvolved.add(a.dstVlan);
      }
      const blastRadius = Array.from(vlansInvolved).map(v => ({
        vlan: v,
        risk: v >= 100 ? "OT exposure" : v === 99 ? "Quarantine" : "IT lateral",
      }));

      const timestamps = entityAnomalies.map(a => a.detectedAt || "").filter(Boolean).sort();

      chains.push({
        chainId: `CHAIN-${String(++chainIdx).padStart(3, "0")}`,
        entityIp: entityAnomalies[0]?.entityIp || entityKey,
        username: entityAnomalies[0]?.username || null,
        confidence: avgConf,
        severity: maxSev,
        killChainCoverage: Math.round(coverage * 100),
        phasesHit,
        predictedNext: predicted,
        intent,
        blastRadius,
        anomalyCount: entityAnomalies.length,
        firstSeen: timestamps[0] || "",
        lastSeen: timestamps[timestamps.length - 1] || "",
      });
    }

    chains.sort((a, b) => b.killChainCoverage - a.killChainCoverage || b.confidence - a.confidence);

    res.json({
      chains,
      summary: {
        totalChains: chains.length,
        criticalChains: chains.filter(c => c.severity === "critical").length,
        avgCoverage: chains.length ? Math.round(chains.reduce((s, c) => s + c.killChainCoverage, 0) / chains.length) : 0,
        avgConfidence: chains.length ? Math.round(chains.reduce((s, c) => s + c.confidence, 0) / chains.length) : 0,
      },
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/entity-graph/:ip", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const ip = req.params.ip as string;
    const depth = Math.min(parseInt((req.query.depth as string) || "2"), 3);
    const cutoff = new Date(Date.now() - 3600000).toISOString();

    const entity = await db.select().from(entities).where(eq(entities.ipAddress, ip)).limit(1);
    if (!entity.length) return res.status(404).json({ detail: "Entity not found" });

    const root = entity[0];
    const nodes: Array<{
      ip: string; username: string | null; vlanId: number | null;
      riskScore: number; deviceType: string | null; depth: number;
      relationship: string;
    }> = [{
      ip: root.ipAddress, username: root.username, vlanId: root.vlanId,
      riskScore: root.riskScore ?? 0, deviceType: root.deviceType, depth: 0,
      relationship: "root",
    }];

    const edges: Array<{
      source: string; target: string; type: string;
      weight: number; evidence: string;
    }> = [];

    const visited = new Set<string>([root.ipAddress]);

    const flowPeers = await db.execute(sql`
      SELECT dst_ip as peer_ip, COUNT(*)::int as flow_count,
             COALESCE(SUM(bytes_count),0)::bigint as total_bytes
      FROM ${flows}
      WHERE src_ip = ${ip} AND timestamp > ${cutoff}
      GROUP BY dst_ip ORDER BY flow_count DESC LIMIT 20
    `);

    const inboundPeers = await db.execute(sql`
      SELECT src_ip as peer_ip, COUNT(*)::int as flow_count,
             COALESCE(SUM(bytes_count),0)::bigint as total_bytes
      FROM ${flows}
      WHERE dst_ip = ${ip} AND timestamp > ${cutoff}
      GROUP BY src_ip ORDER BY flow_count DESC LIMIT 20
    `);

    const peerIps = new Set<string>();
    for (const row of [...(flowPeers.rows as any[]), ...(inboundPeers.rows as any[])]) {
      if (row.peer_ip && !visited.has(row.peer_ip)) {
        peerIps.add(row.peer_ip);
        const dir = (flowPeers.rows as any[]).some((r: any) => r.peer_ip === row.peer_ip) ? "outbound" : "inbound";
        edges.push({
          source: dir === "outbound" ? ip : row.peer_ip,
          target: dir === "outbound" ? row.peer_ip : ip,
          type: "flow",
          weight: Number(row.flow_count),
          evidence: `${row.flow_count} flows, ${(Number(row.total_bytes) / 1048576).toFixed(1)} MB`,
        });
      }
    }

    if (peerIps.size > 0) {
      const peerIpArr = Array.from(peerIps);
      const peerEntities = peerIpArr.length > 0
        ? await db.select().from(entities)
            .where(sql`${entities.ipAddress} IN (${sql.raw(peerIpArr.map(p => `'${p.replace(/'/g, "''")}'`).join(","))})`)
        : [];

      for (const pe of peerEntities) {
        visited.add(pe.ipAddress);
        nodes.push({
          ip: pe.ipAddress, username: pe.username, vlanId: pe.vlanId,
          riskScore: pe.riskScore ?? 0, deviceType: pe.deviceType, depth: 1,
          relationship: pe.vlanId === root.vlanId ? "same_vlan" : "cross_vlan",
        });
      }
    }

    const vlanPeers = await db.select().from(entities)
      .where(eq(entities.vlanId, root.vlanId ?? 0));
    for (const vp of vlanPeers) {
      if (!visited.has(vp.ipAddress)) {
        visited.add(vp.ipAddress);
        nodes.push({
          ip: vp.ipAddress, username: vp.username, vlanId: vp.vlanId,
          riskScore: vp.riskScore ?? 0, deviceType: vp.deviceType, depth: 1,
          relationship: "same_vlan",
        });
        edges.push({
          source: ip, target: vp.ipAddress, type: "vlan_peer",
          weight: 1, evidence: `Same VLAN ${root.vlanId}`,
        });
      }
    }

    const entityAnomalies = await db.select().from(anomalies)
      .where(eq(anomalies.entityIp, ip))
      .orderBy(desc(anomalies.detectedAt))
      .limit(20);

    const timeline = entityAnomalies.map(a => ({
      timestamp: a.detectedAt,
      type: a.anomalyType,
      technique: a.mitreTechnique,
      tactic: a.mitreTactic,
      severity: a.severity,
      confidence: a.confidence,
    }));

    res.json({
      root: { ip: root.ipAddress, username: root.username, vlanId: root.vlanId, riskScore: root.riskScore, deviceType: root.deviceType },
      nodes,
      edges,
      timeline,
      summary: {
        totalNodes: nodes.length,
        totalEdges: edges.length,
        flowPeers: (flowPeers.rows as any[]).length + (inboundPeers.rows as any[]).length,
        vlanPeers: vlanPeers.length - 1,
        anomalyCount: entityAnomalies.length,
        maxDepth: Math.max(...nodes.map(n => n.depth)),
      },
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/integration-status", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const cutoff5m = new Date(Date.now() - 300000).toISOString();
    const cutoff1h = new Date(Date.now() - 3600000).toISOString();

    const recentFlows = await db.execute(sql`
      SELECT COUNT(*)::int as count FROM ${flows} WHERE timestamp > ${cutoff5m}
    `);
    const recentAnomalies = await db.execute(sql`
      SELECT COUNT(*)::int as count FROM ${anomalies} WHERE detected_at > ${cutoff1h}
    `);
    const entityCount = await db.execute(sql`
      SELECT COUNT(*)::int as count FROM ${entities}
    `);

    const flowRate = Math.round(Number((recentFlows.rows[0] as any)?.count || 0) / 5);

    const integrations = [
      {
        name: "Cisco NetFlow / IPFIX",
        type: "telemetry",
        status: flowRate > 0 ? "connected" : "disconnected",
        protocol: "NetFlow v9 / IPFIX v10",
        port: "UDP/2055, UDP/4739",
        metrics: { flowsPerSec: flowRate, exporters: 4, version: "v9/v10" },
        lastData: new Date().toISOString(),
      },
      {
        name: "Cisco ISE pxGrid",
        type: "identity",
        status: "connected",
        protocol: "pxGrid / REST",
        port: "TCP/8910",
        metrics: {
          sessions: Number((entityCount.rows[0] as any)?.count || 0),
          sgtPolicies: 8,
          coaActions: 3,
        },
        lastData: new Date().toISOString(),
      },
      {
        name: "Syslog Collector",
        type: "log_ingestion",
        status: "connected",
        protocol: "Syslog / RFC 5424",
        port: "UDP/514, TCP/6514 (TLS)",
        metrics: {
          sourcesConfigured: 6,
          eventsPerMin: Math.round(Number((recentAnomalies.rows[0] as any)?.count || 0) / 60 * 10),
          parsers: ["Cisco ASA", "Palo Alto", "ISE", "Windows Event"],
        },
        lastData: new Date().toISOString(),
      },
      {
        name: "Cisco DNA Center",
        type: "orchestration",
        status: "connected",
        protocol: "REST API v2",
        port: "TCP/443",
        metrics: { managedDevices: 7, sites: 4, assuranceScore: 82 },
        lastData: new Date().toISOString(),
      },
      {
        name: "Cisco Secure Firewall",
        type: "perimeter",
        status: "connected",
        protocol: "FTD REST API",
        port: "TCP/443",
        metrics: { policies: 12, blockedToday: 847, throughputGbps: 2.4 },
        lastData: new Date().toISOString(),
      },
      {
        name: "Cisco SecureX",
        type: "xdr",
        status: "connected",
        protocol: "SecureX API / CTR",
        port: "TCP/443",
        metrics: { incidents: Number((recentAnomalies.rows[0] as any)?.count || 0), automations: 5, modules: 8 },
        lastData: new Date().toISOString(),
      },
    ];

    res.json({
      integrations,
      summary: {
        total: integrations.length,
        connected: integrations.filter(i => i.status === "connected").length,
        disconnected: integrations.filter(i => i.status === "disconnected").length,
        telemetrySources: integrations.filter(i => i.type === "telemetry").length,
      },
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

function deriveIntent(
  phases: Array<{ phase: string; order: number }>,
  coverage: number,
  severity: string
): string {
  const phaseNames = phases.map(p => p.phase);

  if (phaseNames.includes("Exfiltration")) {
    return "Data theft — active exfiltration detected";
  }
  if (phaseNames.includes("Lateral Movement") && phaseNames.includes("Collection")) {
    return "Targeted intrusion — lateral spread with data staging";
  }
  if (phaseNames.includes("Lateral Movement")) {
    return "Network penetration — lateral movement in progress";
  }
  if (phaseNames.includes("Credential Access") && phaseNames.includes("Defense Evasion")) {
    return "Credential harvesting with evasion techniques";
  }
  if (phaseNames.includes("Reconnaissance") && coverage < 0.3) {
    return "Early-stage reconnaissance — probing network boundaries";
  }
  if (phaseNames.includes("Persistence")) {
    return "Establishing persistence — long-term access objective";
  }
  if (severity === "critical" && coverage >= 0.4) {
    return "Advanced persistent threat — multi-phase coordinated attack";
  }
  return "Suspicious behavioral chain — requires investigation";
}

function getPredictionDesc(phase: string): string {
  const descs: Record<string, string> = {
    "Reconnaissance": "Network scanning and service enumeration expected",
    "Initial Access": "Credential exploitation or phishing attempt predicted",
    "Credential Access": "Password spraying or Kerberoasting likely",
    "Defense Evasion": "VLAN hopping or log tampering anticipated",
    "Lateral Movement": "SMB/RDP pivoting to adjacent hosts predicted",
    "Collection": "Bulk file access and staging for exfiltration",
    "Exfiltration": "Data transfer to external C2 infrastructure",
    "Persistence": "Backdoor installation or scheduled task creation",
  };
  return descs[phase] || "Next attack phase anticipated";
}

export default router;
