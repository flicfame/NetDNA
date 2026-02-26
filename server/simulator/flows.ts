import { db } from "../db";
import { flows, entities, anomalies, vlans } from "@shared/schema";
import { eq, sql } from "drizzle-orm";
import {
  VLANS_DATA, USERS_DATA, PROTOCOLS, ANOMALY_TYPES, EXPORTERS,
  rand, pick, genMac,
} from "./data";

export async function seedVlans() {
  for (const [vid, v] of Object.entries(VLANS_DATA)) {
    try {
      await db.insert(vlans).values({
        vlanId: parseInt(vid),
        name: v.name,
        subnet: v.subnet,
        description: v.name + " VLAN",
        deviceCount: v.size,
      }).onConflictDoNothing();
    } catch {}
  }
}

export async function seedEntities() {
  const now = new Date().toISOString();
  for (const u of USERS_DATA) {
    try {
      await db.insert(entities).values({
        ipAddress: u.ip,
        macAddress: genMac(),
        username: u.username,
        department: u.dept,
        deviceType: pick(["Laptop", "Desktop", "Workstation"]),
        osType: pick(["Windows 11", "macOS 14", "Ubuntu 22.04"]),
        vlanId: u.vlan,
        sgtTag: `SGT_${u.dept.toUpperCase()}`,
        authPolicy: "802.1X-MAB",
        postureStatus: u.posture,
        lastSeen: now,
        firstSeen: now,
        riskScore: u.risk,
        riskTrend: u.risk > 60 ? "rising" : "stable",
        connectionType: u.type,
        updatedAt: now,
      }).onConflictDoNothing();
    } catch {}
  }
}

export async function generateInitialFlows() {
  const now = new Date();
  const flowBatch: any[] = [];
  for (let i = 0; i < 200; i++) {
    const ts = new Date(now.getTime() - rand(0, 3600000)).toISOString();
    const user = pick(USERS_DATA);
    const proto = pick(PROTOCOLS);
    flowBatch.push({
      timestamp: ts,
      srcIp: user.ip,
      dstIp: pick(["8.8.8.8", "1.1.1.1", "104.16.0.1", "13.107.42.14", "172.217.0.46"]),
      srcPort: rand(1024, 65535),
      dstPort: pick(proto.ports),
      protocol: proto.id,
      protocolName: proto.name,
      bytesCount: rand(64, 1500000),
      packets: rand(1, 500),
      tcpFlags: proto.name === "TCP" ? pick(["SYN", "SYN-ACK", "ACK", "FIN", "RST", "PSH-ACK"]) : null,
      srcVlan: user.vlan,
      dstVlan: 0,
      exporterIp: pick(EXPORTERS),
      flowVersion: pick([9, 10]),
      srcUsername: user.username,
      srcDepartment: user.dept,
      connectionType: user.type,
    });
  }
  if (flowBatch.length > 0) {
    await db.insert(flows).values(flowBatch).onConflictDoNothing();
  }

  const anomalyBatch: any[] = [];
  for (let i = 0; i < 8; i++) {
    const ts = new Date(now.getTime() - rand(0, 1800000)).toISOString();
    const user = pick(USERS_DATA);
    const anom = pick(ANOMALY_TYPES);
    anomalyBatch.push({
      detectedAt: ts,
      entityIp: user.ip,
      username: user.username,
      deviceName: `${user.username}-laptop`,
      anomalyType: anom.type,
      severity: anom.sev,
      riskScore: anom.score,
      confidence: anom.conf,
      description: anom.desc,
      evidence: JSON.stringify({ srcIp: user.ip, vlan: user.vlan }),
      mitreTechnique: anom.technique,
      mitreTactic: anom.tactic,
      status: "open",
      srcVlan: user.vlan,
      dstVlan: 0,
      exporterIp: pick(EXPORTERS),
    });
  }
  if (anomalyBatch.length > 0) {
    await db.insert(anomalies).values(anomalyBatch).onConflictDoNothing();
  }
}

export async function tickFlows(ts: string) {
  const now = new Date();
  const flowBatch: any[] = [];
  const numFlows = rand(15, 40);
  for (let i = 0; i < numFlows; i++) {
    const user = pick(USERS_DATA);
    const proto = pick(PROTOCOLS);
    flowBatch.push({
      timestamp: ts,
      srcIp: user.ip,
      dstIp: `${rand(1, 223)}.${rand(0, 255)}.${rand(0, 255)}.${rand(1, 254)}`,
      srcPort: rand(1024, 65535),
      dstPort: pick(proto.ports),
      protocol: proto.id,
      protocolName: proto.name,
      bytesCount: rand(64, 500000),
      packets: rand(1, 200),
      tcpFlags: proto.name === "TCP" ? pick(["SYN", "SYN-ACK", "ACK", "FIN", "PSH-ACK"]) : null,
      srcVlan: user.vlan,
      dstVlan: 0,
      exporterIp: pick(EXPORTERS),
      flowVersion: pick([9, 10]),
      srcUsername: user.username,
      srcDepartment: user.dept,
      connectionType: user.type,
    });
  }
  if (flowBatch.length > 0) {
    await db.insert(flows).values(flowBatch);
  }

  if (Math.random() < 0.15) {
    const user = pick(USERS_DATA);
    const anom = pick(ANOMALY_TYPES);
    await db.insert(anomalies).values({
      detectedAt: ts,
      entityIp: user.ip,
      username: user.username,
      deviceName: `${user.username}-laptop`,
      anomalyType: anom.type,
      severity: anom.sev,
      riskScore: anom.score + rand(-10, 10),
      confidence: anom.conf + rand(-5, 5),
      description: anom.desc,
      evidence: JSON.stringify({ srcIp: user.ip, vlan: user.vlan, timestamp: ts }),
      mitreTechnique: anom.technique,
      mitreTactic: anom.tactic,
      status: "open",
      srcVlan: user.vlan,
      dstVlan: 0,
      exporterIp: pick(EXPORTERS),
    });
  }

  for (const u of USERS_DATA) {
    if (Math.random() < 0.3) {
      const drift = rand(-5, 5);
      const newRisk = Math.max(0, Math.min(100, u.risk + drift));
      await db.update(entities)
        .set({ riskScore: newRisk, lastSeen: ts, updatedAt: ts, riskTrend: drift > 0 ? "rising" : drift < 0 ? "falling" : "stable" })
        .where(eq(entities.ipAddress, u.ip));
    }
  }

  await db.delete(flows).where(
    sql`${flows.timestamp} < ${new Date(now.getTime() - 7200000).toISOString()}`
  );
}
