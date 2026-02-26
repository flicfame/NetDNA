import { db } from "../db";
import {
  shims, downstreamDevices, policyTemplates, shimPolicies,
  shimHealth, shimViolations, shimFlows, shimAuditLog, newTalkers
} from "@shared/schema";
import { eq, sql } from "drizzle-orm";
import crypto from "crypto";

const SHIM_DEFS = [
  { shimId: "NETDNA-EDGE-00001", name: "Plant-A PLC Shim", siteId: "PLANT-A", zone: "Level-1", mode: "monitor", firmware: "1.2.4", mgmtIp: "192.168.100.11", iface_d: "ens3", iface_s: "ens4" },
  { shimId: "NETDNA-EDGE-00002", name: "Plant-A HMI Shim", siteId: "PLANT-A", zone: "Level-2", mode: "enforce", firmware: "1.2.4", mgmtIp: "192.168.100.12", iface_d: "ens3", iface_s: "ens4" },
  { shimId: "NETDNA-EDGE-00003", name: "Plant-B PLC Shim", siteId: "PLANT-B", zone: "Level-1", mode: "monitor", firmware: "1.2.3", mgmtIp: "192.168.101.11", iface_d: "ens3", iface_s: "ens4" },
  { shimId: "NETDNA-EDGE-00004", name: "Substation RTU Shim", siteId: "SUBSTATION-1", zone: "Level-1", mode: "enforce", firmware: "1.2.4", mgmtIp: "192.168.102.11", iface_d: "ens3", iface_s: "ens4" },
  { shimId: "NETDNA-EDGE-00005", name: "Plant-B HMI Shim", siteId: "PLANT-B", zone: "Level-2", mode: "monitor", firmware: "1.2.4", mgmtIp: "192.168.101.12", iface_d: "ens3", iface_s: "ens4" },
  { shimId: "NETDNA-EDGE-00006", name: "DMZ Switch Shim", siteId: "PLANT-A", zone: "DMZ", mode: "contain", firmware: "1.2.4", mgmtIp: "192.168.100.20", iface_d: "ens3", iface_s: "ens4" },
  { shimId: "NETDNA-EDGE-00007", name: "Plant-C PLC Shim", siteId: "PLANT-C", zone: "Level-1", mode: "pending", firmware: "1.2.4", mgmtIp: "192.168.103.11", iface_d: "ens3", iface_s: "ens4" },
];

const DOWNSTREAM_DEFS: { shimId: string; mac: string; ip: string; type: string; name: string; template: string }[] = [
  { shimId: "NETDNA-EDGE-00001", mac: "00:1C:06:A1:01:01", ip: "192.168.101.10", type: "PLC", name: "AB-CompactLogix-01", template: "plc" },
  { shimId: "NETDNA-EDGE-00001", mac: "00:1C:06:A1:01:02", ip: "192.168.101.11", type: "PLC", name: "AB-CompactLogix-02", template: "plc" },
  { shimId: "NETDNA-EDGE-00001", mac: "00:1C:06:A1:01:03", ip: "192.168.101.12", type: "Switch", name: "Stratix-5700-01", template: "unknown" },
  { shimId: "NETDNA-EDGE-00002", mac: "00:50:C2:A2:01:01", ip: "192.168.102.10", type: "HMI", name: "FactoryTalk-HMI-01", template: "hmi" },
  { shimId: "NETDNA-EDGE-00002", mac: "00:50:C2:A2:01:02", ip: "192.168.102.11", type: "Historian", name: "OSIsoft-PI-01", template: "historian" },
  { shimId: "NETDNA-EDGE-00003", mac: "00:1C:06:B1:01:01", ip: "192.168.101.20", type: "PLC", name: "Siemens-S7-1500-01", template: "plc" },
  { shimId: "NETDNA-EDGE-00003", mac: "00:1C:06:B1:01:02", ip: "192.168.101.21", type: "PLC", name: "Siemens-S7-1200-01", template: "plc" },
  { shimId: "NETDNA-EDGE-00004", mac: "00:80:A3:C1:01:01", ip: "192.168.102.20", type: "RTU", name: "SEL-3530-RTU-01", template: "rtu" },
  { shimId: "NETDNA-EDGE-00004", mac: "00:80:A3:C1:01:02", ip: "192.168.102.21", type: "RTU", name: "SEL-3505-RTU-02", template: "rtu" },
  { shimId: "NETDNA-EDGE-00004", mac: "00:80:A3:C1:01:03", ip: "192.168.102.22", type: "Switch", name: "Hirschmann-RS20-01", template: "unknown" },
  { shimId: "NETDNA-EDGE-00005", mac: "00:50:C2:B2:01:01", ip: "192.168.101.30", type: "HMI", name: "WinCC-HMI-01", template: "hmi" },
  { shimId: "NETDNA-EDGE-00005", mac: "00:50:C2:B2:01:02", ip: "192.168.101.31", type: "EngWS", name: "TIA-Portal-WS-01", template: "unknown" },
  { shimId: "NETDNA-EDGE-00006", mac: "00:AA:BB:D1:01:01", ip: "10.0.50.10", type: "Switch", name: "Catalyst-9300-DMZ", template: "unknown" },
  { shimId: "NETDNA-EDGE-00006", mac: "00:AA:BB:D1:01:02", ip: "10.0.50.11", type: "Unknown", name: "", template: "unknown" },
];

const TEMPLATE_SEEDS = [
  {
    name: "plc",
    displayName: "PLC",
    description: "Programmable Logic Controller — Purdue Level 1",
    builtIn: true,
    rules: [
      { type: "allow", src_cidrs: ["192.168.102.0/24"], dst_ports: [502, 44818, 2222], proto: "tcp", desc: "HMI → Modbus/EtherNet-IP" },
      { type: "allow", src_cidrs: ["192.168.103.0/24"], dst_ports: [44818], proto: "tcp", desc: "Historian reads" },
      { type: "allow", conntrack: "established,related", desc: "Established" },
      { type: "deny", dst_ports: [22, 3389, 445], proto: "tcp", severity: "medium", mitre: "T0822", desc: "Block IT admin ports" },
      { type: "deny", src_cidrs: ["10.0.0.0/8"], direction: "in", severity: "high", mitre: "T0866", desc: "Block direct IT access" },
      { type: "deny", direction: "out", not_dst_cidrs: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], severity: "critical", mitre: "T0882", desc: "Block internet egress" },
    ],
  },
  {
    name: "hmi",
    displayName: "HMI / SCADA",
    description: "Human-Machine Interface — Purdue Level 2",
    builtIn: true,
    rules: [
      { type: "allow", dst_cidrs: ["192.168.101.0/24"], dst_ports: [502, 44818, 20000, 102], proto: "tcp", desc: "HMI → PLC protocols" },
      { type: "allow", dst_cidrs: ["192.168.103.0/24"], dst_ports: [1433, 4840], proto: "tcp", desc: "HMI → Historian" },
      { type: "allow", dst_ports: [123], proto: "udp", desc: "NTP" },
      { type: "allow", conntrack: "established,related", desc: "Established" },
      { type: "deny", direction: "out", not_dst_cidrs: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], severity: "high", mitre: "T0882", desc: "Block internet egress" },
    ],
  },
  {
    name: "quarantine",
    displayName: "Quarantine",
    description: "Minimal safe set — manually activated",
    builtIn: true,
    rules: [
      { type: "allow", conntrack: "established,related", desc: "Established only" },
      { type: "deny", match: "all", severity: "critical", desc: "Deny everything else" },
    ],
  },
  {
    name: "rtu",
    displayName: "RTU",
    description: "Remote Terminal Unit — Purdue Level 1",
    builtIn: true,
    rules: [
      { type: "allow", src_cidrs: ["192.168.102.0/24"], dst_ports: [20000, 502, 2404], proto: "tcp", desc: "SCADA → DNP3/Modbus/IEC-104" },
      { type: "allow", conntrack: "established,related", desc: "Established" },
      { type: "deny", dst_ports: [22, 3389, 445], proto: "tcp", severity: "medium", mitre: "T0822", desc: "Block IT admin ports" },
      { type: "deny", src_cidrs: ["10.0.0.0/8"], direction: "in", severity: "high", mitre: "T0866", desc: "Block direct IT access" },
      { type: "deny", direction: "out", not_dst_cidrs: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], severity: "critical", mitre: "T0882", desc: "Block internet egress" },
    ],
  },
  {
    name: "historian",
    displayName: "Historian / Data Collector",
    description: "OT Historian — Purdue Level 3",
    builtIn: true,
    rules: [
      { type: "allow", src_cidrs: ["192.168.101.0/24", "192.168.102.0/24"], dst_ports: [4840, 1433], proto: "tcp", desc: "OPC-UA / SQL from HMI/SCADA" },
      { type: "allow", dst_ports: [123], proto: "udp", desc: "NTP" },
      { type: "allow", conntrack: "established,related", desc: "Established" },
      { type: "deny", direction: "out", not_dst_cidrs: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], severity: "high", mitre: "T0882", desc: "Block internet egress" },
    ],
  },
  {
    name: "unknown",
    displayName: "Unknown Device",
    description: "Unclassified — not in ISE",
    builtIn: true,
    rules: [
      { type: "allow", dst_ports: [67, 68], proto: "udp", desc: "DHCP" },
      { type: "deny", match: "all", severity: "high", mitre: "T0810", desc: "Deny all" },
    ],
  },
];

const VIOLATION_RULES = [
  { rule: "block-it-admin", src: "10.0.0.0/8", dstPorts: [22, 3389, 445], proto: "tcp", sev: "medium", mitre: "T0822" },
  { rule: "block-internet-egress", src: "any", dstPorts: [80, 443], proto: "tcp", sev: "critical", mitre: "T0882" },
  { rule: "block-direct-it", src: "10.0.0.0/8", dstPorts: [502, 44818], proto: "tcp", sev: "high", mitre: "T0866" },
  { rule: "deny-all-unknown", src: "any", dstPorts: [0], proto: "tcp", sev: "high", mitre: "T0810" },
  { rule: "block-smb-lateral", src: "any", dstPorts: [445, 139], proto: "tcp", sev: "medium", mitre: "T1021" },
];

function rand(min: number, max: number) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function randFloat(min: number, max: number) { return Math.random() * (max - min) + min; }
function pick<T>(arr: T[]): T { return arr[rand(0, arr.length - 1)]; }
function randIp(prefix: string) { return `${prefix}.${rand(1, 254)}`; }

function computePolicyHash(templateName: string, mode: string, rules: any[]): string {
  const str = JSON.stringify({ template: templateName, mode, rules }, Object.keys({ template: templateName, mode, rules }).sort());
  return crypto.createHash("sha256").update(str).digest("hex");
}

let seeded = false;

export async function seedShims() {
  const now = new Date().toISOString();
  const oneHourAgo = new Date(Date.now() - 3600000).toISOString();

  for (const t of TEMPLATE_SEEDS) {
    await db.insert(policyTemplates).values({
      name: t.name,
      displayName: t.displayName,
      description: t.description,
      rulesJson: JSON.stringify(t.rules),
      version: 1,
      createdAt: now,
      updatedAt: now,
      builtIn: t.builtIn,
    }).onConflictDoNothing();
  }

  const existing = await db.select({ shimId: shims.shimId }).from(shims).limit(1);
  if (existing.length > 0) {
    seeded = true;
    return;
  }

  for (const s of SHIM_DEFS) {
    const status = s.mode === "pending" ? "pending" : s.mode === "contain" ? "contain" : "online";
    await db.insert(shims).values({
      shimId: s.shimId,
      name: s.name,
      siteId: s.siteId,
      zone: s.zone,
      status,
      mode: s.mode === "pending" ? "monitor" : s.mode,
      firmwareVersion: s.firmware,
      ifaceDevice: s.iface_d,
      ifaceSwitch: s.iface_s,
      mgmtIp: s.mgmtIp,
      registeredAt: oneHourAgo,
      lastHeartbeat: status === "pending" ? null : now,
      approvedAt: status !== "pending" ? oneHourAgo : null,
      approvedBy: status !== "pending" ? "admin" : null,
    }).onConflictDoNothing();

    const templateForShim = s.mode === "contain" ? "quarantine" : (s.zone === "Level-1" ? "plc" : s.zone === "Level-2" ? "hmi" : "unknown");
    const templateRules = TEMPLATE_SEEDS.find(t => t.name === templateForShim)?.rules || [];
    const hash = computePolicyHash(templateForShim, s.mode === "pending" ? "monitor" : s.mode, templateRules);

    await db.insert(shimPolicies).values({
      shimId: s.shimId,
      templateName: templateForShim,
      mode: s.mode === "pending" ? "monitor" : s.mode,
      assignedAt: oneHourAgo,
      assignedBy: "system",
      policyHash: hash,
      containSafeJson: s.mode === "contain" ? JSON.stringify([{ type: "allow", dst_ports: [502], proto: "tcp", desc: "HMI-SCADA safe" }]) : null,
    }).onConflictDoNothing();
  }

  for (const d of DOWNSTREAM_DEFS) {
    await db.insert(downstreamDevices).values({
      shimId: d.shimId,
      mac: d.mac,
      ip: d.ip,
      deviceType: d.type,
      deviceName: d.name,
      templateName: d.template,
      firstSeen: oneHourAgo,
      lastSeen: now,
    }).onConflictDoNothing();
  }

  await db.insert(shimAuditLog).values([
    { ts: oneHourAgo, eventType: "shim_registered", actor: "system", shimId: "NETDNA-EDGE-00001", detail: JSON.stringify({ firmware: "1.2.4" }) },
    { ts: oneHourAgo, eventType: "shim_approved", actor: "admin", shimId: "NETDNA-EDGE-00001", detail: "{}" },
    { ts: oneHourAgo, eventType: "shim_registered", actor: "system", shimId: "NETDNA-EDGE-00007", detail: JSON.stringify({ firmware: "1.2.4" }) },
  ]);

  seeded = true;
  console.log("Shim fleet seeded: %d shims, %d downstream devices, %d templates", SHIM_DEFS.length, DOWNSTREAM_DEFS.length, TEMPLATE_SEEDS.length);
}

export async function tickShims(ts: string) {
  if (!seeded) return;

  const allShims = await db.select().from(shims);

  for (const s of allShims) {
    if (s.status === "pending") continue;

    await db.update(shims).set({ lastHeartbeat: ts }).where(eq(shims.shimId, s.shimId));

    const shimDownstream = await db.select().from(downstreamDevices).where(eq(downstreamDevices.shimId, s.shimId));
    const uptimeBase = 3600 + rand(0, 86400);

    await db.insert(shimHealth).values({
      shimId: s.shimId,
      ts,
      cpuPct: randFloat(8, 45),
      memUsedMb: rand(120, 380),
      bridgeLatencyUs: rand(40, 280),
      bridgeDrops: rand(0, 3),
      linkDeviceUp: true,
      linkSwitchUp: true,
      iseConnected: false,
      coreConnected: true,
      uptimeSec: uptimeBase,
      policyVersion: null,
    });

    const healthCount = await db.select({ c: sql<number>`count(*)` }).from(shimHealth).where(eq(shimHealth.shimId, s.shimId));
    if (Number(healthCount[0]?.c) > 240) {
      await db.execute(sql`DELETE FROM shim_health WHERE shim_id = ${s.shimId} AND id NOT IN (SELECT id FROM shim_health WHERE shim_id = ${s.shimId} ORDER BY id DESC LIMIT 240)`);
    }

    if (Math.random() < 0.3 && shimDownstream.length > 0) {
      const dev = pick(shimDownstream);
      const vRule = pick(VIOLATION_RULES);
      const action = s.mode === "enforce" || s.mode === "contain" ? "blocked" : "would_block";
      await db.insert(shimViolations).values({
        shimId: s.shimId,
        ts,
        ruleName: vRule.rule,
        srcIp: randIp("10.0.1"),
        dstIp: dev.ip || randIp("192.168.101"),
        srcPort: rand(1024, 65535),
        dstPort: vRule.dstPorts[0] || rand(1, 1024),
        proto: vRule.proto,
        bytes: rand(64, 8192),
        action,
        mode: s.mode!,
        severity: vRule.sev,
        mitreTechnique: vRule.mitre,
      });
    }

    if (Math.random() < 0.5 && shimDownstream.length > 0) {
      const dev = pick(shimDownstream);
      await db.insert(shimFlows).values({
        shimId: s.shimId,
        ts,
        srcIp: dev.ip || randIp("192.168.101"),
        dstIp: randIp("192.168.102"),
        srcPort: rand(1024, 65535),
        dstPort: pick([502, 44818, 80, 443, 22, 3389]),
        proto: pick(["tcp", "udp"]),
        bytes: rand(64, 32768),
        packets: rand(1, 50),
        action: "forward",
      });
    }

    if (Math.random() < 0.15 && shimDownstream.length > 0) {
      const dev = pick(shimDownstream);
      await db.insert(newTalkers).values({
        shimId: s.shimId,
        ts,
        srcIp: randIp("10.0." + rand(1, 5)),
        dstIp: dev.ip || randIp("192.168.101"),
        dstPort: pick([502, 44818, 80, 443, 22, 3389, 8080, 161]),
        proto: pick(["tcp", "udp"]),
      });
    }
  }
}
