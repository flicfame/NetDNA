import { db } from "../db";
import { otDevices, otEvents, otProcessValues } from "@shared/schema";
import { eq } from "drizzle-orm";
import { OT_DEVICES_DATA, OT_PROCESS_TAGS } from "./data-remote";
import { rand, pick } from "./data";

export const OT_EVENT_TYPES = [
  { type: "boundary_cross",  sev: "critical", desc: "IT\u2192OT boundary crossing detected \u2014 unauthorized traffic from IT subnet to OT zone",      technique: "T0886", tactic: "Lateral Movement",       ciscoRisk: "Segmentation failure" },
  { type: "firmware_change",  sev: "critical", desc: "Unexpected firmware modification detected on industrial controller \u2014 integrity at risk",       technique: "T0839", tactic: "Impair Process Control", ciscoRisk: "Integrity breach" },
  { type: "engineering_scan", sev: "high",     desc: "Engineering workstation scanning OT subnet \u2014 zone policy violation",                           technique: "T0846", tactic: "Discovery",              ciscoRisk: "Zone policy drift" },
  { type: "rogue_hmi",        sev: "high",     desc: "Rogue HMI connection from unknown IP \u2014 unauthorized operator interface detected",              technique: "T0855", tactic: "Initial Access",         ciscoRisk: "Trust violation" },
  { type: "historian_exfil",  sev: "high",     desc: "Historian data exfiltration \u2014 bulk read of process data to external destination",               technique: "T0882", tactic: "Collection",             ciscoRisk: "Remote access misuse" },
  { type: "coil_manip",       sev: "critical", desc: "PLC output coil manipulation \u2014 unauthorized write command to safety-critical output",          technique: "T0831", tactic: "Impair Process Control", ciscoRisk: "Safety process override" },
  { type: "dnp3_flood",       sev: "high",     desc: "DNP3 protocol flood detected \u2014 high-volume requests targeting SCADA communications",           technique: "T0814", tactic: "Inhibit Response",       ciscoRisk: "Availability risk" },
];

export async function seedOtDevices() {
  const now = new Date().toISOString();
  for (const d of OT_DEVICES_DATA) {
    try {
      await db.insert(otDevices).values({
        name: d.name,
        ipAddress: d.ip,
        deviceType: d.type,
        vendor: d.vendor,
        purdueLevel: d.level,
        protocol: d.protocol,
        functionDesc: d.fn,
        firmwareVer: `v${rand(2, 5)}.${rand(0, 9)}.${rand(0, 9)}`,
        status: "online",
        riskScore: rand(0, 30),
        lastSeen: now,
      }).onConflictDoNothing();
    } catch {}
  }
}

export async function generateInitialOt() {
  const now = new Date();

  for (const tag of OT_PROCESS_TAGS) {
    const ts = now.toISOString();
    const drift = (Math.random() - 0.5) * (tag.max - tag.min) * 0.3;
    const val = tag.normal + drift;
    const isAlarm = val < tag.min || val > tag.max;
    try {
      await db.insert(otProcessValues).values({
        timestamp: ts, deviceName: tag.device, tagName: tag.tag,
        value: parseFloat(val.toFixed(2)), unit: tag.unit,
        normalMin: tag.min, normalMax: tag.max, isAlarm,
      });
    } catch {}
  }

  for (let i = 0; i < 5; i++) {
    const evt = pick(OT_EVENT_TYPES);
    const dev = pick(OT_DEVICES_DATA.filter(d => d.level <= 2));
    try {
      await db.insert(otEvents).values({
        timestamp: new Date(now.getTime() - rand(0, 3600000)).toISOString(),
        deviceName: dev.name, deviceIp: dev.ip,
        eventType: evt.type, severity: evt.sev,
        description: evt.desc, mitreTechnique: evt.technique,
        mitreTactic: evt.tactic, ciscoRisk: evt.ciscoRisk,
        srcIp: `10.10.${rand(1, 254)}.${rand(1, 254)}`,
        dstIp: dev.ip, protocol: dev.protocol, status: "open",
      });
    } catch {}
  }
}

export async function tickOt(ts: string) {
  for (const tag of OT_PROCESS_TAGS) {
    if (Math.random() < 0.5) {
      const drift = (Math.random() - 0.5) * (tag.max - tag.min) * 0.4;
      const val = parseFloat((tag.normal + drift).toFixed(2));
      const isAlarm = val < tag.min || val > tag.max;
      await db.insert(otProcessValues).values({
        timestamp: ts, deviceName: tag.device, tagName: tag.tag,
        value: val, unit: tag.unit,
        normalMin: tag.min, normalMax: tag.max, isAlarm,
      });
    }
  }

  if (Math.random() < 0.1) {
    const evt = pick(OT_EVENT_TYPES);
    const dev = pick(OT_DEVICES_DATA.filter(d => d.level <= 2));
    await db.insert(otEvents).values({
      timestamp: ts, deviceName: dev.name, deviceIp: dev.ip,
      eventType: evt.type, severity: evt.sev,
      description: evt.desc, mitreTechnique: evt.technique,
      mitreTactic: evt.tactic, ciscoRisk: evt.ciscoRisk,
      srcIp: `10.10.${rand(1, 254)}.${rand(1, 254)}`,
      dstIp: dev.ip, protocol: dev.protocol, status: "open",
    });
  }

  if (Math.random() < 0.1) {
    const dev = pick(OT_DEVICES_DATA);
    await db.update(otDevices)
      .set({ riskScore: rand(0, 50), lastSeen: ts })
      .where(eq(otDevices.name, dev.name));
  }
}
