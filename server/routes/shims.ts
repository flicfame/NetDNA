import { Router } from "express";
import { db } from "../db";
import {
  shims, shimHealth, shimViolations, shimFlows, shimPolicies,
  policyTemplates, downstreamDevices, shimAuditLog, newTalkers,
  insertShimSchema, insertShimHealthSchema, insertShimViolationSchema,
  insertShimFlowSchema, insertShimAuditLogSchema, insertDownstreamDeviceSchema,
  insertNewTalkerSchema,
} from "@shared/schema";
import { eq, desc, asc, and, gt, count, sql } from "drizzle-orm";
import { authMiddleware, requirePermission, type AuthRequest } from "../auth";
import crypto from "crypto";

const router = Router();

function buildPolicyHash(templateName: string, mode: string, rulesJson: string): string {
  const str = JSON.stringify({ template: templateName, mode, rules: JSON.parse(rulesJson) }, Object.keys({ template: "", mode: "", rules: [] }).sort());
  return crypto.createHash("sha256").update(str).digest("hex");
}

router.get("/stats", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const [total] = await db.select({ cnt: count() }).from(shims);
    const [online] = await db.select({ cnt: count() }).from(shims).where(eq(shims.status, "online"));
    const [pending] = await db.select({ cnt: count() }).from(shims).where(eq(shims.status, "pending"));
    const [contained] = await db.select({ cnt: count() }).from(shims).where(eq(shims.status, "contain"));

    const cutoff24h = new Date(Date.now() - 86400000).toISOString();
    const [violations24h] = await db.select({ cnt: count() }).from(shimViolations).where(gt(shimViolations.ts, cutoff24h));
    const [shadow24h] = await db.select({ cnt: count() }).from(shimViolations).where(and(eq(shimViolations.action, "would_block"), gt(shimViolations.ts, cutoff24h)));

    res.json({
      shims_total: total.cnt,
      shims_online: online.cnt,
      shims_pending: pending.cnt,
      shims_contained: contained.cnt,
      violations_24h: violations24h.cnt,
      shadow_events_24h: shadow24h.cnt,
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.post("/register", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const body = req.body;
    const shimId = body.shim_id;
    if (!shimId) return res.status(400).json({ detail: "shim_id required" });

    const [existing] = await db.select().from(shims).where(eq(shims.shimId, shimId));

    if (!existing) {
      const now = new Date().toISOString();
      await db.insert(shims).values({
        shimId,
        name: body.name || shimId,
        siteId: body.site_id || null,
        zone: body.zone || null,
        status: "pending",
        mode: "monitor",
        firmwareVersion: body.firmware_version || null,
        ifaceDevice: body.iface_device || null,
        ifaceSwitch: body.iface_switch || null,
        mgmtIp: body.mgmt_ip || null,
        certFingerprint: body.cert_fingerprint || null,
        registeredAt: now,
      });

      await db.insert(shimPolicies).values({
        shimId,
        templateName: "unknown",
        mode: "monitor",
        assignedAt: now,
        assignedBy: "system",
      }).onConflictDoNothing();

      await db.insert(shimAuditLog).values({
        ts: now,
        eventType: "shim_registered",
        actor: "shim",
        shimId,
        detail: JSON.stringify({ firmware: body.firmware_version, site: body.site_id }),
      });

      return res.json({
        status: "pending",
        mode: "monitor",
        message: "Shim registered. Awaiting admin approval in NetDNA Core UI.",
      });
    }

    const now = new Date().toISOString();
    await db.update(shims).set({
      firmwareVersion: body.firmware_version || existing.firmwareVersion,
      mgmtIp: body.mgmt_ip || existing.mgmtIp,
      lastHeartbeat: now,
      status: existing.status === "pending" ? "pending" : "online",
    }).where(eq(shims.shimId, shimId));

    if (existing.status === "pending") {
      return res.json({
        status: "pending",
        mode: "monitor",
        message: "Awaiting admin approval.",
      });
    }

    const [pol] = await db.select().from(shimPolicies).where(eq(shimPolicies.shimId, shimId));
    let policy = null;
    if (pol) {
      const [tmpl] = await db.select().from(policyTemplates).where(eq(policyTemplates.name, pol.templateName));
      if (tmpl) {
        policy = {
          template_name: pol.templateName,
          mode: pol.mode,
          rules: JSON.parse(tmpl.rulesJson),
          policy_hash: pol.policyHash || buildPolicyHash(pol.templateName, pol.mode, tmpl.rulesJson),
          contain_safe: pol.containSafeJson ? JSON.parse(pol.containSafeJson) : null,
        };
      }
    }

    res.json({
      status: existing.status,
      mode: existing.mode,
      policy,
      message: "Welcome back.",
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.post("/:shimId/heartbeat", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const shimId = req.params.shimId;
    const [shim] = await db.select().from(shims).where(eq(shims.shimId, shimId));
    if (!shim) return res.status(404).json({ detail: `Shim ${shimId} not registered` });
    if (shim.status === "pending") return res.status(403).json({ detail: "Shim not yet approved" });

    const now = new Date().toISOString();
    await db.update(shims).set({
      lastHeartbeat: now,
      status: shim.status === "contain" ? "contain" : "online",
    }).where(eq(shims.shimId, shimId));

    const body = req.body;
    await db.insert(shimHealth).values({
      shimId,
      ts: body.ts || now,
      cpuPct: body.cpu_pct ?? null,
      memUsedMb: body.mem_used_mb ?? null,
      bridgeLatencyUs: body.bridge_latency_us ?? null,
      bridgeDrops: body.bridge_drops ?? null,
      linkDeviceUp: body.link_device_up ?? true,
      linkSwitchUp: body.link_switch_up ?? true,
      iseConnected: body.ise_connected ?? false,
      coreConnected: body.core_connected ?? true,
      uptimeSec: body.uptime_sec ?? null,
      policyVersion: body.policy_version ?? null,
    });

    const [pol] = await db.select().from(shimPolicies).where(eq(shimPolicies.shimId, shimId));
    const currentHash = pol?.policyHash || null;
    const policyChanged = !!(currentHash && body.policy_version && body.policy_version !== currentHash);

    res.json({
      ok: true,
      policy_changed: policyChanged,
      current_policy_hash: currentHash,
      server_ts: now,
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/:shimId/policy", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const shimId = req.params.shimId;
    const [shim] = await db.select().from(shims).where(eq(shims.shimId, shimId));
    if (!shim) return res.status(404).json({ detail: "Shim not found" });
    if (shim.status === "pending") return res.status(403).json({ detail: "Not approved" });

    const [pol] = await db.select().from(shimPolicies).where(eq(shimPolicies.shimId, shimId));
    if (!pol) return res.status(404).json({ detail: "No policy assigned" });

    const [tmpl] = await db.select().from(policyTemplates).where(eq(policyTemplates.name, pol.templateName));
    if (!tmpl) return res.status(404).json({ detail: "Policy template not found" });

    const rules = JSON.parse(tmpl.rulesJson);
    const policyHash = pol.policyHash || buildPolicyHash(pol.templateName, pol.mode, tmpl.rulesJson);

    res.json({
      template_name: pol.templateName,
      mode: pol.mode,
      rules,
      policy_hash: policyHash,
      contain_safe: pol.containSafeJson ? JSON.parse(pol.containSafeJson) : null,
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const allShims = await db.select().from(shims);
    const cutoff24h = new Date(Date.now() - 86400000).toISOString();

    const result = await Promise.all(allShims.map(async (s) => {
      const [latestHealth] = await db.select().from(shimHealth)
        .where(eq(shimHealth.shimId, s.shimId))
        .orderBy(desc(shimHealth.id))
        .limit(1);

      const [dsCount] = await db.select({ cnt: count() }).from(downstreamDevices)
        .where(eq(downstreamDevices.shimId, s.shimId));

      const [violCount] = await db.select({ cnt: count() }).from(shimViolations)
        .where(and(eq(shimViolations.shimId, s.shimId), gt(shimViolations.ts, cutoff24h)));

      const [pol] = await db.select().from(shimPolicies)
        .where(eq(shimPolicies.shimId, s.shimId));

      return {
        shim_id: s.shimId,
        name: s.name,
        site_id: s.siteId,
        zone: s.zone,
        status: s.status,
        mode: s.mode,
        firmware_version: s.firmwareVersion,
        iface_device: s.ifaceDevice,
        iface_switch: s.ifaceSwitch,
        mgmt_ip: s.mgmtIp,
        cert_fingerprint: s.certFingerprint,
        registered_at: s.registeredAt,
        last_heartbeat: s.lastHeartbeat,
        approved_at: s.approvedAt,
        approved_by: s.approvedBy,
        notes: s.notes,
        health: latestHealth ? {
          cpu_pct: latestHealth.cpuPct,
          mem_used_mb: latestHealth.memUsedMb,
          bridge_latency_us: latestHealth.bridgeLatencyUs,
          bridge_drops: latestHealth.bridgeDrops,
          link_device_up: latestHealth.linkDeviceUp,
          link_switch_up: latestHealth.linkSwitchUp,
          ise_connected: latestHealth.iseConnected,
          core_connected: latestHealth.coreConnected,
          uptime_sec: latestHealth.uptimeSec,
          policy_version: latestHealth.policyVersion,
        } : null,
        downstream_count: dsCount.cnt,
        violations_24h: violCount.cnt,
        template_name: pol?.templateName || null,
      };
    }));

    res.json(result);
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/:shimId", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const shimId = req.params.shimId;
    const [shim] = await db.select().from(shims).where(eq(shims.shimId, shimId));
    if (!shim) return res.status(404).json({ detail: "Shim not found" });

    const cutoff24h = new Date(Date.now() - 86400000).toISOString();

    const health24h = await db.select().from(shimHealth)
      .where(and(eq(shimHealth.shimId, shimId), gt(shimHealth.ts, cutoff24h)))
      .orderBy(asc(shimHealth.ts));

    const downstream = await db.select().from(downstreamDevices)
      .where(eq(downstreamDevices.shimId, shimId));

    const violations = await db.select().from(shimViolations)
      .where(eq(shimViolations.shimId, shimId))
      .orderBy(desc(shimViolations.ts))
      .limit(50);

    const [pol] = await db.select().from(shimPolicies).where(eq(shimPolicies.shimId, shimId));
    let policyData = null;
    if (pol) {
      const [tmpl] = await db.select().from(policyTemplates).where(eq(policyTemplates.name, pol.templateName));
      if (tmpl) {
        policyData = {
          template_name: pol.templateName,
          mode: pol.mode,
          display_name: tmpl.displayName,
          description: tmpl.description,
          rules_json: tmpl.rulesJson,
          assigned_at: pol.assignedAt,
          assigned_by: pol.assignedBy,
          policy_hash: pol.policyHash,
          contain_safe_json: pol.containSafeJson,
        };
      }
    }

    res.json({
      shim_id: shim.shimId,
      name: shim.name,
      site_id: shim.siteId,
      zone: shim.zone,
      status: shim.status,
      mode: shim.mode,
      firmware_version: shim.firmwareVersion,
      iface_device: shim.ifaceDevice,
      iface_switch: shim.ifaceSwitch,
      mgmt_ip: shim.mgmtIp,
      cert_fingerprint: shim.certFingerprint,
      registered_at: shim.registeredAt,
      last_heartbeat: shim.lastHeartbeat,
      approved_at: shim.approvedAt,
      approved_by: shim.approvedBy,
      notes: shim.notes,
      health_24h: health24h.map(h => ({
        ts: h.ts,
        cpu_pct: h.cpuPct,
        mem_used_mb: h.memUsedMb,
        bridge_latency_us: h.bridgeLatencyUs,
        bridge_drops: h.bridgeDrops,
        link_device_up: h.linkDeviceUp,
        link_switch_up: h.linkSwitchUp,
        ise_connected: h.iseConnected,
        core_connected: h.coreConnected,
        uptime_sec: h.uptimeSec,
        policy_version: h.policyVersion,
      })),
      downstream: downstream.map(d => ({
        id: d.id,
        shim_id: d.shimId,
        mac: d.mac,
        ip: d.ip,
        device_type: d.deviceType,
        device_name: d.deviceName,
        template_name: d.templateName,
        ise_group: d.iseGroup,
        ise_endpoint_id: d.iseEndpointId,
        first_seen: d.firstSeen,
        last_seen: d.lastSeen,
        notes: d.notes,
      })),
      violations: violations.map(v => ({
        id: v.id,
        shim_id: v.shimId,
        ts: v.ts,
        rule_name: v.ruleName,
        src_ip: v.srcIp,
        dst_ip: v.dstIp,
        src_port: v.srcPort,
        dst_port: v.dstPort,
        proto: v.proto,
        bytes: v.bytes,
        action: v.action,
        mode: v.mode,
        severity: v.severity,
        mitre_technique: v.mitreTechnique,
      })),
      policy: policyData,
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.post("/:shimId/approve", authMiddleware, requirePermission("view_dashboard"), async (req: AuthRequest, res) => {
  try {
    const shimId = req.params.shimId;
    const [shim] = await db.select().from(shims).where(eq(shims.shimId, shimId));
    if (!shim) return res.status(404).json({ detail: "Shim not found" });
    if (shim.status !== "pending") return res.status(400).json({ detail: `Shim is already ${shim.status}` });

    const now = new Date().toISOString();
    const approvedBy = req.body.approved_by || (req as any).user?.sub || "admin";

    await db.update(shims).set({
      status: "online",
      approvedAt: now,
      approvedBy,
    }).where(eq(shims.shimId, shimId));

    await db.insert(shimAuditLog).values({
      ts: now,
      eventType: "shim_approved",
      actor: approvedBy,
      shimId,
      detail: null,
    });

    res.json({ ok: true, message: `Shim ${shimId} approved` });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.post("/:shimId/mode", authMiddleware, requirePermission("view_dashboard"), async (req: AuthRequest, res) => {
  try {
    const shimId = req.params.shimId;
    const [shim] = await db.select().from(shims).where(eq(shims.shimId, shimId));
    if (!shim) return res.status(404).json({ detail: "Shim not found" });
    if (shim.status === "pending") return res.status(400).json({ detail: "Cannot set mode on unapproved shim" });

    const newMode = req.body.mode;
    if (!["monitor", "enforce", "contain"].includes(newMode)) {
      return res.status(400).json({ detail: `Invalid mode: ${newMode}` });
    }
    if (newMode === "contain" && !req.body.contain_safe) {
      return res.status(400).json({ detail: "contain_safe list required for contain mode" });
    }

    const now = new Date().toISOString();
    const actor = req.body.actor || (req as any).user?.sub || "admin";
    const containJson = req.body.contain_safe ? JSON.stringify(req.body.contain_safe) : null;

    await db.update(shimPolicies).set({
      mode: newMode,
      containSafeJson: containJson,
      assignedBy: actor,
      assignedAt: now,
    }).where(eq(shimPolicies.shimId, shimId));

    await db.update(shims).set({
      mode: newMode,
      status: newMode === "contain" ? "contain" : shim.status,
    }).where(eq(shims.shimId, shimId));

    await db.insert(shimAuditLog).values({
      ts: now,
      eventType: "mode_changed",
      actor,
      shimId,
      detail: JSON.stringify({ from: shim.mode, to: newMode }),
    });

    res.json({ ok: true, mode: newMode });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.post("/:shimId/contain/clear", authMiddleware, requirePermission("view_dashboard"), async (req: AuthRequest, res) => {
  try {
    const shimId = req.params.shimId;
    const [shim] = await db.select().from(shims).where(eq(shims.shimId, shimId));
    if (!shim) return res.status(404).json({ detail: "Shim not found" });

    const now = new Date().toISOString();
    const actor = req.body.actor || (req as any).user?.sub || "admin";

    await db.update(shimPolicies).set({
      mode: "enforce",
      containSafeJson: null,
    }).where(eq(shimPolicies.shimId, shimId));

    await db.update(shims).set({
      status: "online",
      mode: "enforce",
    }).where(eq(shims.shimId, shimId));

    await db.insert(shimAuditLog).values({
      ts: now,
      eventType: "contain_cleared",
      actor,
      shimId,
      detail: null,
    });

    res.json({ ok: true, mode: "enforce" });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/:shimId/audit", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const shimId = req.params.shimId;
    const limit = parseInt((req.query.limit as string) || "50");

    const rows = await db.select().from(shimAuditLog)
      .where(eq(shimAuditLog.shimId, shimId))
      .orderBy(desc(shimAuditLog.ts))
      .limit(limit);

    res.json(rows.map(r => ({
      id: r.id,
      ts: r.ts,
      event_type: r.eventType,
      actor: r.actor,
      shim_id: r.shimId,
      detail: r.detail,
    })));
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.post("/telemetry", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const body = req.body;
    const shimId = body.shim_id;
    if (!shimId) return res.status(400).json({ detail: "shim_id required" });

    const [shim] = await db.select().from(shims).where(eq(shims.shimId, shimId));
    if (!shim) return res.status(404).json({ detail: `Unknown shim: ${shimId}` });
    if (shim.status === "pending") return res.status(403).json({ detail: "Shim not approved" });

    const violations = body.violations || [];
    const flows = body.flows || [];
    const newTalkersBatch = body.new_talkers || [];

    for (const v of violations) {
      await db.insert(shimViolations).values({
        shimId,
        ts: v.ts || new Date().toISOString(),
        ruleName: v.rule_name,
        srcIp: v.src_ip || null,
        dstIp: v.dst_ip || null,
        srcPort: v.src_port ?? null,
        dstPort: v.dst_port ?? null,
        proto: v.proto || null,
        bytes: v.bytes ?? null,
        action: v.action,
        mode: v.mode,
        severity: v.severity || "medium",
        mitreTechnique: v.mitre_technique || null,
      });
    }

    for (const f of flows) {
      await db.insert(shimFlows).values({
        shimId,
        ts: f.ts || new Date().toISOString(),
        srcIp: f.src_ip || null,
        dstIp: f.dst_ip || null,
        srcPort: f.src_port ?? null,
        dstPort: f.dst_port ?? null,
        proto: f.proto || null,
        bytes: f.bytes ?? null,
        packets: f.packets ?? null,
        action: f.action || "allow",
      });
    }

    let ntIngested = 0;
    for (const t of newTalkersBatch) {
      if (!t.dst_ip) continue;
      await db.insert(newTalkers).values({
        shimId,
        ts: new Date().toISOString(),
        srcIp: t.src_ip || null,
        dstIp: t.dst_ip,
        dstPort: typeof t.dst_port === "number" ? t.dst_port : null,
        proto: t.proto || null,
      });
      ntIngested++;
    }

    res.json({
      ok: true,
      ingested: {
        violations: violations.length,
        flows: flows.length,
        new_talkers: ntIngested,
      },
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.post("/:shimId/downstream", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const shimId = req.params.shimId;
    const [shim] = await db.select().from(shims).where(eq(shims.shimId, shimId));
    if (!shim) return res.status(404).json({ detail: "Shim not found" });

    const body = req.body;
    const mac = body.mac;
    if (!mac) return res.status(400).json({ detail: "mac required" });

    const [existing] = await db.select().from(downstreamDevices)
      .where(and(eq(downstreamDevices.shimId, shimId), eq(downstreamDevices.mac, mac)));

    if (!existing) {
      const now = new Date().toISOString();
      await db.insert(downstreamDevices).values({
        shimId,
        mac,
        ip: body.ip || null,
        templateName: "unknown",
        firstSeen: now,
        lastSeen: now,
      });

      await db.insert(shimAuditLog).values({
        ts: now,
        eventType: "downstream_discovered",
        actor: "shim",
        shimId,
        detail: JSON.stringify({ mac, ip: body.ip }),
      });

      return res.json({ new: true, template: "unknown" });
    }

    await db.update(downstreamDevices).set({
      ip: body.ip || existing.ip,
      lastSeen: new Date().toISOString(),
    }).where(eq(downstreamDevices.id, existing.id));

    res.json({ new: false, template: existing.templateName });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/:shimId/violations", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const shimId = req.params.shimId;
    const hours = parseInt((req.query.hours as string) || "24");
    const limit = parseInt((req.query.limit as string) || "200");

    const cutoff = new Date(Date.now() - hours * 3600000).toISOString();

    const rows = await db.select().from(shimViolations)
      .where(and(eq(shimViolations.shimId, shimId), gt(shimViolations.ts, cutoff)))
      .orderBy(desc(shimViolations.ts))
      .limit(limit);

    res.json(rows.map(v => ({
      id: v.id,
      shim_id: v.shimId,
      ts: v.ts,
      rule_name: v.ruleName,
      src_ip: v.srcIp,
      dst_ip: v.dstIp,
      src_port: v.srcPort,
      dst_port: v.dstPort,
      proto: v.proto,
      bytes: v.bytes,
      action: v.action,
      mode: v.mode,
      severity: v.severity,
      mitre_technique: v.mitreTechnique,
    })));
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/:shimId/new-talkers", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const shimId = req.params.shimId;
    const hours = Math.max(1, Math.min(8760, parseInt((req.query.hours as string) || "168") || 168));
    const limitVal = Math.max(1, Math.min(1000, parseInt((req.query.limit as string) || "200") || 200));

    const cutoff = new Date(Date.now() - hours * 3600000).toISOString();

    const rows = await db.select().from(newTalkers)
      .where(and(eq(newTalkers.shimId, shimId), gt(newTalkers.ts, cutoff)))
      .orderBy(desc(newTalkers.ts))
      .limit(limitVal);

    res.json(rows.map(t => ({
      id: t.id,
      shim_id: t.shimId,
      ts: t.ts,
      src_ip: t.srcIp,
      dst_ip: t.dstIp,
      dst_port: t.dstPort,
      proto: t.proto,
    })));
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

export default router;
