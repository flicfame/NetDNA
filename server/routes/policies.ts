import { Router } from "express";
import { db } from "../db";
import { policyTemplates, shimPolicies, shims, shimAuditLog } from "@shared/schema";
import { eq, desc } from "drizzle-orm";
import { authMiddleware, requirePermission, type AuthRequest } from "../auth";
import { toSnakeCase, toSnakeCaseArray } from "../utils";
import * as crypto from "crypto";

const router = Router();

router.get("/policies/templates", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const rows = await db
      .select()
      .from(policyTemplates)
      .orderBy(desc(policyTemplates.builtIn));

    const result = rows.map((r) => {
      const obj: any = toSnakeCase(r as any);
      try {
        obj.rules = JSON.parse(r.rulesJson);
      } catch {
        obj.rules = [];
      }
      delete obj.rules_json;
      return obj;
    });

    res.json(result);
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/policies/templates/:name", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const [row] = await db
      .select()
      .from(policyTemplates)
      .where(eq(policyTemplates.name, req.params.name as string));

    if (!row) {
      return res.status(404).json({ detail: `Template '${req.params.name}' not found` });
    }

    const obj: any = toSnakeCase(row as any);
    try {
      obj.rules = JSON.parse(row.rulesJson);
    } catch {
      obj.rules = [];
    }
    delete obj.rules_json;

    res.json(obj);
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.patch("/policies/templates/:name", authMiddleware, requirePermission("view_dashboard"), async (req: AuthRequest, res) => {
  try {
    const name = req.params.name as string;
    const [existing] = await db
      .select()
      .from(policyTemplates)
      .where(eq(policyTemplates.name, name));

    if (!existing) {
      return res.status(404).json({ detail: `Template '${name}' not found` });
    }

    const updates: Record<string, any> = {};
    if (req.body.display_name) updates.displayName = req.body.display_name;
    if (req.body.description) updates.description = req.body.description;
    if (req.body.rules_json) {
      updates.rulesJson = JSON.stringify(req.body.rules_json);
      updates.version = (existing.version || 1) + 1;
    }
    updates.updatedAt = new Date().toISOString();

    if (Object.keys(updates).length <= 1) {
      return res.status(400).json({ detail: "No fields to update" });
    }

    await db
      .update(policyTemplates)
      .set(updates)
      .where(eq(policyTemplates.name, name));

    await db.insert(shimAuditLog).values({
      ts: new Date().toISOString(),
      eventType: "template_updated",
      actor: (req as any).user?.sub || "admin",
      detail: JSON.stringify({ template: name, changes: Object.keys(updates) }),
    });

    res.json({ ok: true, template: name });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.post("/policies/templates", authMiddleware, requirePermission("view_dashboard"), async (req: AuthRequest, res) => {
  try {
    const { name, display_name, description, rules_json } = req.body;

    if (!name || !display_name) {
      return res.status(400).json({ detail: "name and display_name required" });
    }
    if (!rules_json) {
      return res.status(400).json({ detail: "rules_json required" });
    }

    const [existing] = await db
      .select()
      .from(policyTemplates)
      .where(eq(policyTemplates.name, name));

    if (existing) {
      return res.status(409).json({ detail: `Template '${name}' already exists` });
    }

    await db.insert(policyTemplates).values({
      name,
      displayName: display_name,
      description: description || "",
      rulesJson: JSON.stringify(rules_json),
      version: 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      builtIn: false,
    });

    await db.insert(shimAuditLog).values({
      ts: new Date().toISOString(),
      eventType: "template_created",
      actor: (req as any).user?.sub || "admin",
      detail: JSON.stringify({ template: name }),
    });

    res.json({ ok: true, template: name });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.post("/shims/:shimId/policy/assign", authMiddleware, requirePermission("view_dashboard"), async (req: AuthRequest, res) => {
  try {
    const shimId = req.params.shimId as string;
    const { template_name } = req.body;
    const actor = (req as any).user?.sub || "admin";

    const [shim] = await db
      .select()
      .from(shims)
      .where(eq(shims.shimId, shimId));

    if (!shim) {
      return res.status(404).json({ detail: "Shim not found" });
    }

    const [tmpl] = await db
      .select()
      .from(policyTemplates)
      .where(eq(policyTemplates.name, template_name));

    if (!tmpl) {
      return res.status(404).json({ detail: `Template '${template_name}' not found` });
    }

    const rules = JSON.parse(tmpl.rulesJson);
    const mode = shim.mode;
    const policyStr = JSON.stringify({ template: template_name, mode, rules }, Object.keys({ template: template_name, mode, rules }).sort());
    const policyHash = crypto.createHash("sha256").update(policyStr).digest("hex");

    const [existingPolicy] = await db
      .select()
      .from(shimPolicies)
      .where(eq(shimPolicies.shimId, shimId));

    if (existingPolicy) {
      await db
        .update(shimPolicies)
        .set({
          templateName: template_name,
          assignedBy: actor,
          assignedAt: new Date().toISOString(),
          policyHash: policyHash,
        })
        .where(eq(shimPolicies.shimId, shimId));
    } else {
      await db.insert(shimPolicies).values({
        shimId,
        templateName: template_name,
        mode,
        assignedBy: actor,
        assignedAt: new Date().toISOString(),
        policyHash: policyHash,
      });
    }

    await db.insert(shimAuditLog).values({
      ts: new Date().toISOString(),
      eventType: "template_assigned",
      actor,
      shimId,
      detail: JSON.stringify({ template: template_name, hash: policyHash.slice(0, 16) }),
    });

    res.json({ ok: true, template: template_name, policy_hash: policyHash.slice(0, 16) });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/policies/assignments", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const rows = await db
      .select({
        shimId: shimPolicies.shimId,
        templateName: shimPolicies.templateName,
        mode: shimPolicies.mode,
        assignedAt: shimPolicies.assignedAt,
        assignedBy: shimPolicies.assignedBy,
        policyHash: shimPolicies.policyHash,
        siteId: shims.siteId,
        zone: shims.zone,
        status: shims.status,
        displayName: policyTemplates.displayName,
      })
      .from(shimPolicies)
      .innerJoin(shims, eq(shimPolicies.shimId, shims.shimId))
      .innerJoin(policyTemplates, eq(shimPolicies.templateName, policyTemplates.name))
      .orderBy(desc(shimPolicies.assignedAt));

    res.json(toSnakeCaseArray(rows as any));
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

export default router;
