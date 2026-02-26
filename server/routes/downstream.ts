import { Router } from "express";
import { db } from "../db";
import { downstreamDevices, shims, shimViolations } from "@shared/schema";
import { eq, desc, or, and } from "drizzle-orm";
import { authMiddleware, requirePermission, type AuthRequest } from "../auth";
import { toSnakeCase, toSnakeCaseArray } from "../utils";

const router = Router();

const VALID_DEVICE_TYPES = ["PLC", "RTU", "HMI", "Historian", "EngWS", "Switch", "Unknown"];
const VALID_TEMPLATES = ["plc", "rtu", "hmi", "historian", "unknown", "quarantine"];

router.get("/downstream", authMiddleware, requirePermission("view_dashboard"), async (_req, res) => {
  try {
    const devices = await db
      .select({
        id: downstreamDevices.id,
        shimId: downstreamDevices.shimId,
        mac: downstreamDevices.mac,
        ip: downstreamDevices.ip,
        deviceType: downstreamDevices.deviceType,
        deviceName: downstreamDevices.deviceName,
        templateName: downstreamDevices.templateName,
        iseGroup: downstreamDevices.iseGroup,
        iseEndpointId: downstreamDevices.iseEndpointId,
        firstSeen: downstreamDevices.firstSeen,
        lastSeen: downstreamDevices.lastSeen,
        notes: downstreamDevices.notes,
        siteId: shims.siteId,
        zone: shims.zone,
        shimName: shims.name,
      })
      .from(downstreamDevices)
      .leftJoin(shims, eq(downstreamDevices.shimId, shims.shimId))
      .orderBy(desc(downstreamDevices.lastSeen));

    res.json(toSnakeCaseArray(devices as any));
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/downstream/:deviceId", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const deviceId = parseInt(req.params.deviceId as string);
    const [device] = await db
      .select()
      .from(downstreamDevices)
      .where(eq(downstreamDevices.id, deviceId));

    if (!device) {
      return res.status(404).json({ detail: "Device not found" });
    }
    res.json(toSnakeCase(device as any));
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.patch("/downstream/:deviceId", authMiddleware, requirePermission("view_dashboard"), async (req: AuthRequest, res) => {
  try {
    const deviceId = parseInt(req.params.deviceId as string);
    const [existing] = await db
      .select()
      .from(downstreamDevices)
      .where(eq(downstreamDevices.id, deviceId));

    if (!existing) {
      return res.status(404).json({ detail: "Device not found" });
    }

    const { device_type, device_name, template_name, ise_group, notes } = req.body;

    if (device_type && !VALID_DEVICE_TYPES.includes(device_type)) {
      return res.status(400).json({ detail: `Invalid device_type. Valid: ${VALID_DEVICE_TYPES.join(", ")}` });
    }
    if (template_name && !VALID_TEMPLATES.includes(template_name)) {
      return res.status(400).json({ detail: `Invalid template. Valid: ${VALID_TEMPLATES.join(", ")}` });
    }

    const updates: Record<string, any> = {};
    if (device_type !== undefined) updates.deviceType = device_type;
    if (device_name !== undefined) updates.deviceName = device_name;
    if (template_name !== undefined) updates.templateName = template_name;
    if (ise_group !== undefined) updates.iseGroup = ise_group;
    if (notes !== undefined) updates.notes = notes;

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ detail: "No fields to update" });
    }

    await db
      .update(downstreamDevices)
      .set(updates)
      .where(eq(downstreamDevices.id, deviceId));

    const [updated] = await db
      .select()
      .from(downstreamDevices)
      .where(eq(downstreamDevices.id, deviceId));

    res.json(toSnakeCase(updated as any));
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/downstream/:deviceId/history", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const deviceId = parseInt(req.params.deviceId as string);
    const [device] = await db
      .select()
      .from(downstreamDevices)
      .where(eq(downstreamDevices.id, deviceId));

    if (!device) {
      return res.status(404).json({ detail: "Device not found" });
    }

    const violations = await db
      .select()
      .from(shimViolations)
      .where(
        and(
          eq(shimViolations.shimId, device.shimId),
          or(
            eq(shimViolations.srcIp, device.ip || ""),
            eq(shimViolations.dstIp, device.ip || "")
          )
        )
      )
      .orderBy(desc(shimViolations.ts))
      .limit(100);

    res.json(toSnakeCaseArray(violations as any));
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

export default router;
