import { db } from "../db";
import { entities, entityEdges } from "@shared/schema";
import { eq, sql } from "drizzle-orm";

const DECAY = 0.15;
const MAX_PROPAGATED = 25;

export async function tickPropagation() {
  const allEntities = await db
    .select({ ipAddress: entities.ipAddress, riskScore: entities.riskScore })
    .from(entities);

  const riskMap: Record<string, number> = {};
  for (const e of allEntities) {
    riskMap[e.ipAddress] = e.riskScore ?? 0;
  }

  const edges = await db.select().from(entityEdges);

  const deltas: Record<string, number> = {};

  for (const edge of edges) {
    const srcRisk = riskMap[edge.srcIp] ?? 0;
    const dstRisk = riskMap[edge.dstIp] ?? 0;
    const weight = Math.min(edge.weight ?? 1, 10) / 10;

    if (srcRisk > 40) {
      const inherited = srcRisk * DECAY * weight;
      deltas[edge.dstIp] = Math.min((deltas[edge.dstIp] ?? 0) + inherited, MAX_PROPAGATED);
    }
    if (dstRisk > 40) {
      const inherited = dstRisk * DECAY * weight;
      deltas[edge.srcIp] = Math.min((deltas[edge.srcIp] ?? 0) + inherited, MAX_PROPAGATED);
    }
  }

  for (const [ip, delta] of Object.entries(deltas)) {
    if (delta < 1) continue;
    const baseRisk = riskMap[ip] ?? 0;
    const newRisk = Math.min(Math.round(baseRisk + delta), 100);
    if (newRisk <= baseRisk) continue;

    await db
      .update(entities)
      .set({ riskScore: newRisk, updatedAt: new Date().toISOString() })
      .where(eq(entities.ipAddress, ip));
  }
}
