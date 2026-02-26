import { db } from "../db";
import { entities, entityEdges, flows } from "@shared/schema";
import { sql, eq, and, gt } from "drizzle-orm";

export async function tickEdges(ts: string) {
  const cutoff = new Date(Date.now() - 300000).toISOString();

  const recentFlows = await db
    .select({
      srcIp: flows.srcIp,
      dstIp: flows.dstIp,
      cnt: sql<number>`count(*)::int`,
    })
    .from(flows)
    .where(gt(flows.timestamp, cutoff))
    .groupBy(flows.srcIp, flows.dstIp);

  for (const f of recentFlows) {
    if (!f.srcIp || !f.dstIp || f.srcIp === f.dstIp) continue;
    await db
      .insert(entityEdges)
      .values({
        srcIp: f.srcIp,
        dstIp: f.dstIp,
        edgeType: "FLOW",
        weight: f.cnt,
        firstSeen: ts,
        lastSeen: ts,
        evidenceRef: `${f.cnt} flows in last 5min`,
      })
      .onConflictDoNothing();

    await db
      .update(entityEdges)
      .set({ weight: f.cnt, lastSeen: ts, evidenceRef: `${f.cnt} flows in last 5min` })
      .where(
        and(
          eq(entityEdges.srcIp, f.srcIp),
          eq(entityEdges.dstIp, f.dstIp),
          eq(entityEdges.edgeType, "FLOW")
        )
      );
  }

  const allEntities = await db.select({ ipAddress: entities.ipAddress, vlanId: entities.vlanId }).from(entities);
  const vlanGroups: Record<number, string[]> = {};
  for (const e of allEntities) {
    if (e.vlanId == null) continue;
    if (!vlanGroups[e.vlanId]) vlanGroups[e.vlanId] = [];
    vlanGroups[e.vlanId].push(e.ipAddress);
  }

  for (const [vlanId, ips] of Object.entries(vlanGroups)) {
    if (ips.length < 2) continue;
    for (let i = 0; i < ips.length; i++) {
      for (let j = i + 1; j < ips.length; j++) {
        await db
          .insert(entityEdges)
          .values({
            srcIp: ips[i],
            dstIp: ips[j],
            edgeType: "SAME_VLAN",
            weight: 1,
            firstSeen: ts,
            lastSeen: ts,
            evidenceRef: `VLAN ${vlanId}`,
          })
          .onConflictDoNothing();

        await db
          .update(entityEdges)
          .set({ lastSeen: ts })
          .where(
            and(
              eq(entityEdges.srcIp, ips[i]),
              eq(entityEdges.dstIp, ips[j]),
              eq(entityEdges.edgeType, "SAME_VLAN")
            )
          );
      }
    }
  }
}
