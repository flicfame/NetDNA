import { db } from "../db";
import { anomalies, entityEdges, episodes, episodeAnomalies } from "@shared/schema";
import { eq, and, gt, desc, sql, isNull } from "drizzle-orm";

const WINDOW_MS = 30 * 60 * 1000;

const KILL_CHAIN_ORDER = [
  "reconnaissance", "initial-access", "execution", "persistence",
  "privilege-escalation", "defense-evasion", "credential-access",
  "discovery", "lateral-movement", "collection", "exfiltration",
  "command-and-control", "impact",
];

function tacticToPhase(tactic: string | null): number {
  if (!tactic) return -1;
  const normalized = tactic.toLowerCase().replace(/[\s_]/g, "-");
  const idx = KILL_CHAIN_ORDER.indexOf(normalized);
  return idx >= 0 ? idx : -1;
}

function deriveIntent(phases: number[]): string {
  if (phases.includes(10)) return "Data theft — exfiltration detected";
  if (phases.includes(12)) return "Destructive attack — impact stage reached";
  if (phases.includes(8)) return "Lateral movement campaign";
  if (phases.includes(6)) return "Credential harvesting";
  if (phases.length >= 4) return "Multi-stage intrusion";
  if (phases.length >= 2) return "Active reconnaissance/probing";
  return "Isolated anomaly cluster";
}

export async function tickCorrelator(ts: string) {
  const cutoff = new Date(Date.now() - WINDOW_MS).toISOString();

  const recentAnoms = await db
    .select()
    .from(anomalies)
    .where(and(gt(anomalies.detectedAt, cutoff), eq(anomalies.status, "open")))
    .orderBy(desc(anomalies.detectedAt))
    .limit(200);

  if (recentAnoms.length === 0) return;

  const edges = await db.select().from(entityEdges);
  const neighbors: Record<string, Set<string>> = {};
  for (const e of edges) {
    if (!neighbors[e.srcIp]) neighbors[e.srcIp] = new Set();
    if (!neighbors[e.dstIp]) neighbors[e.dstIp] = new Set();
    neighbors[e.srcIp].add(e.dstIp);
    neighbors[e.dstIp].add(e.srcIp);
  }

  const linked = await db.select({ anomalyId: episodeAnomalies.anomalyId }).from(episodeAnomalies);
  const linkedIds = new Set(linked.map(l => l.anomalyId));

  const unlinked = recentAnoms.filter(a => !linkedIds.has(a.id));
  if (unlinked.length === 0) return;

  const clusters: Array<typeof unlinked> = [];
  const visited = new Set<number>();

  for (const anom of unlinked) {
    if (visited.has(anom.id)) continue;
    const cluster = [anom];
    visited.add(anom.id);

    const entityIps = new Set<string>();
    if (anom.entityIp) {
      entityIps.add(anom.entityIp);
      const nb = neighbors[anom.entityIp];
      if (nb) nb.forEach(ip => entityIps.add(ip));
    }

    for (const other of unlinked) {
      if (visited.has(other.id)) continue;
      if (other.entityIp && entityIps.has(other.entityIp)) {
        cluster.push(other);
        visited.add(other.id);
      }
    }

    if (cluster.length >= 2) {
      clusters.push(cluster);
    }
  }

  for (const cluster of clusters) {
    const phases = cluster
      .map(a => tacticToPhase(a.mitreTactic))
      .filter(p => p >= 0);
    const uniquePhases = Array.from(new Set(phases)).sort((a, b) => a - b);
    const coverage = uniquePhases.length / KILL_CHAIN_ORDER.length;
    const confidence = Math.min(
      Math.round((coverage * 60) + (cluster.length * 5) + (uniquePhases.length * 3)),
      100
    );

    const primaryIp = cluster[0].entityIp || "unknown";
    const intent = deriveIntent(uniquePhases);
    const label = `${intent} — ${primaryIp}`;
    const startTime = cluster.reduce((min, a) => a.detectedAt && a.detectedAt < min ? a.detectedAt : min, ts);
    const endTime = cluster.reduce((max, a) => a.detectedAt && a.detectedAt > max ? a.detectedAt : max, "");

    const [episode] = await db
      .insert(episodes)
      .values({
        label,
        intent,
        confidence,
        startTs: startTime,
        endTs: endTime || ts,
        primaryEntityIp: primaryIp,
        status: confidence >= 70 ? "escalated" : "active",
      })
      .returning();

    for (const anom of cluster) {
      await db.insert(episodeAnomalies).values({
        episodeId: episode.id,
        anomalyId: anom.id,
      });
    }
  }
}
