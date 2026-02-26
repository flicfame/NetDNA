import { Router } from "express";
import { db } from "../db";
import { episodes, episodeAnomalies, anomalies } from "@shared/schema";
import { eq, desc, count } from "drizzle-orm";
import { authMiddleware, requirePermission } from "../auth";

const router = Router();

router.get("/", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const limit = parseInt((req.query.limit as string) || "50");
    const statusFilter = req.query.status as string | undefined;
    const where = statusFilter ? eq(episodes.status, statusFilter) : undefined;

    const rows = await db
      .select()
      .from(episodes)
      .where(where)
      .orderBy(desc(episodes.startTs))
      .limit(limit);

    const results = await Promise.all(
      rows.map(async (ep) => {
        const [anomCount] = await db
          .select({ cnt: count() })
          .from(episodeAnomalies)
          .where(eq(episodeAnomalies.episodeId, ep.id));
        return {
          id: ep.id,
          label: ep.label,
          intent: ep.intent,
          confidence: ep.confidence,
          start_ts: ep.startTs,
          end_ts: ep.endTs,
          primary_entity_ip: ep.primaryEntityIp,
          status: ep.status,
          anomaly_count: anomCount.cnt || 0,
        };
      })
    );

    res.json({ episodes: results, count: results.length });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/:id", authMiddleware, requirePermission("view_dashboard"), async (req, res) => {
  try {
    const id = parseInt(req.params.id as string);
    const [episode] = await db.select().from(episodes).where(eq(episodes.id, id));
    if (!episode) return res.status(404).json({ detail: "Episode not found" });

    const links = await db
      .select({ anomalyId: episodeAnomalies.anomalyId })
      .from(episodeAnomalies)
      .where(eq(episodeAnomalies.episodeId, id));

    const linkedAnoms = [];
    for (const link of links) {
      const [anom] = await db
        .select()
        .from(anomalies)
        .where(eq(anomalies.id, link.anomalyId));
      if (anom) linkedAnoms.push(anom);
    }

    res.json({
      id: episode.id,
      label: episode.label,
      intent: episode.intent,
      confidence: episode.confidence,
      start_ts: episode.startTs,
      end_ts: episode.endTs,
      primary_entity_ip: episode.primaryEntityIp,
      status: episode.status,
      anomalies: linkedAnoms.map(a => ({
        id: a.id,
        detected_at: a.detectedAt,
        entity_ip: a.entityIp,
        anomaly_type: a.anomalyType,
        severity: a.severity,
        risk_score: a.riskScore,
        confidence: a.confidence,
        description: a.description,
        mitre_technique: a.mitreTechnique,
        mitre_tactic: a.mitreTactic,
        status: a.status,
      })),
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

export default router;
