import { Router } from "express";

const router = Router();

router.post("/enroll", async (_req, res) => {
  try {
    res.status(503).json({
      detail: "Certificate enrollment not available in simulation mode",
      message: "On production, use netdna-core with mTLS. Run: bash scripts/issue-cert.sh <SHIM_ID>",
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

export default router;
