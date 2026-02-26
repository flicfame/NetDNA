import { Router } from "express";
import type { Request, Response, NextFunction } from "express";
import {
  authMiddleware, createToken, verifyPassword,
  PERMISSIONS, ROLE_LABELS, type AuthRequest,
} from "../auth";
import * as store from "../storage";

const router = Router();

const loginAttempts = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT = 10;
const RATE_WINDOW = 60000;

function loginRateLimit(req: Request, res: Response, next: NextFunction) {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (entry && now < entry.resetAt) {
    if (entry.count >= RATE_LIMIT) {
      return res.status(429).json({ detail: "Too many login attempts. Try again later." });
    }
    entry.count++;
  } else {
    loginAttempts.set(ip, { count: 1, resetAt: now + RATE_WINDOW });
  }
  next();
}

router.post("/login", loginRateLimit, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ detail: "Username and password required" });

    const user = await store.getUser(username);
    if (!user || !verifyPassword(password, user.hashedPw)) {
      return res.status(401).json({ detail: "Incorrect username or password" });
    }
    if (!user.isActive) return res.status(403).json({ detail: "Account disabled" });

    await store.updateUser(user.id, { lastLogin: new Date().toISOString() });
    const token = createToken(user);
    const role = user.role;
    res.json({
      access_token: token,
      token_type: "bearer",
      user: {
        id: user.id,
        username: user.username,
        full_name: user.fullName,
        role,
        role_label: ROLE_LABELS[role]?.label || role,
        permissions: Array.from(PERMISSIONS[role] || []),
      },
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.get("/me", authMiddleware, async (req: AuthRequest, res) => {
  try {
    const user = await store.getUser((req as any).user.sub);
    if (!user) return res.status(404).json({ detail: "User not found" });
    res.json({
      id: user.id,
      username: user.username,
      full_name: user.fullName,
      email: user.email,
      role: user.role,
      role_label: ROLE_LABELS[user.role]?.label || "",
      permissions: Array.from(PERMISSIONS[user.role] || []),
      last_login: user.lastLogin,
    });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

export default router;
