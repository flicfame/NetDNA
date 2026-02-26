import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import type { Request, Response, NextFunction } from "express";

const SECRET = process.env.SESSION_SECRET || "netdna-dev-secret";
const TOKEN_HOURS = 8;

export const PERMISSIONS: Record<string, Set<string>> = {
  admin: new Set([
    "view_dashboard","view_alerts","view_entities","view_flows",
    "view_topology","update_alerts","manage_users",
    "quarantine","view_api_docs","view_settings",
  ]),
  analyst: new Set([
    "view_dashboard","view_alerts","view_entities","view_flows",
    "view_topology","update_alerts","view_api_docs",
  ]),
  viewer: new Set([
    "view_dashboard","view_alerts","view_entities",
    "view_flows","view_topology",
  ]),
};

export const ROLE_LABELS: Record<string, { label: string; colour: string }> = {
  admin:   { label: "Administrator",     colour: "#E2231A" },
  analyst: { label: "Security Analyst",  colour: "#F7810A" },
  viewer:  { label: "Read-Only Viewer",  colour: "#049FD9" },
};

export function hashPassword(plain: string): string {
  return bcrypt.hashSync(plain, 10);
}

export function verifyPassword(plain: string, hashed: string): boolean {
  return bcrypt.compareSync(plain, hashed);
}

export function createToken(user: { id: number; username: string; role: string }): string {
  return jwt.sign(
    { sub: user.username, role: user.role, uid: user.id },
    SECRET,
    { expiresIn: `${TOKEN_HOURS}h` }
  );
}

export function decodeToken(token: string): { sub: string; role: string; uid: number } {
  return jwt.verify(token, SECRET) as any;
}

export interface AuthRequest extends Request {
  user?: { id: number; username: string; role: string; [k: string]: any };
}

export function authMiddleware(req: AuthRequest, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ detail: "Authentication required" });
  }
  try {
    const payload = decodeToken(header.slice(7));
    (req as any).user = payload;
    next();
  } catch {
    return res.status(401).json({ detail: "Invalid or expired token" });
  }
}

export function requirePermission(permission: string) {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    const role = (req as any).user?.role || "viewer";
    if (!PERMISSIONS[role]?.has(permission)) {
      return res.status(403).json({ detail: `Role '${role}' lacks '${permission}' permission` });
    }
    next();
  };
}

export function requireAdmin(req: AuthRequest, res: Response, next: NextFunction) {
  if ((req as any).user?.role !== "admin") {
    return res.status(403).json({ detail: "Administrator access required" });
  }
  next();
}
