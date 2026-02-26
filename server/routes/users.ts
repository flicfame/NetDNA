import { Router } from "express";
import { authMiddleware, requireAdmin, PERMISSIONS, ROLE_LABELS } from "../auth";
import * as store from "../storage";

const router = Router();

router.get("/", authMiddleware, requireAdmin, async (_req, res) => {
  try {
    const allUsers = await store.getAllUsers();
    const result = allUsers.map(u => ({
      id: u.id,
      username: u.username,
      full_name: u.fullName,
      email: u.email,
      role: u.role,
      role_label: ROLE_LABELS[u.role]?.label || u.role,
      role_colour: ROLE_LABELS[u.role]?.colour || "#9E9EA2",
      is_active: u.isActive ? 1 : 0,
      last_login: u.lastLogin,
      created_at: u.createdAt,
      created_by: u.createdBy,
    }));
    res.json({ users: result });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.post("/", authMiddleware, requireAdmin, async (req, res) => {
  try {
    const { username, password, full_name, email, role } = req.body;
    if (!username || !password) return res.status(400).json({ detail: "Username and password required" });
    if (role && !PERMISSIONS[role]) return res.status(400).json({ detail: `Invalid role '${role}'` });
    const existing = await store.getUser(username);
    if (existing) return res.status(400).json({ detail: `Username '${username}' exists` });
    const user = await store.createUser({
      username, password, role: role || "viewer",
      fullName: full_name, email,
      createdBy: (req as any).user?.sub || "admin",
    });
    res.status(201).json({ success: true, user_id: user.id });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.put("/:id", authMiddleware, requireAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id as string);
    await store.updateUser(id, req.body);
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

router.delete("/:id", authMiddleware, requireAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id as string);
    const user = await store.getUserById(id);
    if (user?.username === "admin") return res.status(400).json({ detail: "Cannot delete default admin" });
    await store.deleteUser(id);
    res.json({ success: true });
  } catch (e: any) {
    res.status(500).json({ detail: e.message });
  }
});

export default router;
