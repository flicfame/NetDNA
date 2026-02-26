import { db } from "./db";
import { users } from "@shared/schema";
import { eq } from "drizzle-orm";
import { hashPassword } from "./auth";

export async function getUser(username: string) {
  const [user] = await db.select().from(users).where(eq(users.username, username));
  return user || null;
}

export async function getUserById(id: number) {
  const [user] = await db.select().from(users).where(eq(users.id, id));
  return user || null;
}

export async function getAllUsers() {
  return db.select().from(users);
}

export async function createUser(data: {
  username: string;
  password: string;
  role: string;
  fullName?: string;
  email?: string;
  createdBy?: string;
}) {
  const now = new Date().toISOString();
  const [user] = await db.insert(users).values({
    username: data.username,
    hashedPw: hashPassword(data.password),
    role: data.role,
    fullName: data.fullName || "",
    email: data.email || "",
    createdAt: now,
    createdBy: data.createdBy || "system",
    isActive: true,
  }).returning();
  return user;
}

export async function updateUser(id: number, data: Record<string, any>) {
  const updates: Record<string, any> = {};
  if (data.fullName !== undefined) updates.fullName = data.fullName;
  if (data.full_name !== undefined) updates.fullName = data.full_name;
  if (data.email !== undefined) updates.email = data.email;
  if (data.role !== undefined) updates.role = data.role;
  if (data.is_active !== undefined) updates.isActive = !!data.is_active;
  if (data.isActive !== undefined) updates.isActive = data.isActive;
  if (data.password) updates.hashedPw = hashPassword(data.password);
  if (data.lastLogin !== undefined) updates.lastLogin = data.lastLogin;

  if (Object.keys(updates).length === 0) return;
  await db.update(users).set(updates).where(eq(users.id, id));
}

export async function deleteUser(id: number) {
  await db.delete(users).where(eq(users.id, id));
}

export async function seedDefaultUsers() {
  const mode = process.env.NETDNA_MODE || "sim";
  const isLive = mode === "live" || mode === "hybrid";

  const existing = await getUser("admin");
  if (!existing) {
    const adminPw = process.env.ADMIN_PASSWORD || (isLive ? "" : "netdna2024");
    if (isLive && !adminPw) {
      console.error("FATAL: ADMIN_PASSWORD env var required in live/hybrid mode");
      process.exit(1);
    }
    await createUser({
      username: "admin",
      password: adminPw,
      role: "admin",
      fullName: "System Administrator",
      email: "admin@netdna.local",
      createdBy: "system",
    });
    console.log("Default admin user created");
  }

  if (!isLive) {
    if (!(await getUser("analyst1"))) {
      await createUser({
        username: "analyst1",
        password: "analyst123",
        role: "analyst",
        fullName: "Sarah Chen",
        email: "s.chen@netdna.local",
        createdBy: "system",
      });
    }

    if (!(await getUser("viewer1"))) {
      await createUser({
        username: "viewer1",
        password: "viewer123",
        role: "viewer",
        fullName: "James Wilson",
        email: "j.wilson@netdna.local",
        createdBy: "system",
      });
    }
  }
}
