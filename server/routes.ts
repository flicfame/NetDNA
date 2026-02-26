import type { Express } from "express";
import { type Server } from "http";
import path from "path";
import express from "express";
import authRoutes from "./routes/auth";
import userRoutes from "./routes/users";
import networkRoutes from "./routes/network";
import remoteRoutes from "./routes/remote";
import otRoutes from "./routes/ot";
import analyticsRoutes from "./routes/analytics";
import intelligenceRoutes from "./routes/intelligence";
import episodeRoutes from "./routes/episodes";
import downstreamRoutes from "./routes/downstream";
import policyRoutes from "./routes/policies";
import iseRoutes from "./routes/ise";
import shimRoutes from "./routes/shims";
import enrollRoutes from "./routes/enroll";

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {

  const publicDir = path.join(process.cwd(), "public");
  app.use("/assets", express.static(path.join(publicDir, "assets")));

  app.get("/", (_req, res) => res.sendFile(path.join(publicDir, "pages", "login.html")));
  app.get("/login", (_req, res) => res.sendFile(path.join(publicDir, "pages", "login.html")));
  app.get("/dashboard", (_req, res) => res.sendFile(path.join(publicDir, "pages", "dashboard.html")));
  app.get("/remote", (_req, res) => res.sendFile(path.join(publicDir, "pages", "remote.html")));
  app.get("/ot", (_req, res) => res.sendFile(path.join(publicDir, "pages", "ot.html")));
  app.get("/heatmap", (_req, res) => res.sendFile(path.join(publicDir, "pages", "heatmap.html")));
  app.get("/prediction", (_req, res) => res.sendFile(path.join(publicDir, "pages", "prediction.html")));
  app.get("/quarantine", (_req, res) => res.sendFile(path.join(publicDir, "pages", "quarantine.html")));
  app.get("/topology", (_req, res) => res.sendFile(path.join(publicDir, "pages", "topology.html")));
  app.get("/users", (_req, res) => res.sendFile(path.join(publicDir, "pages", "users.html")));
  app.get("/api-docs", (_req, res) => res.sendFile(path.join(publicDir, "pages", "api-docs.html")));
  app.get("/testlab", (_req, res) => res.sendFile(path.join(publicDir, "pages", "testlab.html")));
  app.get("/mynetwork", (_req, res) => res.sendFile(path.join(publicDir, "pages", "mynetwork.html")));
  app.get("/shim-devices", (_req, res) => res.sendFile(path.join(publicDir, "pages", "shim-devices.html")));
  app.get("/shim-downstream", (_req, res) => res.sendFile(path.join(publicDir, "pages", "shim-downstream.html")));
  app.get("/shim-ise", (_req, res) => res.sendFile(path.join(publicDir, "pages", "shim-ise.html")));
  app.get("/shim-policies", (_req, res) => res.sendFile(path.join(publicDir, "pages", "shim-policies.html")));

  app.use("/api/v1/auth", authRoutes);
  app.use("/api/v1/users", userRoutes);
  app.use("/api/v1", networkRoutes);
  app.use("/api/v1", analyticsRoutes);
  app.use("/api/v1/remote", remoteRoutes);
  app.use("/api/v1/ot", otRoutes);
  app.use("/api/v1/intelligence", intelligenceRoutes);
  app.use("/api/v1/episodes", episodeRoutes);
  app.use("/api/v1", downstreamRoutes);
  app.use("/api/v1", policyRoutes);
  app.use("/api/v1", iseRoutes);
  app.use("/api/v1/shims", shimRoutes);
  app.use("/api/v1", enrollRoutes);

  return httpServer;
}
