import { pgTable, text, integer, serial, boolean, real } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  email: text("email"),
  fullName: text("full_name"),
  hashedPw: text("hashed_pw").notNull(),
  role: text("role").notNull().default("viewer"),
  isActive: boolean("is_active").notNull().default(true),
  lastLogin: text("last_login"),
  createdAt: text("created_at"),
  createdBy: text("created_by"),
});

export const flows = pgTable("flows", {
  id: serial("id").primaryKey(),
  timestamp: text("timestamp"),
  srcIp: text("src_ip"),
  dstIp: text("dst_ip"),
  srcPort: integer("src_port"),
  dstPort: integer("dst_port"),
  protocol: integer("protocol"),
  protocolName: text("protocol_name"),
  bytesCount: integer("bytes_count").default(0),
  packets: integer("packets").default(0),
  tcpFlags: text("tcp_flags"),
  srcVlan: integer("src_vlan").default(0),
  dstVlan: integer("dst_vlan").default(0),
  exporterIp: text("exporter_ip"),
  flowVersion: integer("flow_version"),
  srcUsername: text("src_username"),
  srcDepartment: text("src_department"),
  connectionType: text("connection_type").default("wired"),
});

export const entities = pgTable("entities", {
  id: serial("id").primaryKey(),
  ipAddress: text("ip_address").notNull().unique(),
  macAddress: text("mac_address"),
  username: text("username"),
  department: text("department"),
  deviceType: text("device_type"),
  osType: text("os_type"),
  vlanId: integer("vlan_id"),
  sgtTag: text("sgt_tag"),
  authPolicy: text("auth_policy"),
  postureStatus: text("posture_status").default("unknown"),
  lastSeen: text("last_seen"),
  firstSeen: text("first_seen"),
  riskScore: integer("risk_score").default(0),
  riskTrend: text("risk_trend").default("stable"),
  isQuarantined: boolean("is_quarantined").default(false),
  connectionType: text("connection_type").default("wired"),
  countryCode: text("country_code"),
  city: text("city"),
  ssid: text("ssid"),
  apName: text("ap_name"),
  updatedAt: text("updated_at"),
});

export const anomalies = pgTable("anomalies", {
  id: serial("id").primaryKey(),
  detectedAt: text("detected_at"),
  entityIp: text("entity_ip"),
  username: text("username"),
  deviceName: text("device_name"),
  anomalyType: text("anomaly_type"),
  severity: text("severity"),
  riskScore: integer("risk_score"),
  confidence: integer("confidence"),
  description: text("description"),
  evidence: text("evidence"),
  mitreTechnique: text("mitre_technique"),
  mitreTactic: text("mitre_tactic"),
  status: text("status").default("open"),
  assignedTo: text("assigned_to"),
  resolvedAt: text("resolved_at"),
  srcVlan: integer("src_vlan").default(0),
  dstVlan: integer("dst_vlan").default(0),
  exporterIp: text("exporter_ip"),
});

export const vlans = pgTable("vlans", {
  vlanId: integer("vlan_id").primaryKey(),
  name: text("name"),
  subnet: text("subnet"),
  description: text("description"),
  riskLevel: text("risk_level").default("normal"),
  deviceCount: integer("device_count").default(0),
});

export const vpnSessions = pgTable("vpn_sessions", {
  id: serial("id").primaryKey(),
  timestamp: text("timestamp"),
  username: text("username"),
  vpnIp: text("vpn_ip"),
  publicIp: text("public_ip"),
  countryCode: text("country_code"),
  countryName: text("country_name"),
  city: text("city"),
  deviceType: text("device_type"),
  authMethod: text("auth_method"),
  bytesIn: integer("bytes_in").default(0),
  bytesOut: integer("bytes_out").default(0),
  durationSec: integer("duration_sec").default(0),
  status: text("status").default("active"),
  riskFlag: text("risk_flag"),
});

export const wirelessClients = pgTable("wireless_clients", {
  id: serial("id").primaryKey(),
  timestamp: text("timestamp"),
  username: text("username"),
  macAddress: text("mac_address"),
  ipAddress: text("ip_address"),
  deviceType: text("device_type"),
  osType: text("os_type"),
  ssid: text("ssid"),
  apName: text("ap_name"),
  apLocation: text("ap_location"),
  signalDbm: integer("signal_dbm"),
  channel: integer("channel"),
  vlan: integer("vlan"),
  bytesIn: integer("bytes_in").default(0),
  bytesOut: integer("bytes_out").default(0),
  status: text("status").default("connected"),
  riskFlag: text("risk_flag"),
});

export const accessPoints = pgTable("access_points", {
  id: serial("id").primaryKey(),
  apName: text("ap_name").unique(),
  ipAddress: text("ip_address"),
  location: text("location"),
  ssid: text("ssid"),
  band: text("band"),
  channel: integer("channel"),
  isRogue: boolean("is_rogue").default(false),
  status: text("status").default("Active"),
  clientCount: integer("client_count").default(0),
  lastSeen: text("last_seen"),
});

export const otDevices = pgTable("ot_devices", {
  id: serial("id").primaryKey(),
  name: text("name").unique(),
  ipAddress: text("ip_address"),
  deviceType: text("device_type"),
  vendor: text("vendor"),
  purdueLevel: integer("purdue_level"),
  protocol: text("protocol"),
  functionDesc: text("function_desc"),
  firmwareVer: text("firmware_ver"),
  status: text("status").default("online"),
  riskScore: integer("risk_score").default(0),
  anomalyFlag: text("anomaly_flag"),
  lastSeen: text("last_seen"),
});

export const otEvents = pgTable("ot_events", {
  id: serial("id").primaryKey(),
  timestamp: text("timestamp"),
  deviceName: text("device_name"),
  deviceIp: text("device_ip"),
  eventType: text("event_type"),
  severity: text("severity"),
  description: text("description"),
  mitreTechnique: text("mitre_technique"),
  mitreTactic: text("mitre_tactic"),
  ciscoRisk: text("cisco_risk"),
  srcIp: text("src_ip"),
  dstIp: text("dst_ip"),
  protocol: text("protocol"),
  status: text("status").default("open"),
});

export const otProcessValues = pgTable("ot_process_values", {
  id: serial("id").primaryKey(),
  timestamp: text("timestamp"),
  deviceName: text("device_name"),
  tagName: text("tag_name"),
  value: real("value"),
  unit: text("unit"),
  normalMin: real("normal_min"),
  normalMax: real("normal_max"),
  isAlarm: boolean("is_alarm").default(false),
});

export const otTraffic = pgTable("ot_traffic", {
  id: serial("id").primaryKey(),
  timestamp: text("timestamp"),
  srcIp: text("src_ip"),
  dstIp: text("dst_ip"),
  srcDevice: text("src_device"),
  dstDevice: text("dst_device"),
  protocol: text("protocol"),
  bytesCount: integer("bytes_count").default(0),
  isAnomalous: boolean("is_anomalous").default(false),
  anomalyReason: text("anomaly_reason"),
});

export const entityEdges = pgTable("entity_edges", {
  id: serial("id").primaryKey(),
  srcIp: text("src_ip").notNull(),
  dstIp: text("dst_ip").notNull(),
  edgeType: text("edge_type").notNull(),
  weight: real("weight").default(1),
  firstSeen: text("first_seen"),
  lastSeen: text("last_seen"),
  evidenceRef: text("evidence_ref"),
});

export const episodes = pgTable("episodes", {
  id: serial("id").primaryKey(),
  label: text("label").notNull(),
  intent: text("intent"),
  confidence: real("confidence").default(0),
  startTs: text("start_ts"),
  endTs: text("end_ts"),
  primaryEntityIp: text("primary_entity_ip"),
  status: text("status").notNull().default("active"),
});

export const episodeAnomalies = pgTable("episode_anomalies", {
  id: serial("id").primaryKey(),
  episodeId: integer("episode_id").notNull(),
  anomalyId: integer("anomaly_id").notNull(),
});

export const shims = pgTable("shims", {
  shimId: text("shim_id").primaryKey(),
  name: text("name"),
  siteId: text("site_id"),
  zone: text("zone"),
  status: text("status").notNull().default("pending"),
  mode: text("mode").notNull().default("monitor"),
  firmwareVersion: text("firmware_version"),
  ifaceDevice: text("iface_device"),
  ifaceSwitch: text("iface_switch"),
  mgmtIp: text("mgmt_ip"),
  certFingerprint: text("cert_fingerprint"),
  registeredAt: text("registered_at"),
  lastHeartbeat: text("last_heartbeat"),
  approvedAt: text("approved_at"),
  approvedBy: text("approved_by"),
  notes: text("notes"),
});

export const downstreamDevices = pgTable("downstream_devices", {
  id: serial("id").primaryKey(),
  shimId: text("shim_id").notNull(),
  mac: text("mac").notNull(),
  ip: text("ip"),
  deviceType: text("device_type"),
  deviceName: text("device_name"),
  templateName: text("template_name").default("unknown"),
  iseGroup: text("ise_group"),
  iseEndpointId: text("ise_endpoint_id"),
  firstSeen: text("first_seen"),
  lastSeen: text("last_seen"),
  notes: text("notes"),
});

export const policyTemplates = pgTable("policy_templates", {
  name: text("name").primaryKey(),
  displayName: text("display_name").notNull(),
  description: text("description"),
  rulesJson: text("rules_json").notNull(),
  version: integer("version").default(1),
  createdAt: text("created_at"),
  updatedAt: text("updated_at"),
  builtIn: boolean("built_in").default(false),
});

export const shimPolicies = pgTable("shim_policies", {
  shimId: text("shim_id").primaryKey(),
  templateName: text("template_name").notNull(),
  mode: text("mode").notNull().default("monitor"),
  containSafeJson: text("contain_safe_json"),
  assignedAt: text("assigned_at"),
  assignedBy: text("assigned_by").default("system"),
  policyHash: text("policy_hash"),
});

export const shimHealth = pgTable("shim_health", {
  id: serial("id").primaryKey(),
  shimId: text("shim_id").notNull(),
  ts: text("ts").notNull(),
  cpuPct: real("cpu_pct"),
  memUsedMb: integer("mem_used_mb"),
  bridgeLatencyUs: integer("bridge_latency_us"),
  bridgeDrops: integer("bridge_drops"),
  linkDeviceUp: boolean("link_device_up"),
  linkSwitchUp: boolean("link_switch_up"),
  iseConnected: boolean("ise_connected"),
  coreConnected: boolean("core_connected"),
  uptimeSec: integer("uptime_sec"),
  policyVersion: text("policy_version"),
});

export const shimViolations = pgTable("shim_violations", {
  id: serial("id").primaryKey(),
  shimId: text("shim_id").notNull(),
  ts: text("ts").notNull(),
  ruleName: text("rule_name").notNull(),
  srcIp: text("src_ip"),
  dstIp: text("dst_ip"),
  srcPort: integer("src_port"),
  dstPort: integer("dst_port"),
  proto: text("proto"),
  bytes: integer("bytes"),
  action: text("action").notNull(),
  mode: text("mode").notNull(),
  severity: text("severity"),
  mitreTechnique: text("mitre_technique"),
});

export const shimFlows = pgTable("shim_flows", {
  id: serial("id").primaryKey(),
  shimId: text("shim_id").notNull(),
  ts: text("ts").notNull(),
  srcIp: text("src_ip"),
  dstIp: text("dst_ip"),
  srcPort: integer("src_port"),
  dstPort: integer("dst_port"),
  proto: text("proto"),
  bytes: integer("bytes"),
  packets: integer("packets"),
  action: text("action"),
});

export const iseSyncLog = pgTable("ise_sync_log", {
  id: serial("id").primaryKey(),
  ts: text("ts").notNull(),
  action: text("action").notNull(),
  mac: text("mac"),
  iseEndpointId: text("ise_endpoint_id"),
  iseGroup: text("ise_group"),
  success: boolean("success").notNull(),
  detail: text("detail"),
});

export const shimAuditLog = pgTable("shim_audit_log", {
  id: serial("id").primaryKey(),
  ts: text("ts").notNull(),
  eventType: text("event_type").notNull(),
  actor: text("actor").default("system"),
  shimId: text("shim_id"),
  detail: text("detail"),
});

export const newTalkers = pgTable("new_talkers", {
  id: serial("id").primaryKey(),
  shimId: text("shim_id").notNull(),
  ts: text("ts").notNull(),
  srcIp: text("src_ip"),
  dstIp: text("dst_ip").notNull(),
  dstPort: integer("dst_port"),
  proto: text("proto"),
});

export const enrollmentTokens = pgTable("enrollment_tokens", {
  tokenHash: text("token_hash").primaryKey(),
  shimId: text("shim_id").notNull(),
  createdAt: text("created_at"),
  expiresAt: text("expires_at").notNull(),
  used: boolean("used").default(false),
  usedAt: text("used_at"),
  clientIp: text("client_ip"),
  certFingerprint: text("cert_fingerprint"),
  createdBy: text("created_by").default("admin"),
});

export const insertEntityEdgeSchema = createInsertSchema(entityEdges).omit({ id: true });
export const insertEpisodeSchema = createInsertSchema(episodes).omit({ id: true });
export const insertEpisodeAnomalySchema = createInsertSchema(episodeAnomalies).omit({ id: true });
export const insertShimSchema = createInsertSchema(shims);
export const insertDownstreamDeviceSchema = createInsertSchema(downstreamDevices).omit({ id: true });
export const insertPolicyTemplateSchema = createInsertSchema(policyTemplates);
export const insertShimPolicySchema = createInsertSchema(shimPolicies);
export const insertShimHealthSchema = createInsertSchema(shimHealth).omit({ id: true });
export const insertShimViolationSchema = createInsertSchema(shimViolations).omit({ id: true });
export const insertShimFlowSchema = createInsertSchema(shimFlows).omit({ id: true });
export const insertIseSyncLogSchema = createInsertSchema(iseSyncLog).omit({ id: true });
export const insertShimAuditLogSchema = createInsertSchema(shimAuditLog).omit({ id: true });
export const insertNewTalkerSchema = createInsertSchema(newTalkers).omit({ id: true });
export const insertEnrollmentTokenSchema = createInsertSchema(enrollmentTokens);

export const loginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(1),
});

export type User = typeof users.$inferSelect;
export type Flow = typeof flows.$inferSelect;
export type Entity = typeof entities.$inferSelect;
export type Anomaly = typeof anomalies.$inferSelect;
export type Vlan = typeof vlans.$inferSelect;
export type VpnSession = typeof vpnSessions.$inferSelect;
export type WirelessClient = typeof wirelessClients.$inferSelect;
export type AccessPoint = typeof accessPoints.$inferSelect;
export type OtDevice = typeof otDevices.$inferSelect;
export type OtEvent = typeof otEvents.$inferSelect;
export type OtProcessValue = typeof otProcessValues.$inferSelect;
export type EntityEdge = typeof entityEdges.$inferSelect;
export type InsertEntityEdge = z.infer<typeof insertEntityEdgeSchema>;
export type Episode = typeof episodes.$inferSelect;
export type InsertEpisode = z.infer<typeof insertEpisodeSchema>;
export type EpisodeAnomaly = typeof episodeAnomalies.$inferSelect;
export type Shim = typeof shims.$inferSelect;
export type InsertShim = z.infer<typeof insertShimSchema>;
export type DownstreamDevice = typeof downstreamDevices.$inferSelect;
export type InsertDownstreamDevice = z.infer<typeof insertDownstreamDeviceSchema>;
export type PolicyTemplate = typeof policyTemplates.$inferSelect;
export type InsertPolicyTemplate = z.infer<typeof insertPolicyTemplateSchema>;
export type ShimPolicy = typeof shimPolicies.$inferSelect;
export type InsertShimPolicy = z.infer<typeof insertShimPolicySchema>;
export type ShimHealthRecord = typeof shimHealth.$inferSelect;
export type ShimViolation = typeof shimViolations.$inferSelect;
export type ShimFlow = typeof shimFlows.$inferSelect;
export type IseSyncLogEntry = typeof iseSyncLog.$inferSelect;
export type ShimAuditLogEntry = typeof shimAuditLog.$inferSelect;
export type NewTalker = typeof newTalkers.$inferSelect;
export type InsertNewTalker = z.infer<typeof insertNewTalkerSchema>;
export type EnrollmentToken = typeof enrollmentTokens.$inferSelect;
export type InsertEnrollmentToken = z.infer<typeof insertEnrollmentTokenSchema>;
