export const VLANS_DATA: Record<number, { name: string; subnet: string; size: number }> = {
  10: { name: "IT-Ops",    subnet: "10.10.0.",  size: 12 },
  20: { name: "Finance",   subnet: "10.20.0.",  size: 47 },
  30: { name: "HR",        subnet: "10.30.0.",  size: 31 },
  40: { name: "Dev",       subnet: "10.40.0.",  size: 28 },
  50: { name: "Guest",     subnet: "10.50.0.",  size: 8 },
  60: { name: "CCTV",      subnet: "10.60.0.",  size: 24 },
  70: { name: "VPN-Pool",  subnet: "172.16.0.", size: 50 },
  80: { name: "Wireless",  subnet: "10.80.0.",  size: 100 },
  99: { name: "Quarantine",subnet: "10.99.0.",  size: 0 },
};

export const USERS_DATA = [
  { ip: "10.20.14.22", username: "j.harris",  dept: "Finance",  vlan: 20, risk: 87, posture: "Non-Compliant", type: "wired" },
  { ip: "10.20.14.47", username: "m.patel",   dept: "Finance",  vlan: 20, risk: 62, posture: "Compliant",     type: "wired" },
  { ip: "10.30.8.14",  username: "r.chen",    dept: "HR",       vlan: 30, risk: 44, posture: "Compliant",     type: "wired" },
  { ip: "10.10.3.5",   username: "a.smith",   dept: "IT-Ops",   vlan: 10, risk: 12, posture: "Compliant",     type: "wired" },
  { ip: "10.40.2.88",  username: "l.walsh",   dept: "Dev",      vlan: 40, risk: 8,  posture: "Compliant",     type: "wired" },
  { ip: "10.20.14.33", username: "t.nguyen",  dept: "Finance",  vlan: 20, risk: 5,  posture: "Compliant",     type: "wired" },
  { ip: "10.30.8.22",  username: "s.patel",   dept: "HR",       vlan: 30, risk: 3,  posture: "Compliant",     type: "wired" },
  { ip: "10.40.2.101", username: "k.jones",   dept: "Dev",      vlan: 40, risk: 6,  posture: "Compliant",     type: "wired" },
  { ip: "10.10.3.11",  username: "d.moore",   dept: "IT-Ops",   vlan: 10, risk: 9,  posture: "Compliant",     type: "wired" },
  { ip: "10.20.14.58", username: "b.wilson",  dept: "Finance",  vlan: 20, risk: 4,  posture: "Compliant",     type: "wired" },
];

export const PROTOCOLS = [
  { id: 6,  name: "TCP",  ports: [80, 443, 8080, 3389, 22, 445, 139, 636, 389, 8443] },
  { id: 17, name: "UDP",  ports: [53, 123, 161, 514, 1812, 1813, 500, 4500, 5060] },
  { id: 1,  name: "ICMP", ports: [0] },
];

export const ANOMALY_TYPES = [
  { type: "data_exfiltration",    sev: "critical", score: 92, conf: 88, technique: "T1048", tactic: "Exfiltration",     desc: "Sustained outbound data transfer to external IP exceeds 2GB \u2014 possible data exfiltration" },
  { type: "lateral_movement",     sev: "critical", score: 88, conf: 85, technique: "T1021", tactic: "Lateral Movement", desc: "Sequential SMB/RDP connections to multiple internal hosts \u2014 lateral movement detected" },
  { type: "port_scan",            sev: "high",     score: 75, conf: 92, technique: "T1046", tactic: "Discovery",        desc: "Systematic port scanning across 50+ hosts on internal subnet" },
  { type: "dns_tunnelling",       sev: "high",     score: 78, conf: 82, technique: "T1071", tactic: "C2",              desc: "High-frequency DNS requests with encoded payloads \u2014 likely DNS tunnel" },
  { type: "brute_force",          sev: "high",     score: 70, conf: 90, technique: "T1110", tactic: "Credential Access",desc: "Multiple failed authentication attempts from single source" },
  { type: "vlan_hopping",         sev: "medium",   score: 55, conf: 78, technique: "T1599", tactic: "Defense Evasion",  desc: "Traffic observed crossing VLAN boundary without authorization" },
  { type: "off_hours_access",     sev: "medium",   score: 45, conf: 72, technique: "T1078", tactic: "Persistence",      desc: "Authenticated session established outside normal business hours" },
  { type: "impossible_travel",    sev: "high",     score: 80, conf: 86, technique: "T1078", tactic: "Initial Access",   desc: "VPN login from geographically impossible location within time window" },
  { type: "rogue_ap",             sev: "critical", score: 90, conf: 94, technique: "T1557", tactic: "Collection",       desc: "Unauthorized access point detected on corporate network" },
  { type: "concurrent_sessions",  sev: "medium",   score: 50, conf: 75, technique: "T1078", tactic: "Defense Evasion",  desc: "Same credentials active from multiple locations simultaneously" },
];

export const EXPORTERS = ["10.1.1.1", "10.1.1.2", "10.1.2.1", "10.1.3.1"];

export function rand(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

export function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

export function genMac(): string {
  return "XX:XX:XX:XX:XX:XX".replace(/X/g, () => "0123456789ABCDEF"[rand(0, 15)]);
}
