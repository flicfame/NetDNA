export const VPN_USERS = [
  { username: "j.harris",  dept: "Finance",   homeCountry: "GB", homeCity: "London",      tunnelIp: "172.16.100.22", risk: 87 },
  { username: "m.patel",   dept: "Finance",   homeCountry: "GB", homeCity: "London",      tunnelIp: "172.16.100.47", risk: 62 },
  { username: "r.chen",    dept: "HR",        homeCountry: "GB", homeCity: "Manchester",  tunnelIp: "172.16.100.14", risk: 44 },
  { username: "a.smith",   dept: "IT-Ops",    homeCountry: "GB", homeCity: "London",      tunnelIp: "172.16.100.5",  risk: 12 },
  { username: "l.walsh",   dept: "Dev",       homeCountry: "IE", homeCity: "Dublin",      tunnelIp: "172.16.100.88", risk: 8 },
  { username: "t.nguyen",  dept: "Finance",   homeCountry: "GB", homeCity: "Birmingham",  tunnelIp: "172.16.100.33", risk: 5 },
  { username: "c.external",dept: "Contractor",homeCountry: "US", homeCity: "New York",    tunnelIp: "172.16.100.99", risk: 31 },
];

export const COUNTRIES: Record<string, { name: string; flag: string; lat: number; lon: number; risk: string }> = {
  GB: { name: "United Kingdom", flag: "\u{1F1EC}\u{1F1E7}", lat: 51.5, lon: -0.12, risk: "low" },
  IE: { name: "Ireland",        flag: "\u{1F1EE}\u{1F1EA}", lat: 53.3, lon: -6.26, risk: "low" },
  US: { name: "United States",  flag: "\u{1F1FA}\u{1F1F8}", lat: 38.9, lon: -77.04, risk: "low" },
  FR: { name: "France",         flag: "\u{1F1EB}\u{1F1F7}", lat: 48.8, lon: 2.35,  risk: "low" },
  DE: { name: "Germany",        flag: "\u{1F1E9}\u{1F1EA}", lat: 52.5, lon: 13.4,  risk: "low" },
  IN: { name: "India",          flag: "\u{1F1EE}\u{1F1F3}", lat: 28.6, lon: 77.2,  risk: "medium" },
  CN: { name: "China",          flag: "\u{1F1E8}\u{1F1F3}", lat: 39.9, lon: 116.4, risk: "high" },
  RU: { name: "Russia",         flag: "\u{1F1F7}\u{1F1FA}", lat: 55.7, lon: 37.6,  risk: "high" },
  AE: { name: "UAE",            flag: "\u{1F1E6}\u{1F1EA}", lat: 25.2, lon: 55.3,  risk: "medium" },
  BR: { name: "Brazil",         flag: "\u{1F1E7}\u{1F1F7}", lat: -15.8, lon: -47.9, risk: "medium" },
};

export const ACCESS_POINTS_DATA = [
  { apName: "AP-FLOOR1-RECEPTION", apIp: "10.1.3.1", location: "Floor 1 \u00B7 Reception",   ssid: "CORP-WIFI",  vlan: 20, channel: 6 },
  { apName: "AP-FLOOR1-OPEN",      apIp: "10.1.3.2", location: "Floor 1 \u00B7 Open Plan",   ssid: "CORP-WIFI",  vlan: 20, channel: 11 },
  { apName: "AP-FLOOR2-BOARDROOM", apIp: "10.1.3.3", location: "Floor 2 \u00B7 Boardroom",   ssid: "CORP-WIFI",  vlan: 20, channel: 1 },
  { apName: "AP-FLOOR2-FINANCE",   apIp: "10.1.3.4", location: "Floor 2 \u00B7 Finance",     ssid: "CORP-WIFI",  vlan: 20, channel: 6 },
  { apName: "AP-FLOOR3-DEV",       apIp: "10.1.3.5", location: "Floor 3 \u00B7 Dev Area",    ssid: "CORP-WIFI",  vlan: 40, channel: 11 },
  { apName: "AP-GROUND-LOBBY",     apIp: "10.1.3.6", location: "Ground \u00B7 Lobby",        ssid: "GUEST-WIFI", vlan: 50, channel: 1 },
  { apName: "AP-CARPARK-EXT",      apIp: "10.1.3.7", location: "External \u00B7 Car Park",   ssid: "CORP-WIFI",  vlan: 20, channel: 6 },
];

export const WIRELESS_CLIENTS_DATA = [
  { mac: "A4:C3:F0:11:22:33", username: "j.harris",  device: "MacBook Pro",   os: "macOS 14",   homeAp: "AP-FLOOR2-FINANCE",  vlan: 20 },
  { mac: "B8:27:EB:44:55:66", username: "m.patel",   device: "Dell Latitude", os: "Windows 11", homeAp: "AP-FLOOR2-FINANCE",  vlan: 20 },
  { mac: "C4:85:08:77:88:99", username: "r.chen",    device: "iPhone 15",     os: "iOS 17",     homeAp: "AP-FLOOR1-OPEN",     vlan: 20 },
  { mac: "D0:50:99:AA:BB:CC", username: "a.smith",   device: "Surface Pro",   os: "Windows 11", homeAp: "AP-FLOOR1-RECEPTION",vlan: 20 },
  { mac: "E4:5F:01:DD:EE:FF", username: "l.walsh",   device: "MacBook Air",   os: "macOS 14",   homeAp: "AP-FLOOR3-DEV",      vlan: 40 },
  { mac: "F8:1A:67:10:20:30", username: "k.jones",   device: "ThinkPad X1",   os: "Windows 11", homeAp: "AP-FLOOR3-DEV",      vlan: 40 },
  { mac: "00:11:22:33:44:55", username: "guest_01",  device: "Samsung Galaxy", os: "Android 14", homeAp: "AP-GROUND-LOBBY",    vlan: 50 },
  { mac: "AA:BB:CC:DD:EE:FF", username: "unknown",   device: "Unknown Device", os: "Unknown",   homeAp: "AP-CARPARK-EXT",     vlan: 50 },
];

export const OT_DEVICES_DATA = [
  { name: "SENSOR-TEMP-01",  ip: "192.168.100.11", type: "Temperature Sensor", vendor: "Siemens",     level: 0, protocol: "Modbus/TCP",   fn: "Boiler temp monitoring" },
  { name: "SENSOR-PRES-01",  ip: "192.168.100.12", type: "Pressure Sensor",    vendor: "Endress+H",   level: 0, protocol: "Modbus/TCP",   fn: "Pipeline pressure" },
  { name: "ACTUATOR-VLV-01", ip: "192.168.100.21", type: "Flow Control Valve", vendor: "Emerson",     level: 0, protocol: "Modbus/TCP",   fn: "Water treatment valve" },
  { name: "ACTUATOR-PMP-01", ip: "192.168.100.22", type: "Pump Controller",    vendor: "ABB",         level: 0, protocol: "EtherNet/IP",  fn: "Primary pump control" },
  { name: "PLC-BOILER-01",   ip: "192.168.101.11", type: "PLC",                vendor: "Siemens",     level: 1, protocol: "Modbus/TCP",   fn: "Boiler control logic" },
  { name: "PLC-WATER-01",    ip: "192.168.101.12", type: "PLC",                vendor: "Allen-Bradley",level: 1, protocol: "EtherNet/IP", fn: "Water treatment process" },
  { name: "PLC-POWER-01",    ip: "192.168.101.13", type: "PLC",                vendor: "Schneider",   level: 1, protocol: "Modbus/TCP",   fn: "Power distribution" },
  { name: "RTU-SUBST-01",    ip: "192.168.101.21", type: "RTU",                vendor: "GE Grid",     level: 1, protocol: "DNP3",         fn: "Substation control" },
  { name: "RTU-REMOTE-01",   ip: "192.168.101.22", type: "RTU",                vendor: "SEL",         level: 1, protocol: "DNP3",         fn: "Remote site monitoring" },
  { name: "HMI-MAIN",        ip: "192.168.102.11", type: "HMI",                vendor: "Siemens",     level: 2, protocol: "Modbus/TCP",   fn: "Main process visualisation" },
  { name: "HMI-BACKUP",      ip: "192.168.102.12", type: "HMI",                vendor: "Ignition",    level: 2, protocol: "OPC-UA",       fn: "Backup operator interface" },
  { name: "ENG-WS-01",       ip: "192.168.102.21", type: "Engineering WS",     vendor: "Dell",        level: 2, protocol: "OPC-UA",       fn: "PLC programming station" },
  { name: "SCADA-SRV-01",    ip: "192.168.102.31", type: "SCADA Server",       vendor: "Honeywell",   level: 2, protocol: "OPC-DA",       fn: "Central SCADA server" },
  { name: "HISTORIAN-01",    ip: "192.168.103.11", type: "Historian",          vendor: "OSIsoft",     level: 3, protocol: "OPC-DA",       fn: "Process data historian" },
  { name: "APP-SRV-01",      ip: "192.168.103.12", type: "App Server",         vendor: "VMware",      level: 3, protocol: "HTTPS",        fn: "MES application server" },
  { name: "DMZ-FW-01",       ip: "10.10.0.1",      type: "Firewall",          vendor: "Palo Alto",   level: 4, protocol: "Syslog",       fn: "IT/OT DMZ firewall" },
];

export const OT_PROCESS_TAGS = [
  { device: "SENSOR-TEMP-01",  tag: "BOILER_TEMP",    unit: "\u00B0C",  min: 60, max: 95, normal: 78 },
  { device: "SENSOR-PRES-01",  tag: "PIPE_PRESSURE",  unit: "bar", min: 2.0, max: 6.0, normal: 4.2 },
  { device: "ACTUATOR-VLV-01", tag: "VALVE_POS",      unit: "%",   min: 0, max: 100, normal: 65 },
  { device: "ACTUATOR-PMP-01", tag: "PUMP_RPM",       unit: "rpm", min: 800, max: 3000, normal: 1800 },
  { device: "PLC-POWER-01",    tag: "GRID_FREQ",      unit: "Hz",  min: 49.5, max: 50.5, normal: 50.0 },
  { device: "PLC-POWER-01",    tag: "LOAD_KW",        unit: "kW",  min: 100, max: 500, normal: 280 },
  { device: "PLC-WATER-01",    tag: "FLOW_RATE",      unit: "L/m", min: 50, max: 200, normal: 120 },
  { device: "RTU-SUBST-01",    tag: "BUS_VOLTAGE",    unit: "kV",  min: 10.8, max: 11.2, normal: 11.0 },
];
