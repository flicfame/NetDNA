import { db } from "../db";
import { vpnSessions, wirelessClients, accessPoints } from "@shared/schema";
import { eq, sql } from "drizzle-orm";
import {
  VPN_USERS, COUNTRIES, ACCESS_POINTS_DATA, WIRELESS_CLIENTS_DATA,
} from "./data-remote";
import { rand, pick } from "./data";

export async function seedAccessPoints() {
  const now = new Date().toISOString();
  for (const ap of ACCESS_POINTS_DATA) {
    try {
      await db.insert(accessPoints).values({
        apName: ap.apName,
        ipAddress: ap.apIp,
        location: ap.location,
        ssid: ap.ssid,
        band: "5 GHz",
        channel: ap.channel,
        isRogue: false,
        status: "Active",
        clientCount: rand(1, 8),
        lastSeen: now,
      }).onConflictDoNothing();
    } catch {}
  }
}

export async function generateInitialRemote() {
  const now = new Date();

  for (const vu of VPN_USERS) {
    const ts = new Date(now.getTime() - rand(0, 600000)).toISOString();
    try {
      await db.insert(vpnSessions).values({
        timestamp: ts,
        username: vu.username,
        vpnIp: vu.tunnelIp,
        publicIp: `${rand(1, 223)}.${rand(0, 255)}.${rand(0, 255)}.${rand(1, 254)}`,
        countryCode: vu.homeCountry,
        countryName: COUNTRIES[vu.homeCountry]?.name || vu.homeCountry,
        city: vu.homeCity,
        deviceType: pick(["MacBook Pro", "Windows 11", "MacBook Air", "Windows 10"]),
        authMethod: pick(["Certificate+MFA", "SAML+MFA", "Username+MFA"]),
        bytesIn: rand(10000, 50000000),
        bytesOut: rand(5000, 20000000),
        durationSec: rand(300, 28800),
        status: "active",
        riskFlag: null,
      });
    } catch {}
  }

  for (const wc of WIRELESS_CLIENTS_DATA) {
    const ap = ACCESS_POINTS_DATA.find(a => a.apName === wc.homeAp);
    const ts = new Date(now.getTime() - rand(0, 600000)).toISOString();
    try {
      await db.insert(wirelessClients).values({
        timestamp: ts,
        username: wc.username,
        macAddress: wc.mac,
        ipAddress: `10.80.${rand(1, 254)}.${rand(1, 254)}`,
        deviceType: wc.device,
        osType: wc.os,
        ssid: ap?.ssid || "CORP-WIFI",
        apName: wc.homeAp,
        apLocation: ap?.location || "",
        signalDbm: rand(-75, -30),
        channel: ap?.channel || 6,
        vlan: wc.vlan,
        bytesIn: rand(10000, 5000000),
        bytesOut: rand(5000, 2000000),
        status: "connected",
        riskFlag: null,
      });
    } catch {}
  }
}

export async function tickRemote(ts: string) {
  if (Math.random() < 0.4) {
    const vu = pick(VPN_USERS);
    await db.update(vpnSessions)
      .set({
        bytesIn: sql`${vpnSessions.bytesIn} + ${rand(1000, 100000)}`,
        bytesOut: sql`${vpnSessions.bytesOut} + ${rand(500, 50000)}`,
        durationSec: sql`${vpnSessions.durationSec} + 5`,
        timestamp: ts,
      })
      .where(eq(vpnSessions.username, vu.username));
  }

  if (Math.random() < 0.3) {
    const wc = pick(WIRELESS_CLIENTS_DATA);
    await db.update(wirelessClients)
      .set({
        signalDbm: rand(-75, -30),
        bytesIn: sql`${wirelessClients.bytesIn} + ${rand(1000, 50000)}`,
        bytesOut: sql`${wirelessClients.bytesOut} + ${rand(500, 25000)}`,
        timestamp: ts,
      })
      .where(eq(wirelessClients.macAddress, wc.mac));
  }

  if (Math.random() < 0.2) {
    const ap = pick(ACCESS_POINTS_DATA);
    await db.update(accessPoints)
      .set({ clientCount: rand(0, 12), lastSeen: ts })
      .where(eq(accessPoints.apName, ap.apName));
  }
}
