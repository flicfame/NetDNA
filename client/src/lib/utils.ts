import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function formatBytes(b: number): string {
  if (!b) return "0 B";
  if (b < 1024) return b + " B";
  if (b < 1024 ** 2) return (b / 1024).toFixed(1) + " KB";
  if (b < 1024 ** 3) return (b / 1024 ** 2).toFixed(1) + " MB";
  return (b / 1024 ** 3).toFixed(2) + " GB";
}

export function riskBg(score: number): string {
  if (score >= 80) return "bg-red-50 text-red-600 dark:bg-red-950/30 dark:text-red-400";
  if (score >= 60) return "bg-orange-50 text-orange-600 dark:bg-orange-950/30 dark:text-orange-400";
  if (score >= 30) return "bg-blue-50 text-blue-700 dark:bg-blue-950/30 dark:text-blue-400";
  return "bg-green-50 text-green-700 dark:bg-green-950/30 dark:text-green-400";
}

export function severityColor(sev: string): { bg: string; text: string; dot: string } {
  switch (sev) {
    case "critical":
      return { bg: "bg-red-50 dark:bg-red-950/30", text: "text-red-600 dark:text-red-400", dot: "bg-red-500" };
    case "high":
      return { bg: "bg-orange-50 dark:bg-orange-950/30", text: "text-orange-600 dark:text-orange-400", dot: "bg-orange-500" };
    case "medium":
      return { bg: "bg-blue-50 dark:bg-blue-950/30", text: "text-blue-700 dark:text-blue-400", dot: "bg-blue-500" };
    default:
      return { bg: "bg-green-50 dark:bg-green-950/30", text: "text-green-700 dark:text-green-400", dot: "bg-green-500" };
  }
}
