import type { Classification } from "./types";

/**
 * Formats an ISO-8601 timestamp into a clean relative string or readable date
 * without cluttering the popup UI.
 */
export function formatScanTime(isoString: string, now: Date = new Date()): string {
  try {
    const date = new Date(isoString);
    const timeMs = date.getTime();
    if (isNaN(timeMs)) {
      return isoString;
    }

    const diffMs = now.getTime() - timeMs;
    if (diffMs < 0) {
      // Future timestamp or minor client-server clock skew
      return date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
    }

    const diffSec = Math.floor(diffMs / 1000);
    if (diffSec < 60) {
      return "Just now";
    }

    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) {
      return `${diffMin}m ago`;
    }

    const diffHours = Math.floor(diffMin / 60);
    if (diffHours < 24) {
      return `${diffHours}h ago`;
    }

    const diffDays = Math.floor(diffHours / 24);
    if (diffDays === 1) {
      return "Yesterday";
    }
    if (diffDays < 7) {
      return `${diffDays}d ago`;
    }

    return date.toLocaleDateString([], { month: "short", day: "numeric" });
  } catch {
    return isoString;
  }
}

/**
 * Returns a human-friendly label for classification badges in history lists.
 */
export function formatClassificationLabel(classification: Classification): string {
  switch (classification) {
    case "phishing":
      return "Phishing";
    case "suspicious":
      return "Suspicious";
    case "likely_legitimate":
      return "Legitimate";
    default:
      return "Unclassified";
  }
}

/**
 * Safely extracts hostname or fallback display text from a target reference string.
 */
export function formatTargetDomain(targetReference: string): string {
  if (!targetReference) return "(unknown)";
  try {
    if (targetReference.startsWith("http://") || targetReference.startsWith("https://")) {
      return new URL(targetReference).hostname;
    }
    // If it's already a domain/hostname
    return targetReference;
  } catch {
    return targetReference;
  }
}
