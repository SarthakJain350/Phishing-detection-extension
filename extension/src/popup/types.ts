/** API base URL — local development backend (Phase 1) */
export const API_BASE_URL = "http://127.0.0.1:8000";

/** Allowed source values for website scans (matches backend Literal enum) */
export type ScanSource = "manual_website" | "auto_website";

/** Classification values returned by the backend */
export type Classification =
  | "phishing"
  | "suspicious"
  | "likely_legitimate"
  | null;

/** Analysis status values */
export type AnalysisStatus = "complete" | "partial" | "unavailable";

/** Tool status values */
export type ToolStatusValue =
  | "complete"
  | "partial"
  | "unavailable"
  | "timeout"
  | "error";

export interface ToolStatusDetail {
  status: ToolStatusValue;
  reason_code?: string | null;
}

export interface ToolStatuses {
  heuristics: ToolStatusDetail;
  reputation: ToolStatusDetail;
  llm: ToolStatusDetail;
}

export interface EvidenceItem {
  type: string;
  source: string;
  severity: "low" | "medium" | "high";
  explanation: string;
}

/** Full scan response — matches ScanResponse Pydantic schema exactly */
export interface ScanResponse {
  scan_id: string;
  target_type: "website" | "email";
  target_reference: string;
  classification: Classification;
  risk_score: number | null;
  reasons: string[];
  evidence: EvidenceItem[];
  tool_statuses: ToolStatuses;
  analysis_status: AnalysisStatus;
  source: string;
  created_at: string;
}

/** Website scan request — matches WebsiteScanRequest Pydantic schema exactly */
export interface WebsiteScanRequest {
  url: string;
  page_title?: string;
  source: ScanSource;
}

/** Internal popup UI states — never expose unavailable/error as safe */
export type PopupUIState =
  | { kind: "idle" }
  | { kind: "scanning" }
  | { kind: "result"; data: ScanResponse }
  | { kind: "connection_error"; message: string };
