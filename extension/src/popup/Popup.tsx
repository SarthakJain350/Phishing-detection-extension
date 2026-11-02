import { useState, useEffect, useCallback } from "react";
import type {
  PopupUIState,
  ScanResponse,
  WebsiteScanRequest,
  Classification,
  AnalysisStatus,
  ToolStatusDetail,
  ToolStatuses,
} from "./types";
import { scanWebsite, listRecentScans, checkBackendHealth } from "./api";
import {
  isHighRiskScan,
  createWarningPageUrl,
  openShieldInterstitial,
} from "./warningIntegration";
import {
  getToolStatusLabel,
  getPartialAnalysisSummary,
} from "./statusFormatting";
import {
  formatScanTime,
  formatClassificationLabel,
  formatTargetDomain,
} from "./historyFormatting";
import {
  ShieldLinkIcon,
  DangerIcon,
  CautionIcon,
  CheckIcon,
  UnavailableIcon,
  ChevronIcon,
} from "./icons";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Resolves active browser tab URL and title; returns null if not an http/https page */
async function getActiveTabInfo(): Promise<{
  url: string;
  title: string;
} | null> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url || !tab.url.startsWith("http")) return null;
    return { url: tab.url, title: tab.title ?? "" };
  } catch {
    return null;
  }
}

/** Extracts clean displayable hostname from URL without throwing or RTL hacks */
function hostnameFromUrl(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

// ---------------------------------------------------------------------------
// Atomic Components (Quiet Security Editorial Layout)
// ---------------------------------------------------------------------------

function ProductHeader() {
  return (
    <header className="header" role="banner">
      <ShieldLinkIcon className="header__icon" />
      <span className="header__title">Phishing Attack Detector</span>
    </header>
  );
}

function SiteRow({ domain }: { domain: string }) {
  return (
    <div className="site-row">
      <span className="site-row__label" aria-hidden="true">
        Current site
      </span>
      <div className="site-row__domain-container">
        <span
          className="site-row__domain tabular-nums"
          title={domain}
          aria-label={`Current website domain: ${domain}`}
        >
          {domain}
        </span>
      </div>
    </div>
  );
}

function ClassificationBadge({
  classification,
  analysisStatus,
}: {
  classification: Classification;
  analysisStatus: AnalysisStatus;
}) {
  if (analysisStatus === "unavailable") {
    return (
      <div className="classification-badge classification-badge--unavailable">
        <UnavailableIcon style={{ color: "var(--color-muted)" }} />
        <span>Analysis unavailable</span>
      </div>
    );
  }

  if (analysisStatus === "partial" && classification === null) {
    return (
      <div className="classification-badge classification-badge--partial">
        <CautionIcon style={{ color: "var(--color-amber)" }} />
        <span>Partial analysis</span>
      </div>
    );
  }

  const configs: Record<
    string,
    { icon: JSX.Element; label: string; cls: string }
  > = {
    phishing: {
      icon: <DangerIcon style={{ color: "var(--color-red)" }} />,
      label: "Phishing risk detected",
      cls: "classification-badge--phishing",
    },
    suspicious: {
      icon: <CautionIcon style={{ color: "var(--color-amber)" }} />,
      label: "Suspicious website",
      cls: "classification-badge--suspicious",
    },
    likely_legitimate: {
      icon: <CheckIcon style={{ color: "var(--color-teal)" }} />,
      label: "No strong phishing signals found",
      cls: "classification-badge--likely_legitimate",
    },
  };

  const key = classification ?? "likely_legitimate";
  const cfg = configs[key] ?? configs["likely_legitimate"];

  return (
    <div className={`classification-badge ${cfg.cls}`}>
      {cfg.icon}
      <span>{cfg.label}</span>
    </div>
  );
}

function ScoreBadge({ score }: { score: number | null }) {
  if (score === null) return null;
  return (
    <div
      className="score-badge"
      aria-label={`Risk score: ${score} out of 100`}
    >
      <span className="score-badge__label">Risk score</span>
      <div className="score-badge__row">
        <span className="score-badge__value">{score}</span>
        <span className="score-badge__denominator">/ 100</span>
      </div>
    </div>
  );
}

function StatusChip({ status }: { status: AnalysisStatus }) {
  if (status === "complete") return null;
  const label = status === "partial" ? "Partial analysis" : "Unavailable";
  return (
    <span
      className={`status-chip status-chip--${status}`}
      role="status"
      aria-live="polite"
    >
      {label}
    </span>
  );
}

function ResultSummary({
  classification,
  analysisStatus,
  reasons,
  toolStatuses,
}: {
  classification: Classification;
  analysisStatus: AnalysisStatus;
  reasons: string[];
  toolStatuses?: ToolStatuses;
}) {
  if (analysisStatus === "unavailable") {
    return (
      <p className="result-summary">
        <strong>This is not a safe result.</strong> The scan could not be
        completed. Verify that the backend is running and try again.
      </p>
    );
  }
  if (analysisStatus === "partial") {
    return (
      <p className="result-summary">
        {getPartialAnalysisSummary(reasons, toolStatuses)}
      </p>
    );
  }
  if (classification === "phishing") {
    return (
      <p className="result-summary">
        {reasons[0] ??
          "Several strong warning signs were found. Avoid entering passwords or payment details."}
      </p>
    );
  }
  if (classification === "suspicious") {
    return (
      <p className="result-summary">
        {reasons[0] ??
          "Some warning signs were found, but the evidence is not conclusive."}
      </p>
    );
  }
  return (
    <p className="result-summary">
      {reasons[0] ??
        "The available checks found few warning signs. This does not guarantee the site is safe."}
    </p>
  );
}

function EvidencePane({ data }: { data: ScanResponse }) {
  const hasEvidence = data.evidence.length > 0;
  const extraReasons = data.reasons.slice(1);

  return (
    <div className="evidence-pane">
      {hasEvidence && (
        <>
          <h2 className="evidence-pane__heading">Observed signals</h2>
          <ul className="evidence-list" aria-label="Evidence signals list">
            {data.evidence.map((item, idx) => (
              <li key={idx} className="evidence-item">
                <span
                  className={`evidence-item__indicator evidence-item__indicator--${item.severity}`}
                  aria-label={`Severity: ${item.severity}`}
                />
                <div className="evidence-item__content">
                  <span className="evidence-item__text">{item.explanation}</span>
                  <span className="evidence-item__meta">
                    Source: {item.source} · {item.type}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        </>
      )}

      {extraReasons.length > 0 && (
        <>
          <h2 className="evidence-pane__heading">Additional findings</h2>
          <ul className="evidence-list" aria-label="Additional reasons list">
            {extraReasons.map((reason, idx) => (
              <li key={idx} className="evidence-item">
                <span className="evidence-item__indicator evidence-item__indicator--low" />
                <div className="evidence-item__content">
                  <span className="evidence-item__text">{reason}</span>
                </div>
              </li>
            ))}
          </ul>
        </>
      )}

      <div className="status-table" aria-label="Verification checks">
        <h2 className="evidence-pane__heading">Check status</h2>
        {(
          [
            ["URL heuristics", data.tool_statuses.heuristics],
            ["Reputation check", data.tool_statuses.reputation],
            ["Content analysis", data.tool_statuses.llm],
          ] as [string, ToolStatusDetail][]
        ).map(([name, detail]) => (
          <div key={name} className="status-table__row">
            <span className="status-table__name">{name}</span>
            <span
              className={`status-table__value status-table__value--${detail.status}`}
            >
              {getToolStatusLabel(detail)}
            </span>
          </div>
        ))}
      </div>

      <p className="score-explanation-note">
        Higher scores reflect more risk signals. This score is not a calibrated
        probability of phishing.
      </p>
    </div>
  );
}

function ResultCard({
  data,
  scannedUrl,
  onRescan,
}: {
  data: ScanResponse;
  scannedUrl: string;
  onRescan: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [shieldError, setShieldError] = useState<string | null>(null);

  const isHighRisk = isHighRiskScan(data);

  const handleOpenShield = useCallback(async () => {
    try {
      setShieldError(null);
      const targetUrl = scannedUrl || data.target_reference;
      const warningUrl = createWarningPageUrl({
        destUrl: targetUrl,
        riskScore: data.risk_score,
        reasons: data.reasons,
        isPartial: data.analysis_status === "partial",
      });
      const ok = await openShieldInterstitial(warningUrl);
      if (!ok) {
        setShieldError("Could not open shield interstitial tab.");
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to open warning page.";
      setShieldError(msg);
      console.error("[Popup] Shield interstitial error:", err);
    }
  }, [data, scannedUrl]);

  const cardVariant =
    data.analysis_status === "unavailable"
      ? "unavailable"
      : data.analysis_status === "partial"
        ? "partial"
        : (data.classification ?? "likely_legitimate");

  const hasExpandable =
    data.evidence.length > 0 ||
    data.reasons.length > 1 ||
    data.analysis_status !== "complete";

  return (
    <div
      className={`result-card result-card--${cardVariant}`}
      role="region"
      aria-label="Scan result"
    >
      <div className="result-card__status-bar" aria-hidden="true" />

      <div className="result-card__header">
        <div className="classification-group">
          <ClassificationBadge
            classification={data.classification}
            analysisStatus={data.analysis_status}
          />
          <StatusChip status={data.analysis_status} />
        </div>
        <ScoreBadge score={data.risk_score} />
      </div>

      {data.risk_score !== null && (
        <p className="score-disclaimer">
          Risk indicator — not a probability of phishing.
        </p>
      )}

      <ResultSummary
        classification={data.classification}
        analysisStatus={data.analysis_status}
        reasons={data.reasons}
        toolStatuses={data.tool_statuses}
      />

      {hasExpandable && (
        <button
          className="why-toggle-btn"
          onClick={() => setExpanded((e) => !e)}
          aria-expanded={expanded}
          aria-controls="evidence-details"
        >
          <ChevronIcon down={expanded} />
          <span>{expanded ? "Hide details" : "Why this result?"}</span>
        </button>
      )}

      {expanded && (
        <div id="evidence-details">
          <EvidencePane data={data} />
        </div>
      )}

      {isHighRisk && (
        <div className="shield-action-container">
          <button
            type="button"
            className="btn btn--shield"
            onClick={handleOpenShield}
            aria-label="Open Shield Interstitial to block and review this website"
          >
            <ShieldLinkIcon style={{ width: 14, height: 14, color: "#FFFFFF" }} />
            <span>Open Shield Interstitial</span>
          </button>
          {shieldError && (
            <p className="shield-error-text" role="alert">
              {shieldError}
            </p>
          )}
        </div>
      )}

      <button
        className="btn btn--secondary"
        onClick={onRescan}
        aria-label="Scan this page again"
      >
        Rescan
      </button>
    </div>
  );
}

function ErrorCard({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}) {
  const isTimeout = message.toLowerCase().includes("timed out");
  return (
    <div className="error-card" role="alert">
      <div className="error-card__status-bar" aria-hidden="true" />
      <p className="error-card__heading">
        <UnavailableIcon style={{ color: "var(--color-muted)" }} />
        <span>{isTimeout ? "Request timed out" : "Backend unavailable"}</span>
      </p>
      <p className="error-card__body">
        <strong>This is not a safe result.</strong> {message}
      </p>
      <button className="btn btn--secondary" onClick={onRetry}>
        Try again
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Surface D: Recent Scans & Settings Subviews
// ---------------------------------------------------------------------------

interface RecentScansViewProps {
  onSelectScan: (scan: ScanResponse) => void;
  onBack: () => void;
}

function RecentScansView({ onSelectScan, onBack }: RecentScansViewProps) {
  const [scans, setScans] = useState<ScanResponse[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScans = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listRecentScans(20, 0);
      setScans(data.items);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Unable to load recent scans.";
      setError(message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  return (
    <div className="subview">
      <div className="subview-header">
        <button
          type="button"
          className="subview-back-btn"
          onClick={onBack}
          aria-label="Back to website scan view"
        >
          <span aria-hidden="true">&larr;</span> Back
        </button>
        <h2 className="subview-title">Recent scans</h2>
      </div>

      <div className="subview-body">
        {loading && (
          <div
            className="loading-state"
            role="status"
            aria-live="polite"
            aria-label="Loading recent scans"
          >
            <div className="loading-indicator" aria-hidden="true" />
            <p className="loading-state__heading">Loading scan history…</p>
          </div>
        )}

        {!loading && error && (
          <div className="history-error" role="alert">
            <p className="history-error__heading">Could not load scan history</p>
            <p className="history-error__body">{error}</p>
            <button
              type="button"
              className="btn btn--secondary history-retry-btn"
              onClick={fetchScans}
            >
              Try again
            </button>
          </div>
        )}

        {!loading && !error && scans && scans.length === 0 && (
          <div className="history-empty" role="status">
            <h3 className="history-empty__heading">No recent scans</h3>
            <p className="history-empty__body">Your recent scans will appear here.</p>
          </div>
        )}

        {!loading && !error && scans && scans.length > 0 && (
          <ul className="history-list" aria-label="Recent scans list">
            {scans.map((scan) => {
              const domain = formatTargetDomain(scan.target_reference);
              const classLabel = formatClassificationLabel(scan.classification);
              const timeLabel = formatScanTime(scan.created_at);
              const scoreLabel =
                scan.risk_score !== null ? `Risk score ${scan.risk_score}/100` : "";

              return (
                <li key={scan.scan_id} className="history-list__item">
                  <button
                    type="button"
                    className="history-card"
                    onClick={() => onSelectScan(scan)}
                    aria-label={`View scan details for ${domain}, ${classLabel}, ${scoreLabel || "score unavailable"}`}
                  >
                    <div className="history-card__header">
                      <span
                        className="history-card__domain tabular-nums"
                        title={scan.target_reference}
                      >
                        {domain}
                      </span>
                      <span className="history-card__time tabular-nums">
                        {timeLabel}
                      </span>
                    </div>

                    <div className="history-card__meta">
                      <span
                        className={`history-badge history-badge--${scan.classification || "unclassified"}`}
                      >
                        {classLabel}
                      </span>

                      {scan.risk_score !== null && (
                        <span className="history-card__score tabular-nums">
                          Score: {scan.risk_score}/100
                        </span>
                      )}

                      {scan.analysis_status !== "complete" && (
                        <span
                          className={`history-card__status-chip history-card__status-chip--${scan.analysis_status}`}
                        >
                          {scan.analysis_status === "partial" ? "Partial" : "Unavailable"}
                        </span>
                      )}
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}

interface SettingsViewProps {
  onBack: () => void;
}

function SettingsView({ onBack }: SettingsViewProps) {
  const [backendOk, setBackendOk] = useState<boolean | null>(null);

  useEffect(() => {
    checkBackendHealth().then((ok) => setBackendOk(ok));
  }, []);

  return (
    <div className="subview">
      <div className="subview-header">
        <button
          type="button"
          className="subview-back-btn"
          onClick={onBack}
          aria-label="Back to website scan view"
        >
          <span aria-hidden="true">&larr;</span> Back
        </button>
        <h2 className="subview-title">Settings</h2>
      </div>

      <div className="subview-body settings-body">
        <div className="settings-section">
          <h3 className="settings-section__title">Backend service</h3>
          <div className="settings-row">
            <span className="settings-label">API status</span>
            <span
              className={`settings-status-badge ${
                backendOk === true
                  ? "settings-status-badge--connected"
                  : backendOk === false
                  ? "settings-status-badge--unavailable"
                  : ""
              }`}
            >
              {backendOk === null
                ? "Checking…"
                : backendOk
                ? "Connected"
                : "Unavailable"}
            </span>
          </div>
          <p className="settings-note">
            Target server: <code>http://127.0.0.1:8000</code>
          </p>
        </div>

        <div className="settings-section">
          <h3 className="settings-section__title">Website scanning</h3>
          <div className="settings-row">
            <span className="settings-label">Mode</span>
            <span className="settings-badge">Manual on-demand</span>
          </div>
          <p className="settings-note">
            Automatic background navigation scanning is disabled in this phase.
          </p>
        </div>

        <div className="settings-section">
          <h3 className="settings-section__title">Privacy notice</h3>
          <p className="settings-note">
            Scan history stores result metadata, not full page or email content by default.
          </p>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Root Popup Component
// ---------------------------------------------------------------------------

export type ActiveView = "scan" | "recent_scans" | "settings";

export function Popup() {
  const [domain, setDomain] = useState<string>("");
  const [currentUrl, setCurrentUrl] = useState<string>("");
  const [pageTitle, setPageTitle] = useState<string>("");
  const [uiState, setUiState] = useState<PopupUIState>({ kind: "idle" });
  const [activeView, setActiveView] = useState<ActiveView>("scan");

  useEffect(() => {
    getActiveTabInfo().then((info) => {
      if (info) {
        setCurrentUrl(info.url);
        setDomain(hostnameFromUrl(info.url));
        setPageTitle(info.title);
      } else {
        setDomain("(not a web page)");
      }
    });
  }, []);

  const handleScan = useCallback(async () => {
    if (!currentUrl || !currentUrl.startsWith("http")) {
      setUiState({
        kind: "connection_error",
        message:
          "This page cannot be scanned. Navigate to an http or https website first.",
      });
      return;
    }

    const scannedUrl = currentUrl;
    setUiState({ kind: "scanning" });

    try {
      const payload: WebsiteScanRequest = {
        url: scannedUrl,
        source: "manual_website",
        ...(pageTitle ? { page_title: pageTitle } : {}),
      };
      const result = await scanWebsite(payload);
      setUiState({ kind: "result", data: result, scannedUrl });
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "An unknown error occurred.";
      setUiState({ kind: "connection_error", message });
    }
  }, [currentUrl, pageTitle]);

  const handleReset = useCallback(() => {
    setUiState({ kind: "idle" });
  }, []);

  const handleSelectScan = useCallback((scan: ScanResponse) => {
    setUiState({
      kind: "result",
      data: scan,
      scannedUrl: scan.target_reference,
    });
    setActiveView("scan");
  }, []);

  const canScan = Boolean(currentUrl) && currentUrl.startsWith("http");

  return (
    <div className="popup-layout">
      <ProductHeader />

      {activeView === "scan" && domain && domain !== "(not a web page)" && (
        <SiteRow domain={domain} />
      )}

      {activeView === "scan" && (
        <main className="content">
          {uiState.kind === "idle" && (
            <div className="empty-state">
              <h1 className="empty-state__heading">Check this website</h1>
              <p className="empty-state__body">
                Scan the current page for signals commonly associated with
                phishing.
              </p>
              <button
                className="btn btn--primary"
                onClick={handleScan}
                disabled={!canScan}
                aria-label="Scan current site for phishing signals"
              >
                Scan current site
              </button>
            </div>
          )}

          {uiState.kind === "scanning" && (
            <div
              className="loading-state"
              role="status"
              aria-live="polite"
              aria-label="Scan in progress"
            >
              <div className="loading-indicator" aria-hidden="true" />
              <p className="loading-state__heading">Checking this website…</p>
              <p className="loading-state__body">
                Reviewing the page and available reputation signals.
              </p>
            </div>
          )}

          {uiState.kind === "result" && (
            <ResultCard
              data={uiState.data}
              scannedUrl={uiState.scannedUrl ?? currentUrl}
              onRescan={handleReset}
            />
          )}

          {uiState.kind === "connection_error" && (
            <ErrorCard
              message={uiState.message}
              onRetry={handleReset}
            />
          )}
        </main>
      )}

      {activeView === "recent_scans" && (
        <main className="content content--subview">
          <RecentScansView
            onSelectScan={handleSelectScan}
            onBack={() => setActiveView("scan")}
          />
        </main>
      )}

      {activeView === "settings" && (
        <main className="content content--subview">
          <SettingsView
            onBack={() => setActiveView("scan")}
          />
        </main>
      )}

      <footer className="footer" role="contentinfo">
        <div className="footer__links">
          <button
            type="button"
            className={`footer__action ${activeView === "recent_scans" ? "footer__action--active" : ""}`}
            onClick={() => setActiveView(activeView === "recent_scans" ? "scan" : "recent_scans")}
            aria-pressed={activeView === "recent_scans"}
          >
            Recent scans
          </button>
          <button
            type="button"
            className={`footer__action ${activeView === "settings" ? "footer__action--active" : ""}`}
            onClick={() => setActiveView(activeView === "settings" ? "scan" : "settings")}
            aria-pressed={activeView === "settings"}
          >
            Settings
          </button>
        </div>
        <span className="footer__version">v1.0 (Phase 1)</span>
      </footer>
    </div>
  );
}
