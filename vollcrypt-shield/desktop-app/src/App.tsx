import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { documentDir, join } from "@tauri-apps/api/path";
import { message, open, save } from "@tauri-apps/plugin-dialog";
import { diffLines } from "diff";
import {
  Activity, CheckCircle2, ChevronRight, CircleDot, FileCode2, FolderOpen, FolderPlus,
  GitBranch, KeyRound, LockKeyhole, Radio, RefreshCw, ScrollText, Search,
  PackageCheck, Server, Settings, ShieldCheck, TriangleAlert, Unplug, X
} from "lucide-react";

type View = "overview" | "compare" | "events" | "merkle";

interface DifferenceReport {
  path: string;
  absolutePath: string;
  kind: "added" | "removed" | "modified";
}

interface FileComparisonReport {
  relativePath: string;
  absolutePath: string;
  kind: "added" | "removed" | "modified";
  baselineDigest: string | null;
  currentDigest: string | null;
  baselineSize: number | null;
  currentSize: number | null;
  baselineText: string | null;
  currentText: string | null;
  contentStatus: string;
  detail: string;
}

interface ViewerSettings {
  autoRefresh: boolean;
  refreshIntervalSeconds: number;
  diffContextLines: number;
  wrapDiffLines: boolean;
  eventLimit: number;
}

const defaultSettings: ViewerSettings = {
  autoRefresh: true,
  refreshIntervalSeconds: 15,
  diffContextLines: 5,
  wrapDiffLines: false,
  eventLimit: 100
};

function loadSettings(): ViewerSettings {
  try {
    const stored = JSON.parse(localStorage.getItem("shield-viewer-settings") ?? "{}");
    return {
      autoRefresh: typeof stored.autoRefresh === "boolean"
        ? stored.autoRefresh
        : defaultSettings.autoRefresh,
      refreshIntervalSeconds: [5, 15, 30, 60, 300].includes(stored.refreshIntervalSeconds)
        ? stored.refreshIntervalSeconds
        : defaultSettings.refreshIntervalSeconds,
      diffContextLines: [3, 5, 10, 25].includes(stored.diffContextLines)
        ? stored.diffContextLines
        : defaultSettings.diffContextLines,
      wrapDiffLines: typeof stored.wrapDiffLines === "boolean"
        ? stored.wrapDiffLines
        : defaultSettings.wrapDiffLines,
      eventLimit: [50, 100, 250, 500].includes(stored.eventLimit)
        ? stored.eventLimit
        : defaultSettings.eventLimit
    };
  } catch {
    return defaultSettings;
  }
}

interface ScopeReport {
  id: string;
  root: string;
  status: string;
  policyMode: string;
  responseActions: string[];
  protectedSystemPath: boolean;
  contained: boolean;
  containmentReason: string | null;
  agentOnline: boolean;
  baselineRoot: string | null;
  observedRoot: string | null;
  baselineCreatedAtUnixMs: number | null;
  entryCount: number;
  differences: DifferenceReport[];
  samplePaths: string[];
  error: string | null;
  witnessEpoch: number | null;
  acceptedWitnessIds: string[];
}

interface WitnessReport {
  configured: boolean;
  quorumValid: boolean;
  threshold: number | null;
  registeredWitnesses: number;
  verifiedScopes: number;
  totalScopes: number;
  policyPath: string | null;
  statementsDir: string | null;
  error: string | null;
}

interface EventReport {
  sequence: number;
  timestampUnixMs: number;
  scopeId: string;
  kind: string;
  severity: "critical" | "warning" | "info";
  path: string | null;
  detail: string;
}

interface ViewerReport {
  configPath: string;
  stateDir: string;
  checkedAtUnixMs: number;
  status: string;
  trustScore: number;
  trustLevel: string;
  trustNote: string;
  agentKeyId: string;
  auditChainValid: boolean;
  stateSignatureValid: boolean;
  auditError: string | null;
  stateError: string | null;
  witness: WitnessReport;
  events: EventReport[];
  scopes: ScopeReport[];
}

interface OfflinePackageReport {
  packagePath: string;
  kind: string;
  channelId: string;
  sequence: number;
  createdAtUnixMs: number;
  expiresAtUnixMs: number;
  senderKeyId: string;
  packageHash: string;
  payloadBytes: number;
  payloadStatus: string;
  scopeId: string | null;
  baselineRoot: string | null;
  observedRoot: string | null;
  epoch: number | null;
  detail: string;
}

interface FolderSetupReport {
  configPath: string;
  rootPath: string;
  breakGlassSecretPath: string;
  baselineRoot: string;
  scopeId: string;
}

const demoReport: ViewerReport = {
  configPath: "/etc/vollcrypt-shield/shield.toml",
  stateDir: "/var/lib/vollcrypt-shield",
  checkedAtUnixMs: Date.now(),
  status: "attention",
  trustScore: 45,
  trustLevel: "local-unanchored",
  trustNote:
    "Signatures are verified independently, but the trusted key is stored on the monitored machine until a witness anchor is paired.",
  agentKeyId: "772f34604f7389a821f8f58fc867bc520d05e40ecf39a58bd06509764b542f83",
  auditChainValid: true,
  stateSignatureValid: true,
  auditError: null,
  stateError: null,
  witness: {
    configured: false,
    quorumValid: false,
    threshold: null,
    registeredWitnesses: 0,
    verifiedScopes: 0,
    totalScopes: 2,
    policyPath: null,
    statementsDir: null,
    error: null
  },
  events: [
    {
      sequence: 18,
      timestampUnixMs: Date.now() - 93_000,
      scopeId: "api-production",
      kind: "Verification failed",
      severity: "critical",
      path: null,
      detail: "1 integrity differences policy=5ae87c28"
    },
    {
      sequence: 17,
      timestampUnixMs: Date.now() - 420_000,
      scopeId: "frontend-assets",
      kind: "Verification passed",
      severity: "info",
      path: null,
      detail: "verified root=31d41df7"
    },
    {
      sequence: 16,
      timestampUnixMs: Date.now() - 3_240_000,
      scopeId: "api-production",
      kind: "Policy activated",
      severity: "warning",
      path: null,
      detail: "policy=5ae87c28 approved_by=772f3460"
    }
  ],
  scopes: [
    {
      id: "api-production",
      root: "/srv/vollcrypt/api",
      status: "changed",
      policyMode: "active",
      responseActions: ["warn", "quarantine", "contain-scope"],
      protectedSystemPath: false,
      contained: false,
      containmentReason: null,
      agentOnline: true,
      baselineRoot: "4f8b24a9bb86cdca960af91f7d2f086f2629a888e4eb28dcaf4c9896e9828141",
      observedRoot: "1a09bda87a9eb99f3f7571518e33924687c969554e99823b81b7d39be3e1bb3a",
      baselineCreatedAtUnixMs: Date.now() - 86_400_000,
      entryCount: 1428,
      differences: [{
        path: "config/runtime.toml",
        absolutePath: "/srv/vollcrypt/api/config/runtime.toml",
        kind: "modified"
      }],
      samplePaths: [
        "bin/api-server", "config/default.toml", "config/runtime.toml",
        "migrations/001_initial.sql", "migrations/002_sessions.sql"
      ],
      error: null,
      witnessEpoch: null,
      acceptedWitnessIds: []
    },
    {
      id: "frontend-assets",
      root: "/srv/vollcrypt/web",
      status: "verified",
      policyMode: "dry-run",
      responseActions: ["warn"],
      protectedSystemPath: false,
      contained: false,
      containmentReason: null,
      agentOnline: true,
      baselineRoot: "31d41df7047031400d85e6940d9bb74575eb45a591e24459e2d93ca80ed1608d",
      observedRoot: "31d41df7047031400d85e6940d9bb74575eb45a591e24459e2d93ca80ed1608d",
      baselineCreatedAtUnixMs: Date.now() - 172_800_000,
      entryCount: 386,
      differences: [],
      samplePaths: ["assets/index.js", "assets/theme.css", "index.html"],
      error: null,
      witnessEpoch: null,
      acceptedWitnessIds: []
    }
  ]
};

const isTauri = () => "__TAURI_INTERNALS__" in window;

function statusLabel(status: string) {
  const labels: Record<string, string> = {
    verified: "Verified",
    attention: "Attention",
    changed: "Changed",
    contained: "Contained",
    invalid: "Invalid proof",
    checking: "Checking"
  };
  return labels[status] ?? status;
}

function formatDate(timestamp: number | null) {
  if (!timestamp) return "Not available";
  return new Intl.DateTimeFormat(undefined, {
    month: "short", day: "2-digit", hour: "2-digit",
    minute: "2-digit", second: "2-digit"
  }).format(new Date(timestamp));
}

function shortHash(value: string | null) {
  return value ? `${value.slice(0, 12)}...${value.slice(-8)}` : "Unavailable";
}

function StatusIcon({ status, size = 16 }: { status: string; size?: number }) {
  if (status === "verified") return <CheckCircle2 size={size} />;
  if (status === "contained") return <LockKeyhole size={size} />;
  if (status === "checking") return <RefreshCw size={size} className="spin" />;
  return <TriangleAlert size={size} />;
}

function App() {
  const [report, setReport] = useState<ViewerReport | null>(null);
  const [activeView, setActiveView] = useState<View>("overview");
  const [selectedScope, setSelectedScope] = useState<string | null>(null);
  const [configPath, setConfigPath] = useState(
    () => localStorage.getItem("shield-config") ?? ""
  );
  const [witnessPolicyPath, setWitnessPolicyPath] = useState(
    () => localStorage.getItem("shield-witness-policy") ?? ""
  );
  const [witnessStatementsDir, setWitnessStatementsDir] = useState(
    () => localStorage.getItem("shield-witness-statements") ?? ""
  );
  const [loading, setLoading] = useState(false);
  const [folderSetupPending, setFolderSetupPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [eventSearch, setEventSearch] = useState("");
  const [offlineReport, setOfflineReport] = useState<OfflinePackageReport | null>(null);
  const [offlineError, setOfflineError] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settings, setSettings] = useState<ViewerSettings>(loadSettings);
  const [selectedDifference, setSelectedDifference] = useState<DifferenceReport | null>(null);
  const inspectionInFlight = useRef(false);
  const pendingInspectionPath = useRef<string | null>(null);
  const requestedInspectionPath = useRef("");

  const inspect = useCallback(async (path: string) => {
    requestedInspectionPath.current = path;
    if (inspectionInFlight.current) {
      pendingInspectionPath.current = path;
      return;
    }
    inspectionInFlight.current = true;
    setLoading(true);
    setError(null);
    try {
      let nextPath: string | null = path;
      while (nextPath) {
        const currentPath = nextPath;
        pendingInspectionPath.current = null;
        try {
          const next = isTauri()
            ? await invoke<ViewerReport>("inspect_agent", {
                configPath: currentPath,
                witnessPolicyPath: witnessPolicyPath || null,
                witnessStatementsDir: witnessStatementsDir || null
              })
            : { ...demoReport, checkedAtUnixMs: Date.now() };
          if (requestedInspectionPath.current === currentPath) {
            setReport(next);
            setSelectedScope((current) =>
              next.scopes.some((scope) => scope.id === current)
                ? current
                : next.scopes[0]?.id ?? null
            );
            setError(null);
          }
        } catch (reason) {
          if (requestedInspectionPath.current === currentPath) {
            setError(String(reason));
          }
        }
        nextPath = pendingInspectionPath.current;
      }
    } finally {
      inspectionInFlight.current = false;
      setLoading(false);
    }
  }, [witnessPolicyPath, witnessStatementsDir]);

  useEffect(() => {
    if (configPath) {
      void inspect(configPath);
    } else if (!isTauri()) {
      void inspect(demoReport.configPath);
    }
  }, [configPath, inspect]);

  useEffect(() => {
    localStorage.setItem("shield-viewer-settings", JSON.stringify(settings));
  }, [settings]);

  useEffect(() => {
    if (!settings.autoRefresh || !configPath) return;
    const timer = window.setInterval(
      () => void inspect(configPath),
      settings.refreshIntervalSeconds * 1_000
    );
    return () => window.clearInterval(timer);
  }, [settings.autoRefresh, settings.refreshIntervalSeconds, configPath, inspect]);

  const chooseConfig = async () => {
    if (!isTauri()) {
      setConfigPath(demoReport.configPath);
      return;
    }
    const selected = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "Shield configuration", extensions: ["toml"] }]
    });
    if (typeof selected === "string") {
      localStorage.setItem("shield-config", selected);
      setConfigPath(selected);
    }
  };

  const chooseMonitoredFolder = async () => {
    if (!isTauri()) {
      setConfigPath(demoReport.configPath);
      return;
    }
    setError(null);
    const rootPath = await open({ multiple: false, directory: true });
    if (typeof rootPath !== "string") return;

    setFolderSetupPending(true);
    try {
      const existing = await invoke<string | null>("find_monitored_folder", { rootPath });
      if (existing) {
        localStorage.setItem("shield-config", existing);
        setConfigPath(existing);
        return;
      }
      await message(
        "Choose a separate location for the emergency recovery key. Do not save it inside the monitored folder.",
        { title: "Emergency recovery key", kind: "warning" }
      );
      const defaultRecoveryPath = await join(
        await documentDir(),
        "shield-break-glass.seed"
      );
      const breakGlassSecretPath = await save({
        title: "Save emergency recovery key outside the monitored folder",
        defaultPath: defaultRecoveryPath,
        filters: [{ name: "Shield emergency recovery key", extensions: ["seed"] }]
      });
      if (typeof breakGlassSecretPath !== "string") return;
      const setup = await invoke<FolderSetupReport>("monitor_folder", {
        rootPath,
        breakGlassSecretPath
      });
      localStorage.setItem("shield-config", setup.configPath);
      setConfigPath(setup.configPath);
    } catch (reason) {
      const detail = String(reason);
      setError(detail);
      await message(detail, { title: "Folder setup failed", kind: "error" });
    } finally {
      setFolderSetupPending(false);
    }
  };

  const chooseWitnessPolicy = async () => {
    if (!isTauri()) return;
    const selected = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "Witness policy", extensions: ["json"] }]
    });
    if (typeof selected === "string") {
      localStorage.setItem("shield-witness-policy", selected);
      setWitnessPolicyPath(selected);
    }
  };

  const chooseWitnessStatements = async () => {
    if (!isTauri()) return;
    const selected = await open({ multiple: false, directory: true });
    if (typeof selected === "string") {
      localStorage.setItem("shield-witness-statements", selected);
      setWitnessStatementsDir(selected);
    }
  };

  const clearWitnessMaterial = () => {
    localStorage.removeItem("shield-witness-policy");
    localStorage.removeItem("shield-witness-statements");
    setWitnessPolicyPath("");
    setWitnessStatementsDir("");
  };

  const chooseOfflinePackage = async () => {
    if (!isTauri()) return;
    setOfflineError(null);
    try {
      const packagePath = await open({
        title: "Select signed offline package (.vcsp or .cbor)",
        multiple: false,
        directory: false,
        filters: [{ name: "Signed Shield package", extensions: ["vcsp", "cbor"] }]
      });
      if (typeof packagePath !== "string") return;
      const publicKeyPath = await open({
        title: "Select trusted public verification key (.public, .pub, or .key)",
        multiple: false,
        directory: false,
        filters: [{ name: "Trusted public verification key", extensions: ["public", "pub", "key"] }]
      });
      if (typeof publicKeyPath !== "string") return;
      const result = await invoke<OfflinePackageReport>("inspect_offline_package", {
        packagePath,
        expectedPublicKeyPath: publicKeyPath
      });
      setOfflineReport(result);
    } catch (reason) {
      setOfflineReport(null);
      setOfflineError(String(reason));
    }
  };

  const scope = report?.scopes.find((item) => item.id === selectedScope) ?? null;
  const filteredEvents = useMemo(() => {
    const query = eventSearch.trim().toLowerCase();
    if (!report) return [];
    const events = query ? report.events.filter((event) =>
      [event.kind, event.scopeId, event.path ?? "", event.detail]
        .join(" ")
        .toLowerCase()
        .includes(query)
    ) : report.events;
    return events.slice(0, settings.eventLimit);
  }, [eventSearch, report, settings.eventLimit]);

  const compareDifference = (difference: DifferenceReport) => {
    setSelectedDifference(difference);
    setActiveView("compare");
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark"><ShieldCheck size={22} /></span>
          <div>
            <strong>Vollcrypt Shield</strong>
            <span>Integrity Viewer</span>
          </div>
        </div>
        <div className="topbar-actions">
          {report && !offlineReport && (
            <button
              className={`auto-refresh ${settings.autoRefresh ? "enabled" : ""}`}
              onClick={() => setSettings((value) => ({
                ...value,
                autoRefresh: !value.autoRefresh
              }))}
              title="Toggle automatic refresh"
            >
              <Radio size={15} />
              {loading ? "Verifying" : "Auto"}
            </button>
          )}
          <button
            className="icon-button"
            onClick={() => configPath && void inspect(configPath)}
            disabled={!configPath || loading || folderSetupPending}
            title="Refresh verification"
          >
            <RefreshCw size={17} className={loading ? "spin" : ""} />
          </button>
          <button
            className="secondary-command"
            onClick={() => void chooseOfflinePackage()}
            title="Verify a signed air-gapped evidence package"
          >
            <PackageCheck size={16} />
            Verify offline package
          </button>
          <button
            className="secondary-command"
            onClick={() => void chooseConfig()}
            disabled={folderSetupPending}
          >
            <FolderOpen size={16} />
            Open configuration
          </button>
          <button
            className="command-button"
            onClick={() => void chooseMonitoredFolder()}
            disabled={folderSetupPending}
          >
            {folderSetupPending ? <RefreshCw size={16} className="spin" /> : <FolderPlus size={16} />}
            {folderSetupPending ? "Preparing folder..." : "Monitor folder"}
          </button>
          <button
            className="icon-button"
            onClick={() => setSettingsOpen(true)}
            title="Viewer settings"
          >
            <Settings size={17} />
          </button>
        </div>
      </header>

      {offlineReport ? (
        <OfflinePackageView
          report={offlineReport}
          onClose={() => setOfflineReport(null)}
        />
      ) : !report ? (
        <main className="empty-state">
          <ShieldCheck size={38} />
          <h1>No agent connected</h1>
          <div className="empty-actions">
            <button
              className="command-button"
              onClick={() => void chooseMonitoredFolder()}
              disabled={folderSetupPending}
            >
              {folderSetupPending ? <RefreshCw size={16} className="spin" /> : <FolderPlus size={16} />}
              {folderSetupPending ? "Preparing folder..." : "Monitor folder"}
            </button>
            <button
              className="secondary-command"
              onClick={() => void chooseConfig()}
              disabled={folderSetupPending}
            >
              <FolderOpen size={16} />
              Open configuration
            </button>
          </div>
          {error && <p className="error-message">{error}</p>}
          {offlineError && <p className="error-message">{offlineError}</p>}
        </main>
      ) : (
        <div className="workspace">
          <aside className="scope-sidebar">
            <div className="sidebar-heading">
              <span>Monitored scopes</span>
              <b>{report.scopes.length}</b>
            </div>
            <div className="scope-list">
              {report.scopes.map((item) => (
                <button
                  key={item.id}
                  className={`scope-row ${selectedScope === item.id ? "selected" : ""}`}
                  onClick={() => setSelectedScope(item.id)}
                >
                  <span className={`status-dot ${item.status}`} />
                  <span className="scope-copy">
                    <strong>{item.id}</strong>
                    <small>{item.root}</small>
                  </span>
                  <ChevronRight size={15} />
                </button>
              ))}
            </div>
            <div className="identity-block">
              <span><KeyRound size={14} /> Agent identity</span>
              <code>{shortHash(report.agentKeyId)}</code>
              <small>{report.stateDir}</small>
            </div>
          </aside>

          <main className="main-panel">
            <section className={`system-state ${report.status}`}>
              <div className="state-title">
                <StatusIcon status={report.status} size={25} />
                <div>
                  <span>Independent verification</span>
                  <h1>{statusLabel(report.status)}</h1>
                </div>
              </div>
              <div className="state-metrics">
                <div>
                  <span>Trust score</span>
                  <strong>{report.trustScore}<small>/100</small></strong>
                </div>
                <div>
                  <span>Audit chain</span>
                  <strong>{report.auditChainValid ? "Valid" : "Invalid"}</strong>
                </div>
                <div>
                  <span>Signed state</span>
                  <strong>{report.stateSignatureValid ? "Valid" : "Invalid"}</strong>
                </div>
                <div>
                  <span>Witness quorum</span>
                  <strong>
                    {report.witness.quorumValid
                      ? "Valid"
                      : `${report.witness.verifiedScopes}/${report.witness.totalScopes}`}
                  </strong>
                </div>
                <div>
                  <span>Last checked</span>
                  <strong>{formatDate(report.checkedAtUnixMs)}</strong>
                </div>
              </div>
            </section>

            <section className="trust-strip">
              <Server size={16} />
              <div className="trust-copy">
                <strong>{report.trustLevel}</strong>
                <span>{report.trustNote}</span>
              </div>
              <div className="trust-actions">
                <button
                  className="icon-button"
                  onClick={() => void chooseWitnessPolicy()}
                  title="Select externally pinned witness policy"
                >
                  <KeyRound size={15} />
                </button>
                <button
                  className="icon-button"
                  onClick={() => void chooseWitnessStatements()}
                  title="Select signed witness statements directory"
                >
                  <FolderOpen size={15} />
                </button>
                {(witnessPolicyPath || witnessStatementsDir) && (
                  <button
                    className="icon-button"
                    onClick={clearWitnessMaterial}
                    title="Clear witness material"
                  >
                    <Unplug size={15} />
                  </button>
                )}
              </div>
            </section>

            {(error || offlineError || report.auditError || report.stateError || report.witness.error) && (
              <section className="integrity-errors">
                <TriangleAlert size={18} />
                <div>
                  {error && <p>{error}</p>}
                  {offlineError && <p>Offline package: {offlineError}</p>}
                  {report.auditError && <p>Audit: {report.auditError}</p>}
                  {report.stateError && <p>State: {report.stateError}</p>}
                  {report.witness.error && <p>Witness: {report.witness.error}</p>}
                </div>
              </section>
            )}

            <nav className="view-tabs" aria-label="Viewer sections">
              <button
                className={activeView === "overview" ? "active" : ""}
                onClick={() => setActiveView("overview")}
              >
                <Activity size={16} /> Overview
              </button>
              {scope && scope.differences.length > 0 && (
                <button
                  className={activeView === "compare" ? "active" : ""}
                  onClick={() => {
                    setSelectedDifference((current) => current ?? scope.differences[0]);
                    setActiveView("compare");
                  }}
                >
                  <FileCode2 size={16} /> Compare
                  <span>{scope.differences.length}</span>
                </button>
              )}
              <button
                className={activeView === "events" ? "active" : ""}
                onClick={() => setActiveView("events")}
              >
                <ScrollText size={16} /> Events
                <span>{report.events.length}</span>
              </button>
              <button
                className={activeView === "merkle" ? "active" : ""}
                onClick={() => setActiveView("merkle")}
              >
                <GitBranch size={16} /> Merkle tree
              </button>
            </nav>

            {activeView === "overview" && scope && (
              <Overview scope={scope} onCompare={compareDifference} />
            )}
            {activeView === "compare" && scope && selectedDifference && (
              <Comparison
                configPath={report.configPath}
                scope={scope}
                difference={selectedDifference}
                settings={settings}
                onSelect={setSelectedDifference}
              />
            )}
            {activeView === "events" && (
              <Events
                events={filteredEvents}
                search={eventSearch}
                onSearch={setEventSearch}
              />
            )}
            {activeView === "merkle" && scope && <MerkleTree scope={scope} />}
          </main>
        </div>
      )}
      {settingsOpen && (
        <SettingsPanel
          settings={settings}
          onChange={setSettings}
          onClose={() => setSettingsOpen(false)}
        />
      )}
    </div>
  );
}

function OfflinePackageView({
  report,
  onClose
}: {
  report: OfflinePackageReport;
  onClose: () => void;
}) {
  return (
    <main className="offline-view">
      <section className="offline-state">
        <div className="state-title">
          <CheckCircle2 size={25} />
          <div>
            <span>Independent package verification</span>
            <h1>Signature verified</h1>
          </div>
        </div>
        <button className="icon-button" onClick={onClose} title="Close package report">
          <X size={17} />
        </button>
      </section>

      <section className="offline-content">
        <div className="section-header">
          <div>
            <span>Offline evidence</span>
            <h2>{report.kind.replace(/-/g, " ")}</h2>
            <p>{report.packagePath}</p>
          </div>
          <span className="status-badge verified">
            <PackageCheck size={16} /> {report.payloadStatus}
          </span>
        </div>

        <div className="facts-grid offline-facts">
          <div className="fact">
            <span>Channel</span>
            <strong>{report.channelId}</strong>
            <small>
              Sequence {report.sequence} / {report.sequence === 1 ? "initial package" : "continuity requires cursor"}
            </small>
          </div>
          <div className="fact">
            <span>Sender identity</span>
            <strong>{shortHash(report.senderKeyId)}</strong>
            <small>ML-DSA-65</small>
          </div>
          <div className="fact">
            <span>Validity</span>
            <strong>{formatDate(report.expiresAtUnixMs)}</strong>
            <small>Created {formatDate(report.createdAtUnixMs)}</small>
          </div>
          <div className="fact">
            <span>Payload</span>
            <strong>{report.payloadBytes.toLocaleString()} bytes</strong>
            <small>{report.scopeId ?? "No scope"}{report.epoch ? ` / epoch ${report.epoch}` : ""}</small>
          </div>
        </div>

        <div className="offline-detail">
          <ShieldCheck size={18} />
          <div>
            <span>Inner evidence</span>
            <strong>{report.detail}</strong>
          </div>
        </div>

        {(report.baselineRoot || report.observedRoot) && (
          <div className="root-comparison">
            <div>
              <span>Baseline root</span>
              <code>{report.baselineRoot ?? "Not included"}</code>
            </div>
            <div className="root-divider"><CircleDot size={18} /></div>
            <div>
              <span>Observed root</span>
              <code>{report.observedRoot ?? "Not included"}</code>
            </div>
          </div>
        )}

        <div className="package-hash">
          <span>Signed package hash</span>
          <code>{report.packageHash}</code>
        </div>
      </section>
    </main>
  );
}

type DiffRowKind = "added" | "removed" | "unchanged" | "skip";

interface DiffRow {
  key: string;
  kind: DiffRowKind;
  baselineLine: number | null;
  currentLine: number | null;
  text: string;
}

function comparisonRows(
  baseline: string,
  current: string,
  contextLines: number
): DiffRow[] {
  const rows: DiffRow[] = [];
  let baselineLine = 1;
  let currentLine = 1;
  let sequence = 0;
  for (const change of diffLines(baseline, current)) {
    const lines = change.value.split(/\r?\n/);
    if (lines[lines.length - 1] === "") lines.pop();
    const kind: DiffRowKind = change.added
      ? "added"
      : change.removed
        ? "removed"
        : "unchanged";
    for (const text of lines) {
      rows.push({
        key: `${sequence++}`,
        kind,
        baselineLine: kind === "added" ? null : baselineLine++,
        currentLine: kind === "removed" ? null : currentLine++,
        text
      });
    }
  }

  const changed = rows
    .map((row, index) => row.kind === "unchanged" ? -1 : index)
    .filter((index) => index >= 0);
  if (changed.length === 0) {
    const visible = rows.slice(0, 200);
    if (visible.length < rows.length) {
      visible.push({
        key: "skip-tail",
        kind: "skip",
        baselineLine: null,
        currentLine: null,
        text: `${rows.length - visible.length} unchanged lines hidden`
      });
    }
    return visible;
  }

  const visible = new Set<number>();
  for (const index of changed) {
    const start = Math.max(0, index - contextLines);
    const end = Math.min(rows.length - 1, index + contextLines);
    for (let cursor = start; cursor <= end; cursor += 1) visible.add(cursor);
  }
  const output: DiffRow[] = [];
  let previous = -1;
  for (const index of [...visible].sort((left, right) => left - right)) {
    if (previous >= 0 && index > previous + 1) {
      output.push({
        key: `skip-${previous}-${index}`,
        kind: "skip",
        baselineLine: null,
        currentLine: null,
        text: `${index - previous - 1} unchanged lines hidden`
      });
    }
    output.push(rows[index]);
    previous = index;
  }
  return output;
}

function Comparison({
  configPath,
  scope,
  difference,
  settings,
  onSelect
}: {
  configPath: string;
  scope: ScopeReport;
  difference: DifferenceReport;
  settings: ViewerSettings;
  onSelect: (difference: DifferenceReport) => void;
}) {
  const [report, setReport] = useState<FileComparisonReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    setReport(null);
    void invoke<FileComparisonReport>("inspect_difference", {
      configPath,
      scopeId: scope.id,
      relativePath: difference.path
    }).then((value) => {
      if (active) setReport(value);
    }).catch((reason) => {
      if (active) setError(String(reason));
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [configPath, scope.id, difference.path]);

  const rows = useMemo(
    () => report?.contentStatus === "text"
      ? comparisonRows(
          report.baselineText ?? "",
          report.currentText ?? "",
          settings.diffContextLines
        )
      : [],
    [report, settings.diffContextLines]
  );

  return (
    <section className="view-content comparison-view">
      <div className="section-header">
        <div>
          <span>Verified file comparison</span>
          <h2>{difference.absolutePath}</h2>
          <p>{difference.path}</p>
        </div>
        <span className={`status-badge ${difference.kind}`}>
          <FileCode2 size={14} /> {difference.kind}
        </span>
      </div>

      <div className="comparison-layout">
        <div className="comparison-files" aria-label="Changed files">
          {scope.differences.map((item) => (
            <button
              key={`${item.kind}:${item.path}`}
              className={item.path === difference.path ? "selected" : ""}
              onClick={() => onSelect(item)}
              title={item.absolutePath}
            >
              <FileCode2 size={15} />
              <span>
                <strong>{item.absolutePath}</strong>
                <small>{item.kind}</small>
              </span>
            </button>
          ))}
        </div>

        <div className="comparison-main">
          {loading && (
            <div className="comparison-loading">
              <RefreshCw size={18} className="spin" /> Verifying file evidence
            </div>
          )}
          {error && (
            <div className="scope-error">
              <TriangleAlert size={17} /> {error}
            </div>
          )}
          {report && (
            <>
              <div className="comparison-facts">
                <div>
                  <span>Baseline</span>
                  <strong>{report.baselineSize === null ? "Absent" : `${report.baselineSize} B`}</strong>
                  <code>{shortHash(report.baselineDigest)}</code>
                </div>
                <div>
                  <span>Current</span>
                  <strong>{report.currentSize === null ? "Absent" : `${report.currentSize} B`}</strong>
                  <code>{shortHash(report.currentDigest)}</code>
                </div>
              </div>
              <div className="comparison-note">{report.detail}</div>
              {report.contentStatus === "text" ? (
                <div className={`diff-view ${settings.wrapDiffLines ? "wrap" : ""}`}>
                  <div className="diff-heading">
                    <span>Baseline</span>
                    <span>Current</span>
                    <span>Content</span>
                  </div>
                  {rows.map((row) => row.kind === "skip" ? (
                    <div className="diff-skip" key={row.key}>{row.text}</div>
                  ) : (
                    <div className={`diff-row ${row.kind}`} key={row.key}>
                      <span>{row.baselineLine ?? ""}</span>
                      <span>{row.currentLine ?? ""}</span>
                      <b>{row.kind === "added" ? "+" : row.kind === "removed" ? "-" : " "}</b>
                      <code>{row.text || " "}</code>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="comparison-unavailable">
                  <FileCode2 size={20} />
                  <strong>{report.contentStatus.replace(/-/g, " ")}</strong>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </section>
  );
}

function SettingsPanel({
  settings,
  onChange,
  onClose
}: {
  settings: ViewerSettings;
  onChange: (settings: ViewerSettings) => void;
  onClose: () => void;
}) {
  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  const update = <K extends keyof ViewerSettings>(key: K, value: ViewerSettings[K]) => {
    onChange({ ...settings, [key]: value });
  };
  return (
    <div className="settings-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="settings-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="settings-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header>
          <div>
            <span>Viewer preferences</span>
            <h2 id="settings-title">Settings</h2>
          </div>
          <button className="icon-button" onClick={onClose} title="Close settings">
            <X size={17} />
          </button>
        </header>

        <div className="settings-section">
          <h3>Verification</h3>
          <label className="setting-row">
            <span><strong>Automatic verification</strong><small>Background integrity checks</small></span>
            <button
              className={`switch ${settings.autoRefresh ? "on" : ""}`}
              role="switch"
              aria-checked={settings.autoRefresh}
              onClick={() => update("autoRefresh", !settings.autoRefresh)}
            ><i /></button>
          </label>
          <label className="setting-row">
            <span><strong>Verification interval</strong><small>Seconds between checks</small></span>
            <select
              value={settings.refreshIntervalSeconds}
              onChange={(event) => update("refreshIntervalSeconds", Number(event.target.value))}
            >
              <option value={5}>5 seconds</option>
              <option value={15}>15 seconds</option>
              <option value={30}>30 seconds</option>
              <option value={60}>1 minute</option>
              <option value={300}>5 minutes</option>
            </select>
          </label>
        </div>

        <div className="settings-section">
          <h3>Comparison</h3>
          <label className="setting-row">
            <span><strong>Context lines</strong><small>Unchanged lines around differences</small></span>
            <select
              value={settings.diffContextLines}
              onChange={(event) => update("diffContextLines", Number(event.target.value))}
            >
              <option value={3}>3 lines</option>
              <option value={5}>5 lines</option>
              <option value={10}>10 lines</option>
              <option value={25}>25 lines</option>
            </select>
          </label>
          <label className="setting-row">
            <span><strong>Wrap long lines</strong><small>Keep content within the comparison pane</small></span>
            <button
              className={`switch ${settings.wrapDiffLines ? "on" : ""}`}
              role="switch"
              aria-checked={settings.wrapDiffLines}
              onClick={() => update("wrapDiffLines", !settings.wrapDiffLines)}
            ><i /></button>
          </label>
        </div>

        <div className="settings-section">
          <h3>Events</h3>
          <label className="setting-row">
            <span><strong>Visible event limit</strong><small>Maximum timeline entries</small></span>
            <select
              value={settings.eventLimit}
              onChange={(event) => update("eventLimit", Number(event.target.value))}
            >
              <option value={50}>50 events</option>
              <option value={100}>100 events</option>
              <option value={250}>250 events</option>
              <option value={500}>500 events</option>
            </select>
          </label>
        </div>

        <footer>
          <button className="secondary-command" onClick={() => onChange(defaultSettings)}>
            Reset defaults
          </button>
          <button className="command-button" onClick={onClose}>Done</button>
        </footer>
      </section>
    </div>
  );
}

function Overview({
  scope,
  onCompare
}: {
  scope: ScopeReport;
  onCompare: (difference: DifferenceReport) => void;
}) {
  return (
    <section className="view-content">
      <div className="section-header">
        <div>
          <span>Selected scope</span>
          <h2>{scope.id}</h2>
          <p>{scope.root}</p>
        </div>
        <span className={`status-badge ${scope.status}`}>
          <StatusIcon status={scope.status} />
          {statusLabel(scope.status)}
        </span>
      </div>

      <div className="facts-grid">
        <div className="fact">
          <span>Policy mode</span>
          <strong>{scope.policyMode}</strong>
          <small>{scope.responseActions.join(" / ")}</small>
        </div>
        <div className="fact">
          <span>Agent channel</span>
          <strong>{scope.agentOnline ? "Socket online" : "Signed files"}</strong>
          <small>Independent viewer verification</small>
        </div>
        <div className="fact">
          <span>Baseline</span>
          <strong>{scope.entryCount.toLocaleString()} entries</strong>
          <small>{formatDate(scope.baselineCreatedAtUnixMs)}</small>
        </div>
        <div className="fact">
          <span>Containment</span>
          <strong>{scope.contained ? "Active" : "Clear"}</strong>
          <small>{scope.containmentReason ?? "No scope lock"}</small>
        </div>
      </div>

      <div className="root-comparison">
        <div>
          <span>Approved Merkle root</span>
          <code>{scope.baselineRoot ?? "Unavailable"}</code>
        </div>
        <div className="root-divider"><CircleDot size={18} /></div>
        <div>
          <span>Observed Merkle root</span>
          <code>{scope.observedRoot ?? "Unavailable"}</code>
        </div>
      </div>

      {scope.differences.length > 0 && (
        <div className="difference-table">
          <div className="table-heading">
            <span>Detected differences</span>
            <b>{scope.differences.length}</b>
          </div>
          {scope.differences.map((difference) => (
            <button
              type="button"
              className="difference-row"
              key={`${difference.kind}:${difference.path}`}
              onClick={() => onCompare(difference)}
              title={`Compare ${difference.absolutePath}`}
            >
              <FileCode2 size={16} />
              <span className="difference-path">
                <code>{difference.absolutePath}</code>
                <small>{difference.path}</small>
              </span>
              <span className={`change-kind ${difference.kind}`}>
                {difference.kind}
              </span>
              <ChevronRight size={15} />
            </button>
          ))}
        </div>
      )}

      {scope.error && (
        <div className="scope-error">
          <TriangleAlert size={17} />
          {scope.error}
        </div>
      )}
    </section>
  );
}

function Events({
  events,
  search,
  onSearch
}: {
  events: EventReport[];
  search: string;
  onSearch: (value: string) => void;
}) {
  return (
    <section className="view-content">
      <div className="section-header event-header">
        <div>
          <span>Verified audit chain</span>
          <h2>Event timeline</h2>
        </div>
        <label className="search-box">
          <Search size={15} />
          <input
            value={search}
            onChange={(event) => onSearch(event.target.value)}
            placeholder="Filter events"
          />
        </label>
      </div>
      <div className="timeline">
        {events.map((event) => (
          <article className="timeline-row" key={event.sequence}>
            <span className={`event-marker ${event.severity}`} />
            <div className="event-time">
              #{event.sequence}
              <small>{formatDate(event.timestampUnixMs)}</small>
            </div>
            <div className="event-body">
              <div>
                <strong>{event.kind}</strong>
                <span>{event.scopeId}</span>
              </div>
              <p>{event.detail}</p>
              {event.path && <code>{event.path}</code>}
            </div>
          </article>
        ))}
        {events.length === 0 && (
          <div className="no-results">No matching events</div>
        )}
      </div>
    </section>
  );
}

function MerkleTree({ scope }: { scope: ScopeReport }) {
  return (
    <section className="view-content">
      <div className="section-header">
        <div>
          <span>Canonical file-level tree</span>
          <h2>{scope.id}</h2>
          <p>{scope.entryCount.toLocaleString()} signed leaves</p>
        </div>
        <span className={`status-badge ${scope.status}`}>
          <GitBranch size={16} />
          SHA-256
        </span>
      </div>
      <div className="tree-root">
        <ShieldCheck size={19} />
        <div>
          <span>ML-DSA-65 signed root</span>
          <code>{scope.baselineRoot ?? "Unavailable"}</code>
        </div>
      </div>
      <div className="tree-list">
        {scope.samplePaths.map((path, index) => {
          const changed = scope.differences.find(
            (difference) => difference.path === path
          );
          return (
            <div
              className={`tree-row ${changed ? "changed" : ""}`}
              key={path}
            >
              <span className="tree-branch">
                {index === scope.samplePaths.length - 1 ? "\\-" : "+-"}
              </span>
              <FileCode2 size={15} />
              <code>{path}</code>
              {changed && (
                <span className={`change-kind ${changed.kind}`}>
                  {changed.kind}
                </span>
              )}
            </div>
          );
        })}
        {scope.samplePaths.length === 0 && (
          <div className="no-results">No verified baseline entries</div>
        )}
      </div>
    </section>
  );
}

export default App;
