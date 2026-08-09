import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import {
  Activity, CheckCircle2, ChevronRight, CircleDot, FileCode2, FolderOpen,
  GitBranch, KeyRound, LockKeyhole, Radio, RefreshCw, ScrollText, Search,
  PackageCheck, Server, ShieldCheck, TriangleAlert, Unplug, X
} from "lucide-react";

type View = "overview" | "events" | "merkle";

interface DifferenceReport {
  path: string;
  kind: "added" | "removed" | "modified";
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
      differences: [{ path: "config/runtime.toml", kind: "modified" }],
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
  const [error, setError] = useState<string | null>(null);
  const [eventSearch, setEventSearch] = useState("");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [offlineReport, setOfflineReport] = useState<OfflinePackageReport | null>(null);
  const [offlineError, setOfflineError] = useState<string | null>(null);

  const inspect = useCallback(async (path: string) => {
    setLoading(true);
    setError(null);
    try {
      const next = isTauri()
        ? await invoke<ViewerReport>("inspect_agent", {
            configPath: path,
            witnessPolicyPath: witnessPolicyPath || null,
            witnessStatementsDir: witnessStatementsDir || null
          })
        : { ...demoReport, checkedAtUnixMs: Date.now() };
      setReport(next);
      setSelectedScope((current) =>
        next.scopes.some((scope) => scope.id === current)
          ? current
          : next.scopes[0]?.id ?? null
      );
    } catch (reason) {
      setError(String(reason));
    } finally {
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
    if (!autoRefresh || !configPath) return;
    const timer = window.setInterval(() => void inspect(configPath), 15_000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, configPath, inspect]);

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
    const packagePath = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "Shield offline package", extensions: ["vcsp", "cbor"] }]
    });
    if (typeof packagePath !== "string") return;
    const publicKeyPath = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "Trusted ML-DSA public key", extensions: ["public", "pub", "key"] }]
    });
    if (typeof publicKeyPath !== "string") return;
    try {
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
    if (!report || !query) return report?.events ?? [];
    return report.events.filter((event) =>
      [event.kind, event.scopeId, event.path ?? "", event.detail]
        .join(" ")
        .toLowerCase()
        .includes(query)
    );
  }, [eventSearch, report]);

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
              className={`auto-refresh ${autoRefresh ? "enabled" : ""}`}
              onClick={() => setAutoRefresh((value) => !value)}
              title="Toggle automatic refresh"
            >
              <Radio size={15} />
              Live
            </button>
          )}
          <button
            className="icon-button"
            onClick={() => configPath && void inspect(configPath)}
            disabled={!configPath || loading}
            title="Refresh verification"
          >
            <RefreshCw size={17} className={loading ? "spin" : ""} />
          </button>
          <button
            className="secondary-command"
            onClick={() => void chooseOfflinePackage()}
          >
            <PackageCheck size={16} />
            Verify package
          </button>
          <button className="command-button" onClick={() => void chooseConfig()}>
            <FolderOpen size={16} />
            Open configuration
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
          <button className="command-button" onClick={() => void chooseConfig()}>
            <FolderOpen size={16} />
            Open configuration
          </button>
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

            {activeView === "overview" && scope && <Overview scope={scope} />}
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

function Overview({ scope }: { scope: ScopeReport }) {
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
            <div
              className="difference-row"
              key={`${difference.kind}:${difference.path}`}
            >
              <FileCode2 size={16} />
              <code>{difference.path}</code>
              <span className={`change-kind ${difference.kind}`}>
                {difference.kind}
              </span>
            </div>
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
