import { useCallback, useEffect, useState, type ReactNode } from "react";

type Summary = Record<"findings" | "events" | "alerts" | "incidents" | "soar_runs", number>;
type AlertItem = {
  id: string;
  title: string;
  severity: string;
  rule_id: string;
  created_at: string;
  context: { match_count?: number; threshold?: number; window_seconds?: number; group_value?: string | null };
  mitre: string[];
};
type Finding = {
  id: string; title: string; severity: string; asset_id: string; recommendation: string;
  source: string; category?: string; policy_id?: string | null; resource_type?: string | null;
  evidence?: Record<string, unknown>; control_ids?: string[];
};
type Policy = {
  id: string; title: string; resource_types: string[]; severity: string;
  category: string; description: string; recommendation: string; framework_mappings: string[];
};
type EventItem = { id: string; timestamp: string; event_type: string; severity: string; host?: string; actor?: string; message: string; source: string };
type Rule = { id: string; title: string; severity: string; match: Record<string, string>; threshold: number; window_seconds: number; group_by?: string };
type Playbook = { id: string; name: string; steps: string[] };

const API = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";
const tabs = ["Overview", "Posture", "Policies", "Telemetry", "Detections", "SOAR"] as const;
type Tab = (typeof tabs)[number];

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${API}${path}`);
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.json() as Promise<T>;
}

function Badge({ value }: { value: string }) {
  return <span className={`badge ${value.toLowerCase()}`}>{value}</span>;
}

export default function App() {
  const [tab, setTab] = useState<Tab>("Overview");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [status, setStatus] = useState("Connecting");
  const [error, setError] = useState("");
  const [actionMessage, setActionMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [health, counts, alertRows, findingRows, policyRows, eventRows, ruleRows, playbookRows] = await Promise.all([
        get<{ status: string }>("/health"),
        get<Summary>("/api/v1/summary"),
        get<AlertItem[]>("/api/v1/alerts?limit=50"),
        get<Finding[]>("/api/v1/findings?limit=50"),
        get<Policy[]>("/api/v1/posture/policies"),
        get<EventItem[]>("/api/v1/events?limit=50"),
        get<Rule[]>("/api/v1/rules"),
        get<Playbook[]>("/api/v1/soar/playbooks"),
      ]);
      setSummary(counts);
      setAlerts(alertRows);
      setFindings(findingRows);
      setPolicies(policyRows);
      setEvents(eventRows);
      setRules(ruleRows);
      setPlaybooks(playbookRows);
      setStatus(health.status === "ok" ? "API online" : "API error");
      setError("");
    } catch (reason) {
      setStatus("API offline");
      setError(reason instanceof Error ? reason.message : "Could not load the local API.");
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 30000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  async function runPlaybook(id: string, approved: boolean) {
    setBusy(true);
    setActionMessage("");
    try {
      const response = await fetch(`${API}/api/v1/soar/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ playbook_id: id, approved, dry_run: true }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || `HTTP ${response.status}`);
      setActionMessage(`${result.playbook_id}: ${result.status}. Simulation only; no external action was performed.`);
      await refresh();
    } catch (reason) {
      setActionMessage(reason instanceof Error ? reason.message : "SOAR preview failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main>
      <header>
        <div>
          <small className="eyebrow">LOCAL-FIRST CLOUD DEFENSE</small>
          <h1>AzureSentinelForge</h1>
          <p>Posture management · runtime signals · SIEM correlation · safe SOAR</p>
        </div>
        <div className={`connection ${status === "API online" ? "online" : "offline"}`}>
          <i /> {status}
          <button className="refresh" onClick={() => void refresh()} aria-label="Refresh dashboard">↻</button>
        </div>
      </header>

      <aside className="notice">
        <strong>Demo data boundary</strong>
        <span>Fixtures are synthetic. Live Azure inventory requires your subscription and appropriate read-only permissions. This project does not provision resources or perform remediation. Microsoft Sentinel and Defender for Cloud are separate Microsoft services and may incur charges.</span>
      </aside>

      <nav aria-label="Dashboard sections">
        {tabs.map((item) => <button key={item} className={tab === item ? "active" : ""} onClick={() => setTab(item)}>{item}</button>)}
      </nav>

      {error && <div className="error">{error}. Start the API with <code>uvicorn backend.app.main:app --reload</code>.</div>}
      {actionMessage && <div className="action-message">{actionMessage}</div>}

      {tab === "Overview" && <>
        <div className="section-heading"><div><small>SECURITY OPERATIONS</small><h2>Environment overview</h2></div><span>Refreshes every 30 seconds</span></div>
        <section className="metrics">
          {(["findings", "events", "alerts", "incidents", "soar_runs"] as const).map((key) => (
            <article className="metric" key={key}><small>{key.replace("_", " ").toUpperCase()}</small><strong>{summary ? summary[key] : "—"}</strong><label>Local SQLite</label></article>
          ))}
        </section>
        <div className="columns">
          <Panel title="Recent detections" count={alerts.length}>
            {alerts.length ? alerts.slice(0, 8).map((item) => <AlertRow item={item} key={item.id} />) : <Empty>No alerts yet. Load the synthetic demo to populate detections.</Empty>}
          </Panel>
          <Panel title="Posture findings" count={findings.length}>
            {findings.length ? findings.slice(0, 6).map((item) => <div className="list-row" key={item.id}><div><b>{item.title}</b><small>{item.asset_id}</small></div><Badge value={item.severity} /></div>) : <Empty>No posture findings loaded.</Empty>}
          </Panel>
        </div>
      </>}

      {tab === "Posture" && <>
        <div className="section-heading"><div><small>CLOUD SECURITY POSTURE</small><h2>Configuration findings</h2></div><span>{findings.length} records</span></div>
        <Panel title="Evaluated assets">
          {findings.length ? findings.map((item) => <div className="detail-row" key={item.id}><div><b>{item.title}</b><small>{item.asset_id} · {item.policy_id || item.category || "policy"} · {item.resource_type || "resource"} · {item.source}</small><p>{item.recommendation}</p>{item.evidence && <small>Evidence: {JSON.stringify(item.evidence)}</small>}</div><Badge value={item.severity} /></div>) : <Empty>Run <code>python scripts/load_demo.py</code> to evaluate the labelled synthetic inventory.</Empty>}
        </Panel>
      </>}

      {tab === "Policies" && <>
        <div className="section-heading"><div><small>POLICY CATALOG</small><h2>Azure posture checks</h2></div><span>{policies.length} implemented checks</span></div>
        <div className="columns">
          {policies.map((policy) => <article className="panel" key={policy.id}>
            <div className="panel-heading"><h3>{policy.title}</h3><Badge value={policy.severity} /></div>
            <small>{policy.id} · {policy.resource_types.join(", ")} · {policy.category}</small>
            <p className="muted">{policy.description}</p>
            <p className="muted">Guidance: {policy.recommendation}</p>
            <small>{policy.framework_mappings.length ? policy.framework_mappings.join(", ") : "Framework crosswalk pending validation"}</small>
          </article>)}
        </div>
        <p className="muted">Checks only report explicitly observed risky values. Missing inventory properties remain unknown and do not generate a pass or fail finding.</p>
      </>}

      {tab === "Telemetry" && <>
        <div className="section-heading"><div><small>HOST AND CONTAINER SIGNALS</small><h2>Recent events</h2></div><span>{events.length} records</span></div>
        <Panel title="Normalized event stream">
          {events.length ? events.map((item) => <div className="detail-row" key={item.id}><div><b>{item.event_type}</b><small>{item.timestamp} · {item.source} · {item.host || "unknown host"} · {item.actor || "unknown actor"}</small><p>{item.message}</p></div><Badge value={item.severity} /></div>) : <Empty>Use the Linux auth-log or Docker snapshot adapters, or load the synthetic fixtures.</Empty>}
        </Panel>
      </>}

      {tab === "Detections" && <>
        <div className="section-heading"><div><small>YAML DETECTION ENGINE</small><h2>Detection rules</h2></div><span>{rules.length} active rules</span></div>
        <Panel title="Loaded rules">
          {rules.map((rule) => <div className="detail-row" key={rule.id}><div><b>{rule.title}</b><small>{rule.id} · match: {Object.entries(rule.match).map(([key, value]) => `${key}=${value}`).join(", ")}</small>{rule.threshold > 1 && <p>Threshold: {rule.threshold} events / {rule.window_seconds}s{rule.group_by ? ` grouped by ${rule.group_by}` : ""}</p>}</div><Badge value={rule.severity} /></div>)}
        </Panel>
      </>}

      {tab === "SOAR" && <>
        <div className="section-heading"><div><small>SAFE ORCHESTRATION</small><h2>Playbook previews</h2></div><span>Dry-run only</span></div>
        <div className="columns">
          {playbooks.map((playbook) => <article className="playbook" key={playbook.id}><small>PLAYBOOK</small><h3>{playbook.name}</h3><ol>{playbook.steps.map((step) => <li key={step}>{step}</li>)}</ol><div className="button-row"><button disabled={busy} onClick={() => void runPlaybook(playbook.id, false)}>Preview</button><button className="secondary" disabled={busy} onClick={() => void runPlaybook(playbook.id, true)}>Approve preview record</button></div></article>)}
        </div>
        <p className="muted">Approval changes only the local audit record. There is no remediation executor, cloud write permission, account action, IP block, or host isolation.</p>
      </>}

      <footer>AzureSentinelForge 0.3 · Local API: {API} · No paid cloud dependency for the synthetic demo</footer>
    </main>
  );
}

function Panel({ title, count, children }: { title: string; count?: number; children: ReactNode }) {
  return <article className="panel"><div className="panel-heading"><h3>{title}</h3>{count !== undefined && <span>{count}</span>}</div>{children}</article>;
}
function Empty({ children }: { children: ReactNode }) { return <p className="empty">{children}</p>; }
function AlertRow({ item }: { item: AlertItem }) {
  const correlation = item.context?.threshold && item.context.threshold > 1;
  return <div className="list-row"><div><b>{item.title}</b><small>{item.rule_id}{correlation ? ` · ${item.context.match_count}/${item.context.threshold} in ${item.context.window_seconds}s` : ""}</small></div><Badge value={item.severity} /></div>;
}
