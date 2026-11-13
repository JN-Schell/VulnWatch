import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  Bell,
  BookOpen,
  Check,
  CheckCheck,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  Clock3,
  Database,
  FileCheck2,
  FileUp,
  Globe2,
  LayoutDashboard,
  ListFilter,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Menu,
  Moon,
  Plus,
  RefreshCw,
  Search,
  Server,
  Settings2,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Sun,
  Target,
  X,
} from "lucide-react";
import { api, date, setCSRF } from "./api";
import type {
  Asset,
  Audit,
  CVE,
  Dashboard,
  Finding,
  ImportJob,
  Notification,
  Policy,
  Sync,
  User,
} from "./types";

type Page =
  | "Overview"
  | "Vulnerabilities"
  | "Assets"
  | "Remediation"
  | "Imports"
  | "CVE intelligence"
  | "Reports"
  | "Settings";
const pages: { label: Page; icon: typeof Shield }[] = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "Vulnerabilities", icon: ShieldAlert },
  { label: "Assets", icon: Server },
  { label: "Remediation", icon: CheckCheck },
  { label: "Imports", icon: FileUp },
  { label: "CVE intelligence", icon: Database },
  { label: "Reports", icon: FileCheck2 },
  { label: "Settings", icon: Settings2 },
];
const levels = ["critical", "high", "medium", "low", "unknown", "none"];
const states = ["open", "in_progress", "mitigated", "verified", "accepted"];
const transitions: Record<string, string[]> = {
  open: ["in_progress", "accepted"],
  in_progress: ["open", "mitigated", "accepted"],
  mitigated: ["in_progress", "verified", "accepted"],
  verified: ["open"],
  accepted: ["open"],
};
const titleCase = (value: string) =>
  value.replaceAll("_", " ").replace(/^./, (text) => text.toUpperCase());

function Badge({ value }: { value: string }) {
  return (
    <span className={`badge ${value}`}>
      <i />
      {titleCase(value)}
    </span>
  );
}
function Empty({
  children = "No records yet. Import a scan to get started.",
}: {
  children?: ReactNode;
}) {
  return (
    <div className="empty">
      <ShieldCheck size={30} />
      <p>{children}</p>
    </div>
  );
}
function Modal({
  title,
  close,
  children,
  error,
}: {
  title: string;
  close: () => void;
  children: ReactNode;
  error?: string;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current!;
    dialog.showModal();
    return () => dialog.close();
  }, []);
  return (
    <dialog
      aria-label={title}
      ref={ref}
      onCancel={close}
      onClick={(event) => {
        if (event.target === ref.current) close();
      }}
    >
      <div className="modal-head">
        <h2>{title}</h2>
        <button
          aria-label="Close dialog"
          className="icon-button"
          onClick={close}
        >
          <X size={20} />
        </button>
      </div>
      <div className="modal-body">
        {error && (
          <div role="alert" className="error">
            {error}
          </div>
        )}
        {children}
      </div>
    </dialog>
  );
}

function RiskChart({ trend }: { trend: Dashboard["trend"] }) {
  if (!trend.length)
    return (
      <Empty>
        No risk history yet. Assessments appear after your first import.
      </Empty>
    );
  const maximum = Math.max(...trend.map((entry) => entry.risk), 1);
  const points = trend.map(
    (entry, index) =>
      `${40 + (index / Math.max(trend.length - 1, 1)) * 640},${170 - (entry.risk / maximum) * 135}`,
  );
  if (points.length === 1)
    points.push(`680,${170 - (trend[0].risk / maximum) * 135}`);
  return (
    <div className="risk-chart">
      <svg
        viewBox="0 0 720 220"
        role="img"
        aria-label="Recorded aggregate custom risk over time"
      >
        <defs>
          <linearGradient id="risk-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity=".22" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0, 1, 2, 3].map((index) => (
          <g key={index}>
            <line
              x1="40"
              x2="685"
              y1={35 + index * 45}
              y2={35 + index * 45}
              stroke="currentColor"
              className="chart-grid"
              strokeDasharray="4 6"
            />
            <text x="0" y={39 + index * 45}>
              {Math.round(maximum * (1 - index / 3))}
            </text>
          </g>
        ))}
        <polygon
          points={`40,170 ${points.join(" ")} 680,170`}
          fill="url(#risk-fill)"
        />
        <polyline
          points={points.join(" ")}
          fill="none"
          stroke="var(--accent)"
          strokeWidth="2.5"
          strokeLinejoin="round"
        />
        {trend.map((entry, index) => (
          <circle
            key={entry.date}
            cx={40 + (index / Math.max(trend.length - 1, 1)) * 640}
            cy={170 - (entry.risk / maximum) * 135}
            r="4"
            fill="var(--accent)"
          >
            <title>
              {entry.date}: {entry.risk}
            </title>
          </circle>
        ))}
        <text x="40" y="208">
          {date(trend[0].date, true)}
        </text>
        <text x="680" y="208" textAnchor="end">
          {date(trend[trend.length - 1].date, true)}
        </text>
      </svg>
    </div>
  );
}

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [booting, setBooting] = useState(true);
  const [page, setPage] = useState<Page>("Overview");
  const [theme, setTheme] = useState(
    localStorage.getItem("vw-theme") || "dark",
  );
  const [mobile, setMobile] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [assetFilter, setAssetFilter] = useState("");
  const [overdue, setOverdue] = useState(false);
  const [listPage, setListPage] = useState(1);
  const [imports, setImports] = useState<ImportJob[]>([]);
  const [sync, setSync] = useState<Sync | null>(null);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [bell, setBell] = useState(false);
  const [cves, setCves] = useState<CVE[]>([]);
  const [cveTotal, setCveTotal] = useState(0);
  const [cvePage, setCvePage] = useState(1);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [detail, setDetail] = useState<Finding | null>(null);
  const [cveDetail, setCveDetail] = useState<CVE | null>(null);
  const [newAsset, setNewAsset] = useState(false);
  const [editAsset, setEditAsset] = useState<Asset | null>(null);
  const [report, setReport] = useState<(Dashboard & { asset: Asset }) | null>(
    null,
  );
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [adapter, setAdapter] = useState("generic-json");
  const fileInput = useRef<HTMLInputElement>(null);
  const loadGeneration = useRef(0);
  const canWrite = user?.role !== "viewer";

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("vw-theme", theme);
  }, [theme]);
  useEffect(() => {
    const expire = () => {
      loadGeneration.current += 1;
      setBusy(false);
      setUser(null);
      setCSRF("");
    };
    window.addEventListener("session-expired", expire);
    api<{ user: User; csrf_token: string }>("/auth/session")
      .then((session) => {
        setUser(session.user);
        setCSRF(session.csrf_token);
      })
      .catch(() => {})
      .finally(() => setBooting(false));
    return () => window.removeEventListener("session-expired", expire);
  }, []);
  useEffect(() => {
    if (notice) {
      const timer = setTimeout(() => setNotice(""), 6000);
      return () => clearTimeout(timer);
    }
  }, [notice]);

  const load = useCallback(async () => {
    if (!user) return;
    const generation = ++loadGeneration.current;
    setBusy(true);
    try {
      const params = new URLSearchParams({
        q: query,
        page: String(listPage),
        page_size: "15",
      });
      if (status) params.set("status", status);
      else if (page === "Remediation") params.set("status", "in_progress");
      if (severity) params.set("severity_level", severity);
      if (assetFilter) params.set("asset_id", assetFilter);
      if (overdue) params.set("overdue", "true");
      const [
        summary,
        inventory,
        members,
        records,
        jobs,
        syncState,
        alerts,
        intelligence,
        currentPolicy,
      ] = await Promise.all([
        api<Dashboard>("/dashboard"),
        api<Asset[]>("/assets"),
        api<User[]>("/users"),
        api<{ items: Finding[]; total: number }>(`/findings?${params}`),
        api<ImportJob[]>("/imports"),
        api<Sync>("/sync"),
        api<Notification[]>("/notifications"),
        api<{ items: CVE[]; total: number }>(
          `/cves?q=${encodeURIComponent(page === "CVE intelligence" ? query : "")}&page=${cvePage}`,
        ),
        api<Policy>("/policy"),
      ]);
      if (generation !== loadGeneration.current) return;
      setDashboard(summary);
      setAssets(inventory);
      setUsers(members);
      setFindings(records.items);
      setTotal(records.total);
      setImports(jobs);
      setSync(syncState);
      setNotifications(alerts);
      setCves(intelligence.items);
      setCveTotal(intelligence.total);
      setPolicy(currentPolicy);
      if (page === "Settings" && user.role === "admin") {
        const events = await api<Audit[]>("/audit");
        if (generation === loadGeneration.current) setAudit(events);
      }
    } catch (failure) {
      if (generation === loadGeneration.current)
        setError((failure as Error).message);
    } finally {
      if (generation === loadGeneration.current) setBusy(false);
    }
  }, [
    user,
    page,
    query,
    status,
    severity,
    assetFilter,
    overdue,
    listPage,
    cvePage,
  ]);
  useEffect(() => {
    const timer = setTimeout(load, 200);
    return () => clearTimeout(timer);
  }, [load]);

  async function action(
    work: () => Promise<unknown>,
    success: string,
    refresh = true,
  ) {
    setBusy(true);
    setError("");
    try {
      await work();
      setNotice(success);
      if (refresh) await load();
    } catch (failure) {
      setError((failure as Error).message);
    } finally {
      setBusy(false);
    }
  }
  function navigate(next: Page) {
    setPage(next);
    setQuery("");
    setStatus("");
    setSeverity("");
    setAssetFilter("");
    setOverdue(false);
    setListPage(1);
    setCvePage(1);
    setMobile(false);
  }
  async function openFinding(id: number) {
    try {
      setDetail(await api<Finding>(`/findings/${id}`));
    } catch (failure) {
      setError((failure as Error).message);
    }
  }
  async function openCVE(id: string) {
    try {
      setCveDetail(await api<CVE>(`/cves/${id}`));
    } catch (failure) {
      setError((failure as Error).message);
    }
  }

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setBusy(true);
    setError("");
    try {
      const session = await api<{ user: User; csrf_token: string }>(
        "/auth/login",
        { method: "POST", body: JSON.stringify(Object.fromEntries(data)) },
      );
      setCSRF(session.csrf_token);
      setUser(session.user);
    } catch (failure) {
      setError((failure as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (booting)
    return (
      <div className="boot">
        <ShieldCheck size={42} />
        <p>Connecting to VulnWatch…</p>
      </div>
    );
  if (!user)
    return (
      <div className="login-screen">
        <div className="login-art">
          <div className="brand">
            <span className="brand-mark">
              <ShieldCheck />
            </span>
            vuln<span>watch</span>
          </div>
          <div>
            <span className="eyebrow">
              KNOW YOUR EXPOSURE. OWN YOUR RESPONSE.
            </span>
            <h1>
              A clearer view.
              <br />A stronger defense.
            </h1>
            <p>
              From the first finding to verified remediation.
              <br />
              Your security operations, connected.
            </p>
            <div className="login-orbit">
              <ShieldCheck size={85} />
              <span className="orbit-label">
                <Activity size={14} /> Built for defensive security
              </span>
            </div>
          </div>
          <span className="muted">VULNWATCH / VULNERABILITY MANAGEMENT</span>
        </div>
        <main className="login-form">
          <div className="login-box">
            <span className="login-lock">
              <LockKeyhole size={24} />
            </span>
            <h2>Welcome back</h2>
            <p className="muted">Sign in to your security workspace.</p>
            {error && (
              <div role="alert" className="error">
                {error}
              </div>
            )}
            <form onSubmit={login}>
              <label>
                Email address
                <input
                  name="email"
                  type="email"
                  placeholder="you@organization.com"
                  autoComplete="username"
                  required
                />
              </label>
              <label>
                Password
                <input
                  name="password"
                  type="password"
                  placeholder="Enter your password"
                  autoComplete="current-password"
                  maxLength={128}
                  required
                />
              </label>
              <button className="primary full" disabled={busy}>
                {busy ? (
                  <LoaderCircle className="spin" size={17} />
                ) : (
                  <>
                    Sign in to workspace <ArrowRight size={17} />
                  </>
                )}
              </button>
            </form>
            <p className="login-help">
              <Shield size={14} /> Access is managed by your administrator.
              <br />
              No public registration. No default credentials.
            </p>
          </div>
        </main>
      </div>
    );

  const findingTable = (compact = false) => (
    <>
      {findings.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Vulnerability</th>
                <th>Severity</th>
                <th>Asset</th>
                <th>
                  Priority <span className="muted">/100</span>
                </th>
                <th>Status</th>
                {!compact && <th>Due date</th>}
                <th>
                  <span className="sr-only">Details</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {findings.slice(0, compact ? 5 : 15).map((finding) => (
                <tr key={finding.id}>
                  <td>
                    <button
                      className="table-title"
                      onClick={() => openFinding(finding.id)}
                    >
                      {finding.title}
                    </button>
                    <span className="subline mono">
                      {finding.cve_id || "NON-CVE FINDING"}
                      {finding.locator && ` · ${finding.locator}`}
                    </span>
                  </td>
                  <td>
                    <Badge value={finding.severity} />
                  </td>
                  <td>
                    <span className="asset-cell">
                      <Server size={13} />
                      {finding.asset.name}
                    </span>
                  </td>
                  <td>
                    <div className="score">
                      {finding.risk_score.toFixed(1)}
                      <span className="mini-track">
                        <i style={{ width: `${finding.risk_score}%` }} />
                      </span>
                    </div>
                  </td>
                  <td>
                    <Badge value={finding.status} />
                  </td>
                  {!compact && (
                    <td className={finding.overdue ? "danger-text" : "muted"}>
                      {date(finding.due_at, true)}
                      {finding.overdue && (
                        <span className="subline danger-text">Overdue</span>
                      )}
                    </td>
                  )}
                  <td>
                    <button
                      className="icon-button"
                      aria-label={`View ${finding.title}`}
                      onClick={() => openFinding(finding.id)}
                    >
                      <ArrowUpRight size={16} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty>
          {imports.length
            ? "No findings match your filters."
            : "Your inventory is ready. Add assets, then import your first scan."}
        </Empty>
      )}
    </>
  );
  const filterBar = (
    <div className="filter-bar">
      <div className="search-input">
        <Search size={16} />
        <input
          aria-label="Search findings"
          placeholder="Search CVE, vulnerability, or asset…"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setListPage(1);
          }}
        />
      </div>
      <select
        aria-label="Severity filter"
        value={severity}
        onChange={(event) => {
          setSeverity(event.target.value);
          setListPage(1);
        }}
      >
        <option value="">All severities</option>
        {levels.map((level) => (
          <option key={level} value={level}>
            {titleCase(level)}
          </option>
        ))}
      </select>
      <select
        aria-label="Status filter"
        value={status}
        onChange={(event) => {
          setStatus(event.target.value);
          setListPage(1);
        }}
      >
        <option value="">
          {page === "Remediation" ? "In progress (default)" : "All statuses"}
        </option>
        {states.map((state) => (
          <option key={state} value={state}>
            {titleCase(state)}
          </option>
        ))}
      </select>
      <select
        aria-label="Asset filter"
        value={assetFilter}
        onChange={(event) => {
          setAssetFilter(event.target.value);
          setListPage(1);
        }}
      >
        <option value="">All assets</option>
        {assets.map((asset) => (
          <option key={asset.id} value={asset.id}>
            {asset.name}
          </option>
        ))}
      </select>
      <button
        className={`secondary ${overdue ? "selected" : ""}`}
        onClick={() => {
          setOverdue(!overdue);
          setListPage(1);
        }}
      >
        <ListFilter size={14} />
        Overdue
      </button>
    </div>
  );

  return (
    <div className="app-shell">
      <a className="skip" href="#main">
        Skip to content
      </a>
      <aside className={`sidebar ${mobile ? "mobile-open" : ""}`}>
        <div className="brand">
          <span className="brand-mark">
            <ShieldCheck size={22} />
          </span>
          vuln<span>watch</span>
          <button
            className="icon-button mobile-only"
            aria-label="Close navigation"
            onClick={() => setMobile(false)}
          >
            <X size={18} />
          </button>
        </div>
        <div className="workspace">
          <span className="workspace-icon">
            <Shield size={17} />
          </span>
          <div>
            Security workspace<span>Organization overview</span>
          </div>
          <ChevronDown size={13} />
        </div>
        <span className="nav-label">WORKSPACE</span>
        <nav>
          {pages.map(({ label, icon: Icon }) => (
            <button
              key={label}
              className={page === label ? "active" : ""}
              onClick={() => navigate(label)}
            >
              <Icon size={18} />
              {label}
              {label === "Vulnerabilities" && dashboard && (
                <span className="nav-count">{dashboard.total}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="defense-card">
            <span className="live-dot" />
            <span>Defensive by design</span>
            <p>
              Visibility. Prioritization.
              <br />
              Verified remediation.
            </p>
            <button onClick={() => navigate("Reports")}>
              View security reports <ArrowUpRight size={14} />
            </button>
          </div>
          <button
            className="sidebar-help"
            onClick={() => {
              setNotice(
                "Start with Assets → Imports. Use CVE intelligence for NVD records, and Settings for policy. Full documentation is in the repository README.",
              );
            }}
          >
            <CircleHelp size={17} />
            Workspace guide
          </button>
          <div className="user-block">
            <span className="avatar">
              {user.name
                .split(" ")
                .map((part) => part[0])
                .slice(0, 2)
                .join("")}
            </span>
            <div>
              {user.name}
              <span>{titleCase(user.role)}</span>
            </div>
            <button
              aria-label="Sign out"
              className="icon-button"
              onClick={() =>
                action(
                  async () => {
                    await api("/auth/logout", { method: "POST" });
                    loadGeneration.current += 1;
                    setUser(null);
                    setCSRF("");
                    setDetail(null);
                    setCveDetail(null);
                    setReport(null);
                    navigate("Overview");
                  },
                  "Signed out",
                  false,
                )
              }
            >
              <LogOut size={16} />
            </button>
          </div>
        </div>
      </aside>
      <div className="app-main">
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button mobile-only"
              aria-label="Open navigation"
              onClick={() => setMobile(true)}
            >
              <Menu size={20} />
            </button>
            <Shield size={15} />
            <span>Workspace</span>
            <ChevronRight size={13} />
            <strong>{page}</strong>
          </div>
          <div className="top-actions">
            <span className="environment">
              <span className="live-dot" />
              PRIVATE WORKSPACE
            </span>
            <button
              className="icon-button"
              aria-label="Toggle theme"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            >
              {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
            </button>
            <div className="bell-wrap">
              <button
                className="icon-button"
                aria-label="Notifications"
                aria-expanded={bell}
                onClick={() => setBell(!bell)}
              >
                <Bell size={18} />
                {notifications.length > 0 && <i className="notification-dot" />}
              </button>
              {bell && (
                <div className="notification-panel">
                  <h3>Workspace notifications</h3>
                  {notifications.length ? (
                    notifications.slice(0, 8).map((entry) => (
                      <button
                        key={entry.id}
                        onClick={() => {
                          setBell(false);
                          if (entry.finding_id) openFinding(entry.finding_id);
                        }}
                      >
                        {entry.message}
                        <span>{date(entry.created_at)}</span>
                      </button>
                    ))
                  ) : (
                    <p className="muted">You're all caught up.</p>
                  )}
                </div>
              )}
            </div>
            <span className="avatar small">{user.name[0]}</span>
          </div>
        </header>
        <main id="main" className="content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                SECURITY OPERATIONS /{" "}
                {page === "Overview" ? "COMMAND CENTER" : page.toUpperCase()}
              </div>
              <h1>
                {page === "Overview"
                  ? "Security overview"
                  : page === "Vulnerabilities"
                    ? "Vulnerability inventory"
                    : page === "Remediation"
                      ? "Remediation workspace"
                      : page}
              </h1>
              <p>
                {
                  {
                    Overview:
                      "Understand your exposure. Focus on what matters.",
                    Vulnerabilities: "Every finding. One source of truth.",
                    Assets: "The systems you protect and the risks they carry.",
                    Remediation:
                      "Turn security findings into verified outcomes.",
                    Imports:
                      "Bring your scan results into a connected workflow.",
                    "CVE intelligence":
                      "Authoritative vulnerability data, synchronized from NVD.",
                    Reports:
                      "Measure exposure, aging, and remediation performance.",
                    Settings:
                      "Manage your security policy and workspace access.",
                  }[page]
                }
              </p>
            </div>
            <div className="heading-actions">
              <button className="secondary" onClick={load} disabled={busy}>
                <RefreshCw size={15} className={busy ? "spin" : ""} />
                <span>Refresh</span>
              </button>
              {page === "Assets" && canWrite ? (
                <button className="primary" onClick={() => setNewAsset(true)}>
                  <Plus size={16} />
                  Add asset
                </button>
              ) : canWrite &&
                page !== "Settings" &&
                page !== "CVE intelligence" ? (
                <button className="primary" onClick={() => navigate("Imports")}>
                  <Plus size={16} />
                  Import findings
                </button>
              ) : null}
            </div>
          </div>
          {imports.some((job) => job.adapter === "demo-fixture") && (
            <div className="demo-banner">
              <CircleHelp size={14} />
              Demonstration data is present. Synthetic findings are not actual
              scan results or NVD intelligence.
            </div>
          )}
          {error && (
            <div role="alert" className="error">
              <ShieldAlert size={17} />
              {error}
              <button aria-label="Dismiss error" onClick={() => setError("")}>
                <X size={16} />
              </button>
            </div>
          )}
          {notice && (
            <div role="status" className="notice">
              <Check size={17} />
              {notice}
              <button
                aria-label="Dismiss notification"
                onClick={() => setNotice("")}
              >
                <X size={16} />
              </button>
            </div>
          )}
          {page === "Overview" && dashboard && (
            <>
              <div className="overview-meta">
                <span>
                  <span className="live-dot" />
                  Live inventory <span className="separator">/</span>{" "}
                  {assets.length} assets monitored
                </span>
                <span>
                  <Clock3 size={13} />
                  {date(new Date().toISOString())}
                </span>
              </div>
              <div className="stats-grid">
                {[
                  {
                    label: "Total findings",
                    value: dashboard.total,
                    icon: ShieldAlert,
                    foot: `${dashboard.unique_vulnerabilities} unique vulnerabilities`,
                    color: "",
                  },
                  {
                    label: "Critical exposure",
                    value: dashboard.severity.critical || 0,
                    icon: Target,
                    foot: "Findings at critical severity",
                    color: "critical-stat",
                  },
                  {
                    label: "Verified remediations",
                    value: dashboard.verified,
                    icon: ShieldCheck,
                    foot: `${dashboard.active} findings still active`,
                    color: "success-stat",
                  },
                  {
                    label: "Overdue tasks",
                    value: dashboard.overdue,
                    icon: Clock3,
                    foot: "Past remediation deadline",
                    color: "warning-stat",
                  },
                ].map((stat) => (
                  <section
                    className={`stat-card ${stat.color}`}
                    key={stat.label}
                  >
                    <div>
                      <span>{stat.label}</span>
                      <stat.icon size={17} />
                    </div>
                    <strong>{stat.value.toLocaleString()}</strong>
                    <p>{stat.foot}</p>
                  </section>
                ))}
              </div>
              <div className="charts-grid">
                <section className="panel">
                  <div className="panel-heading">
                    <div>
                      <h2>
                        Risk trajectory{" "}
                        <span className="info-tag">CUSTOM PRIORITY</span>
                      </h2>
                      <p>Aggregate active risk from recorded assessments</p>
                    </div>
                    <span className="chart-legend">
                      <i />
                      Recorded history
                    </span>
                  </div>
                  <RiskChart trend={dashboard.trend} />
                  <div className="chart-footer">
                    <span>
                      <Activity size={14} />
                      Current aggregate priority
                    </span>
                    <strong>
                      {dashboard.risk_total.toLocaleString()}{" "}
                      <span>points</span>
                    </strong>
                  </div>
                </section>
                <section className="panel severity-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Severity distribution</h2>
                      <p>Across all recorded findings</p>
                    </div>
                    <Shield size={18} />
                  </div>
                  <div className="severity-body">
                    <div
                      className="donut"
                      style={{
                        background: dashboard.total
                          ? `conic-gradient(${(() => {
                              let current = 0;
                              return levels
                                .map((level) => {
                                  const start = current;
                                  current +=
                                    ((dashboard.severity[level] || 0) /
                                      dashboard.total) *
                                    100;
                                  return `var(--${level}) ${start}% ${current}%`;
                                })
                                .join(",");
                            })()})`
                          : "var(--border)",
                      }}
                    >
                      <div>
                        <strong>{dashboard.total}</strong>
                        <span>FINDINGS</span>
                      </div>
                    </div>
                    <div className="severity-legend">
                      {levels
                        .filter(
                          (level) =>
                            ["critical", "high", "medium", "low"].includes(
                              level,
                            ) || dashboard.severity[level],
                        )
                        .map((level) => (
                          <button
                            key={level}
                            onClick={() => {
                              navigate("Vulnerabilities");
                              setSeverity(level);
                            }}
                          >
                            <span>
                              <i style={{ background: `var(--${level})` }} />
                              {titleCase(level)}
                            </span>
                            <strong>{dashboard.severity[level] || 0}</strong>
                          </button>
                        ))}
                    </div>
                  </div>
                  <div className="panel-note">
                    Severity uses configured thresholds, not custom priority.
                  </div>
                </section>
              </div>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>
                      Priority findings{" "}
                      <span className="count-pill">{total}</span>
                    </h2>
                    <p>Highest custom priority in your inventory</p>
                  </div>
                  <button
                    className="text-button"
                    onClick={() => navigate("Vulnerabilities")}
                  >
                    View inventory <ArrowRight size={15} />
                  </button>
                </div>
                {findingTable(true)}
              </section>
              <div className="bottom-grid">
                <section className="panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Exposure by asset</h2>
                      <p>Active findings across your environment</p>
                    </div>
                    <Server size={17} />
                  </div>
                  <div className="asset-bars">
                    {dashboard.asset_distribution.length ? (
                      dashboard.asset_distribution.slice(0, 5).map((entry) => (
                        <div className="bar-row" key={entry.asset}>
                          <span>
                            <Server size={13} />
                            {entry.asset}
                          </span>
                          <div>
                            <i
                              style={{
                                width: `${(entry.count / Math.max(...dashboard.asset_distribution.map((item) => item.count), 1)) * 100}%`,
                              }}
                            />
                          </div>
                          <strong>{entry.count}</strong>
                        </div>
                      ))
                    ) : (
                      <Empty>No active asset exposure.</Empty>
                    )}
                  </div>
                </section>
                <section className="panel integration-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Intelligence pipeline</h2>
                      <p>Your connection to authoritative CVE data</p>
                    </div>
                    <Globe2 size={18} />
                  </div>
                  <div className="integration-status">
                    <span className="nvd-icon">
                      <Database size={24} />
                    </span>
                    <div>
                      <strong>NIST NVD</strong>
                      <span>CVE API 2.0</span>
                    </div>
                    <Badge
                      value={sync?.last_success ? "verified" : "unknown"}
                    />
                  </div>
                  <div className="integration-lines">
                    <span>
                      Last successful sync
                      <strong>{date(sync?.last_success || null)}</strong>
                    </span>
                    <span>
                      API access
                      <strong>
                        {sync?.api_key_configured
                          ? "Authenticated"
                          : "Public rate limit"}
                      </strong>
                    </span>
                    <span>
                      Data status
                      <strong>
                        {sync?.last_error
                          ? "Needs attention"
                          : sync?.running
                            ? "Synchronizing"
                            : sync?.requested
                              ? "Queued"
                              : sync?.last_success
                                ? "Connected"
                                : "Awaiting first sync"}
                      </strong>
                    </span>
                  </div>
                  <button
                    className="text-button"
                    onClick={() => navigate("CVE intelligence")}
                  >
                    Explore CVE intelligence <ArrowRight size={14} />
                  </button>
                </section>
              </div>
            </>
          )}
          {(page === "Vulnerabilities" || page === "Remediation") && (
            <>
              {page === "Remediation" && (
                <div className="summary-strip">
                  <span>
                    <Clock3 size={17} /> {dashboard?.overdue || 0} overdue
                  </span>
                  <span>
                    <CheckCheck size={17} /> {dashboard?.verified || 0} verified
                  </span>
                  <span>
                    <Activity size={17} /> Mean time to remediate:{" "}
                    {dashboard?.average_remediation_days ?? "—"} days
                  </span>
                </div>
              )}
              <section className="panel">
                {filterBar}
                {findingTable()}
                <div className="pagination">
                  <span>
                    {total} findings · Page {listPage} of{" "}
                    {Math.max(1, Math.ceil(total / 15))}
                  </span>
                  <div>
                    <button
                      className="secondary"
                      aria-label="Previous page"
                      disabled={listPage === 1}
                      onClick={() => setListPage(listPage - 1)}
                    >
                      <ChevronLeft size={15} />
                    </button>
                    <button
                      className="secondary"
                      aria-label="Next page"
                      disabled={listPage * 15 >= total}
                      onClick={() => setListPage(listPage + 1)}
                    >
                      <ChevronRight size={15} />
                    </button>
                  </div>
                </div>
              </section>
            </>
          )}
          {page === "Assets" && (
            <div className="asset-grid">
              {assets.length ? (
                assets.map((asset) => (
                  <section className="panel asset-card" key={asset.id}>
                    <div className="asset-card-top">
                      <span className="asset-icon">
                        <Server size={24} />
                      </span>
                      <span className={`exposure ${asset.exposure}`}>
                        {asset.exposure === "internet" ? (
                          <Globe2 size={12} />
                        ) : (
                          <LockKeyhole size={12} />
                        )}{" "}
                        {titleCase(asset.exposure)}
                      </span>
                    </div>
                    <h2>{asset.name}</h2>
                    <p className="muted">
                      {asset.category} · {asset.owner || "No owner recorded"}
                    </p>
                    <div className="asset-criticality">
                      <span>Business criticality</span>
                      <div>
                        {[1, 2, 3, 4, 5].map((value) => (
                          <i
                            key={value}
                            className={
                              asset.criticality >= value ? "filled" : ""
                            }
                          />
                        ))}
                      </div>
                      <strong>{asset.criticality}/5</strong>
                    </div>
                    <div className="asset-card-actions">
                      <button
                        className="text-button"
                        onClick={() => {
                          navigate("Vulnerabilities");
                          setAssetFilter(String(asset.id));
                        }}
                      >
                        View findings <ArrowRight size={14} />
                      </button>
                      {canWrite && (
                        <button
                          className="text-button"
                          onClick={() => setEditAsset(asset)}
                        >
                          Edit
                        </button>
                      )}
                      <button
                        className="icon-button"
                        aria-label={`Report for ${asset.name}`}
                        onClick={() =>
                          action(
                            async () =>
                              setReport(
                                await api(`/assets/${asset.id}/report`),
                              ),
                            "Asset report loaded",
                          )
                        }
                      >
                        <FileCheck2 size={17} />
                      </button>
                    </div>
                  </section>
                ))
              ) : (
                <section className="panel">
                  <Empty>
                    Add your first asset to start tracking its security posture.
                  </Empty>
                </section>
              )}
            </div>
          )}
          {page === "Imports" && (
            <>
              <div className="import-grid">
                <section className="panel import-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Import scan results</h2>
                      <p>
                        Validated, deduplicated, and added to your inventory.
                      </p>
                    </div>
                    <FileUp size={20} />
                  </div>
                  <form
                    onSubmit={(event) => {
                      event.preventDefault();
                      if (!uploadFile) return;
                      const form = new FormData();
                      form.append("file", uploadFile);
                      action(async () => {
                        const result = await api<{
                          created: number;
                          duplicates: number;
                        }>(`/imports?adapter=${adapter}`, {
                          method: "POST",
                          body: form,
                        });
                        setNotice(
                          `${result.created} findings created, ${result.duplicates} duplicates observed`,
                        );
                        setUploadFile(null);
                        if (fileInput.current) fileInput.current.value = "";
                      }, "Import processed successfully");
                    }}
                  >
                    <label>
                      Import adapter
                      <select
                        value={adapter}
                        onChange={(event) => setAdapter(event.target.value)}
                      >
                        <option value="generic-json">
                          Generic JSON · schema 1.0
                        </option>
                        <option value="generic-csv">
                          Generic CSV · schema 1.0
                        </option>
                      </select>
                    </label>
                    <label className="dropzone">
                      <FileUp size={30} />
                      <strong>
                        {uploadFile
                          ? uploadFile.name
                          : "Choose a scan result file"}
                      </strong>
                      <span>
                        UTF-8 {adapter === "generic-json" ? "JSON" : "CSV"} ·
                        Maximum 2 MiB · 1,000 findings
                      </span>
                      <input
                        ref={fileInput}
                        aria-label="Scan result file"
                        type="file"
                        accept={adapter === "generic-json" ? ".json" : ".csv"}
                        disabled={!canWrite}
                        onChange={(event) =>
                          setUploadFile(event.target.files?.[0] || null)
                        }
                      />
                    </label>
                    <button
                      className="primary full"
                      disabled={!uploadFile || busy || !canWrite}
                    >
                      <FileUp size={16} />
                      Validate & import findings
                    </button>
                  </form>
                </section>
                <section className="panel schema-panel">
                  <span className="eyebrow">IMPORT CONTRACT</span>
                  <h2>Structured data. Trusted workflow.</h2>
                  <p>
                    Assets must exist before import. CVE IDs deduplicate across
                    scanner sources; non-CVE findings require a
                    namespace-qualified external ID.
                  </p>
                  <pre>{`{\n  "schema_version": "1.0",\n  "findings": [{\n    "asset": "server-01",\n    "cve_id": "CVE-2021-44228",\n    "title": "Log4Shell",\n    "cvss_score": 10,\n    "locator": "tcp/443",\n    "source": "your-scanner"\n  }]\n}`}</pre>
                  <span className="safe-note">
                    <ShieldCheck size={16} />
                    Data only. Files are never executed.
                  </span>
                </section>
              </div>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Import history</h2>
                    <p>Each batch is validated and processed atomically.</p>
                  </div>
                  <span className="count-pill">{imports.length}</span>
                </div>
                {imports.length ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>File</th>
                          <th>Adapter</th>
                          <th>Status</th>
                          <th>Created</th>
                          <th>Duplicates</th>
                          <th>Imported</th>
                        </tr>
                      </thead>
                      <tbody>
                        {imports.map((job) => (
                          <tr key={job.id}>
                            <td>
                              {job.filename}
                              {job.error && (
                                <span className="subline danger-text">
                                  {job.error}
                                </span>
                              )}
                            </td>
                            <td className="mono muted">{job.adapter}</td>
                            <td>
                              <Badge value={job.status} />
                            </td>
                            <td>{job.created_count}</td>
                            <td>{job.duplicate_count}</td>
                            <td className="muted">{date(job.created_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <Empty>No import jobs yet.</Empty>
                )}
              </section>
            </>
          )}
          {page === "CVE intelligence" && (
            <>
              <div className="summary-strip">
                <span>
                  <Database size={18} /> {cveTotal.toLocaleString()} matching
                  CVE records
                </span>
                <span>Last sync: {date(sync?.last_success || null)}</span>
                {user.role === "admin" && (
                  <button
                    className="secondary"
                    disabled={busy || sync?.requested || sync?.running}
                    onClick={() =>
                      action(
                        () => api("/sync", { method: "POST" }),
                        "Synchronization queued for the worker",
                      )
                    }
                  >
                    <RefreshCw size={14} />
                    {sync?.requested ? "Sync queued" : "Request sync"}
                  </button>
                )}
              </div>
              {sync?.last_error && (
                <div className="error">{sync.last_error}</div>
              )}
              <section className="panel">
                <div className="filter-bar">
                  <div className="search-input">
                    <Search size={16} />
                    <input
                      aria-label="Search CVE intelligence"
                      placeholder="Search CVE ID or description…"
                      value={query}
                      onChange={(event) => {
                        setQuery(event.target.value);
                        setCvePage(1);
                      }}
                    />
                  </div>
                  <span className="muted">
                    Source: NIST NVD · No simulated integration
                  </span>
                </div>
                {cves.length ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>CVE identifier</th>
                          <th>Description</th>
                          <th>CVSS</th>
                          <th>NVD severity</th>
                          <th>Modified</th>
                        </tr>
                      </thead>
                      <tbody>
                        {cves.map((cve) => (
                          <tr key={cve.id}>
                            <td>
                              <button
                                className="table-title mono"
                                onClick={() => openCVE(cve.id)}
                              >
                                {cve.id}
                              </button>
                              <span className="subline">{cve.nvd_status}</span>
                            </td>
                            <td className="description-cell">
                              {cve.description}
                            </td>
                            <td>
                              {cve.cvss_score ?? "—"}
                              <span className="subline">
                                {cve.cvss_version
                                  ? `v${cve.cvss_version}`
                                  : "Unscored"}
                              </span>
                            </td>
                            <td>
                              <Badge value={cve.severity} />
                            </td>
                            <td className="muted">{date(cve.modified_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <Empty>
                    No matching NVD records. Start the worker and request
                    synchronization; imported CVEs may await enrichment.
                  </Empty>
                )}
                <div className="pagination">
                  <span>Page {cvePage}</span>
                  <div>
                    <button
                      className="secondary"
                      disabled={cvePage === 1}
                      onClick={() => setCvePage(cvePage - 1)}
                    >
                      <ChevronLeft size={15} />
                      Previous
                    </button>
                    <button
                      className="secondary"
                      disabled={cvePage * 50 >= cveTotal}
                      onClick={() => setCvePage(cvePage + 1)}
                    >
                      Next
                      <ChevronRight size={15} />
                    </button>
                  </div>
                </div>
              </section>
            </>
          )}
          {page === "Reports" && dashboard && (
            <>
              <div className="report-banner">
                <div>
                  <span className="eyebrow">SECURITY POSTURE REPORT</span>
                  <h2>Evidence for your next security review.</h2>
                  <p>
                    Export the current inventory or explore the metrics that
                    drive remediation.
                  </p>
                </div>
                <a className="primary" href="/api/reports/export">
                  <ArrowDownToLine size={17} />
                  Export findings CSV
                </a>
              </div>
              <div className="stats-grid">
                <section className="stat-card">
                  <div>
                    Mean remediation time
                    <Clock3 size={18} />
                  </div>
                  <strong>
                    {dashboard.average_remediation_days ?? "—"}
                    <small> days</small>
                  </strong>
                  <p>First observation → latest verification</p>
                </section>
                <section className="stat-card success-stat">
                  <div>
                    Verified rate
                    <ShieldCheck size={18} />
                  </div>
                  <strong>
                    {dashboard.total
                      ? Math.round((dashboard.verified / dashboard.total) * 100)
                      : 0}
                    <small>%</small>
                  </strong>
                  <p>Of all recorded findings</p>
                </section>
                <section className="stat-card">
                  <div>
                    Risk accepted
                    <Shield size={18} />
                  </div>
                  <strong>{dashboard.accepted}</strong>
                  <p>Excluded from active aggregate risk</p>
                </section>
                <section className="stat-card warning-stat">
                  <div>
                    Active exposure
                    <Activity size={18} />
                  </div>
                  <strong>{dashboard.active}</strong>
                  <p>Open, in progress, and mitigated</p>
                </section>
              </div>
              <div className="bottom-grid">
                <section className="panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Vulnerability aging</h2>
                      <p>Active findings, measured from first observation</p>
                    </div>
                    <Clock3 size={18} />
                  </div>
                  <div className="asset-bars">
                    {["0–7 days", "8–30 days", "31–90 days", "90+ days"].map(
                      (bucket) => (
                        <div className="bar-row" key={bucket}>
                          <span>{bucket}</span>
                          <div>
                            <i
                              style={{
                                width: `${((dashboard.aging[bucket] || 0) / Math.max(...Object.values(dashboard.aging), 1)) * 100}%`,
                              }}
                            />
                          </div>
                          <strong>{dashboard.aging[bucket] || 0}</strong>
                        </div>
                      ),
                    )}
                  </div>
                </section>
                <section className="panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Remediation performance</h2>
                      <p>By current assignee, not historical attribution</p>
                    </div>
                    <CheckCheck size={18} />
                  </div>
                  {dashboard.performance.length ? (
                    <div className="table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>Team member</th>
                            <th>Assigned</th>
                            <th>Verified</th>
                            <th>Overdue</th>
                          </tr>
                        </thead>
                        <tbody>
                          {dashboard.performance.map((member) => (
                            <tr key={member.name}>
                              <td>{member.name}</td>
                              <td>{member.assigned}</td>
                              <td>{member.verified}</td>
                              <td className="danger-text">{member.overdue}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <Empty>Assign findings to measure team performance.</Empty>
                  )}
                </section>
              </div>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Asset-level reports</h2>
                    <p>A focused view of each system's security posture</p>
                  </div>
                </div>
                <div className="asset-report-list">
                  {assets.map((asset) => (
                    <button
                      key={asset.id}
                      onClick={() =>
                        action(
                          async () =>
                            setReport(await api(`/assets/${asset.id}/report`)),
                          "Asset report loaded",
                        )
                      }
                    >
                      <Server size={17} />
                      {asset.name}
                      <ArrowUpRight size={16} />
                    </button>
                  ))}
                </div>
              </section>
            </>
          )}
          {page === "Settings" && (
            <>
              <div className="import-grid">
                <section className="panel settings-panel">
                  <h2>Risk prioritization policy</h2>
                  <p className="muted">
                    Custom priority is not CVSS. Changes append risk assessments
                    for every finding.
                  </p>
                  {policy && (
                    <form
                      key={policy.version}
                      onSubmit={(event) => {
                        event.preventDefault();
                        const data = new FormData(event.currentTarget);
                        const body = Object.fromEntries(
                          [...data.entries()].map(([key, value]) => [
                            key,
                            Number(value),
                          ]),
                        );
                        action(
                          () =>
                            api("/policy", {
                              method: "PUT",
                              body: JSON.stringify(body),
                            }),
                          "Policy updated and findings reassessed",
                        );
                      }}
                    >
                      <div className="form-grid">
                        {(
                          [
                            "low",
                            "medium",
                            "high",
                            "critical",
                            "internet_multiplier",
                            "unknown_baseline",
                          ] as const
                        ).map((field) => (
                          <label key={field}>
                            {titleCase(field)}
                            <input
                              name={field}
                              type="number"
                              step="0.1"
                              min={
                                field === "internet_multiplier"
                                  ? 1
                                  : field === "unknown_baseline"
                                    ? 0
                                    : 0.1
                              }
                              max={field === "internet_multiplier" ? 2 : 10}
                              defaultValue={policy[field]}
                              disabled={user.role !== "admin"}
                              required
                            />
                          </label>
                        ))}
                      </div>
                      <p className="formula">
                        priority = min(100, base × 10 × (0.6 + criticality ×
                        0.08) × exposure multiplier)
                      </p>
                      <button
                        className="primary"
                        disabled={busy || user.role !== "admin"}
                      >
                        <Check size={16} />
                        Save policy
                      </button>
                    </form>
                  )}
                </section>
                <section className="panel settings-panel">
                  <h2>Workspace access</h2>
                  <p className="muted">
                    Server-enforced roles. Administrators manage access;
                    analysts remediate; viewers observe.
                  </p>
                  {users.map((member) => (
                    <div className="member-row" key={member.id}>
                      <span className="avatar small">{member.name[0]}</span>
                      <div>
                        <strong>{member.name}</strong>
                        <span>{member.email}</span>
                      </div>
                      <span className="role-tag">
                        {member.active ? member.role : "disabled"}
                      </span>
                      {user.role === "admin" &&
                        member.id !== user.id &&
                        member.active && (
                          <button
                            className="text-button danger-text"
                            onClick={() => {
                              if (confirm(`Disable access for ${member.name}?`))
                                action(
                                  () =>
                                    api(`/users/${member.id}/disable`, {
                                      method: "POST",
                                    }),
                                  "Account disabled and sessions revoked",
                                );
                            }}
                          >
                            Disable
                          </button>
                        )}
                    </div>
                  ))}
                  {user.role === "admin" && (
                    <details>
                      <summary>Add team member</summary>
                      <form
                        onSubmit={(event) => {
                          event.preventDefault();
                          const form = event.currentTarget;
                          action(async () => {
                            await api("/users", {
                              method: "POST",
                              body: JSON.stringify(
                                Object.fromEntries(new FormData(form)),
                              ),
                            });
                            form.reset();
                          }, "Team member created");
                        }}
                      >
                        <label>
                          Name
                          <input name="name" required maxLength={100} />
                        </label>
                        <label>
                          Email
                          <input
                            name="email"
                            type="email"
                            required
                            maxLength={254}
                          />
                        </label>
                        <label>
                          Temporary password
                          <input
                            name="password"
                            type="password"
                            minLength={14}
                            maxLength={128}
                            required
                            autoComplete="new-password"
                          />
                        </label>
                        <label>
                          Role
                          <select name="role">
                            <option value="analyst">Analyst</option>
                            <option value="viewer">Viewer</option>
                            <option value="admin">Administrator</option>
                          </select>
                        </label>
                        <button className="primary" disabled={busy}>
                          <Plus size={16} />
                          Create user
                        </button>
                      </form>
                    </details>
                  )}
                </section>
              </div>
              {user.role === "admin" && (
                <section className="panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Audit trail</h2>
                      <p>
                        Latest 100 events · use paginated API for older records
                      </p>
                    </div>
                    <BookOpen size={18} />
                  </div>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Event</th>
                          <th>Actor ID</th>
                          <th>Target</th>
                          <th>Recorded</th>
                        </tr>
                      </thead>
                      <tbody>
                        {audit.map((entry) => (
                          <tr key={entry.id}>
                            <td className="mono">{entry.action}</td>
                            <td>{entry.actor_id ?? "System"}</td>
                            <td>{entry.target}</td>
                            <td className="muted">{date(entry.created_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}
            </>
          )}
          <footer>
            <span>
              <ShieldCheck size={13} />
              VulnWatch{" "}
              <span className="muted">
                / Defensive vulnerability management
              </span>
            </span>
            <span>Prioritize with context. Remediate with confidence.</span>
          </footer>
        </main>
      </div>
      {detail && (
        <Modal
          title="Finding details"
          error={error}
          close={() => setDetail(null)}
        >
          <div className="detail-title">
            <Badge value={detail.severity} />
            <span className="mono muted">
              {detail.cve_id || `FINDING-${detail.id}`}
            </span>
            <h2>{detail.title}</h2>
            <p>
              {detail.description || "No description provided by the scanner."}
            </p>
          </div>
          <div className="detail-metrics">
            <div>
              <span>CVSS base score</span>
              <strong>{detail.cvss_score ?? "Unknown"}</strong>
              <small>Source: {detail.score_source}</small>
            </div>
            <div>
              <span>Custom priority / 100</span>
              <strong>{detail.risk_score}</strong>
              <small>Not an official CVSS score</small>
            </div>
            <div>
              <span>Status</span>
              <Badge value={detail.status} />
              <small>{detail.asset.name}</small>
            </div>
          </div>
          <dl className="detail-facts">
            <dt>First / last seen</dt>
            <dd>
              {date(detail.first_seen)} / {date(detail.last_seen)}
            </dd>
            <dt>Observations</dt>
            <dd>{detail.occurrences}</dd>
            <dt>Source / locator</dt>
            <dd>
              {detail.source} / {detail.locator || "Not specified"}
            </dd>
            <dt>Deadline</dt>
            <dd className={detail.overdue ? "danger-text" : ""}>
              {date(detail.due_at)}
            </dd>
          </dl>
          {detail.cve_id && (
            <button
              className="text-button"
              onClick={() => openCVE(detail.cve_id!)}
            >
              View authoritative CVE record <ArrowUpRight size={15} />
            </button>
          )}
          {canWrite && (
            <form
              key={`${detail.id}-${detail.revision}`}
              className="workflow-form"
              onSubmit={(event) => {
                event.preventDefault();
                const form = new FormData(event.currentTarget);
                const deadline = String(form.get("due_at"));
                const body = {
                  revision: detail.revision,
                  status: form.get("status"),
                  assignee_id: form.get("assignee_id")
                    ? Number(form.get("assignee_id"))
                    : null,
                  due_at: deadline
                    ? new Date(`${deadline}T23:59:00Z`).toISOString()
                    : null,
                  kind: form.get("kind"),
                  note: form.get("note"),
                };
                action(async () => {
                  await api(`/findings/${detail.id}`, {
                    method: "PATCH",
                    body: JSON.stringify(body),
                  });
                  setDetail(await api<Finding>(`/findings/${detail.id}`));
                }, "Remediation update recorded");
              }}
            >
              <h3>Update remediation</h3>
              <div className="form-grid">
                <label>
                  Status
                  <select
                    aria-label="Status"
                    name="status"
                    defaultValue={detail.status}
                  >
                    {[detail.status, ...transitions[detail.status]]
                      .filter(
                        (value) =>
                          value !== "accepted" || user.role === "admin",
                      )
                      .map((value) => (
                        <option key={value} value={value}>
                          {titleCase(value)}
                        </option>
                      ))}
                  </select>
                </label>
                <label>
                  Assigned to
                  <select
                    aria-label="Assigned to"
                    name="assignee_id"
                    defaultValue={detail.assignee_id || ""}
                  >
                    <option value="">Unassigned</option>
                    {users
                      .filter(
                        (member) => member.active && member.role !== "viewer",
                      )
                      .map((member) => (
                        <option key={member.id} value={member.id}>
                          {member.name}
                        </option>
                      ))}
                  </select>
                </label>
                <label>
                  Due date (UTC)
                  <input
                    type="date"
                    name="due_at"
                    defaultValue={detail.due_at?.slice(0, 10) || ""}
                  />
                </label>
                <label>
                  Activity type
                  <select aria-label="Activity type" name="kind">
                    <option value="note">Remediation note</option>
                    <option value="mitigation">Mitigation evidence</option>
                    <option value="verification">Verification evidence</option>
                  </select>
                </label>
              </div>
              <label>
                Notes / evidence
                <textarea
                  name="note"
                  placeholder="Document the action taken and verification evidence…"
                  required
                  maxLength={5000}
                  rows={3}
                />
              </label>
              <button className="primary" disabled={busy}>
                <Check size={16} />
                Record update
              </button>
            </form>
          )}
          <div className="history">
            <h3>Finding history</h3>
            {detail.history?.map((entry, index) => (
              <div key={index}>
                <i />
                <span>
                  <strong>{titleCase(entry.to_status)}</strong>
                  <small>{date(entry.created_at)}</small>
                  <p>{entry.note}</p>
                </span>
              </div>
            ))}
            <h3>Remediation activity</h3>
            {detail.activities?.length ? (
              detail.activities.map((entry, index) => (
                <div key={index}>
                  <i />
                  <span>
                    <strong>{titleCase(entry.kind)}</strong>
                    <small>{date(entry.created_at)}</small>
                    <p>{entry.note}</p>
                  </span>
                </div>
              ))
            ) : (
              <p className="muted">No remediation activity recorded.</p>
            )}
          </div>
        </Modal>
      )}
      {cveDetail && (
        <Modal title={cveDetail.id} close={() => setCveDetail(null)}>
          <div className="detail-title">
            <Badge value={cveDetail.severity} />
            <span className="muted">{cveDetail.nvd_status}</span>
            <p>{cveDetail.description}</p>
          </div>
          <div className="detail-metrics">
            <div>
              <span>CVSS base score</span>
              <strong>{cveDetail.cvss_score ?? "Unknown"}</strong>
              <small>Version {cveDetail.cvss_version || "not supplied"}</small>
            </div>
            <div>
              <span>Published</span>
              <strong className="date-metric">
                {date(cveDetail.published_at)}
              </strong>
            </div>
            <div>
              <span>Last modified</span>
              <strong className="date-metric">
                {date(cveDetail.modified_at)}
              </strong>
            </div>
          </div>
          {cveDetail.cvss_vector && <pre>{cveDetail.cvss_vector}</pre>}
          <h3>Affected products / version boundaries</h3>
          {cveDetail.affected_products?.length ? (
            cveDetail.affected_products.map((product, index) => (
              <pre key={index}>{JSON.stringify(product, null, 2)}</pre>
            ))
          ) : (
            <p className="muted">
              No CPE applicability supplied yet. This is not proof an asset is
              unaffected.
            </p>
          )}
          <h3>Authoritative references</h3>
          {cveDetail.references?.map((reference, index) => (
            <a
              className="reference"
              key={index}
              href={reference.url}
              target="_blank"
              rel="noopener noreferrer"
            >
              {reference.url}
              <ArrowUpRight size={14} />
            </a>
          ))}
        </Modal>
      )}
      {(newAsset || editAsset) && (
        <Modal
          error={error}
          title={editAsset ? "Edit asset" : "Add asset"}
          close={() => {
            setNewAsset(false);
            setEditAsset(null);
          }}
        >
          <form
            onSubmit={(event) => {
              event.preventDefault();
              const form = new FormData(event.currentTarget);
              const body = {
                ...Object.fromEntries(form),
                criticality: Number(form.get("criticality")),
              };
              action(async () => {
                await api(editAsset ? `/assets/${editAsset.id}` : "/assets", {
                  method: editAsset ? "PUT" : "POST",
                  body: JSON.stringify(body),
                });
                setNewAsset(false);
                setEditAsset(null);
              }, "Asset saved");
            }}
          >
            <label>
              Asset identifier
              <input
                name="name"
                required
                pattern="[a-zA-Z0-9][a-zA-Z0-9._:/\-]*"
                maxLength={200}
                placeholder="server-01"
                defaultValue={editAsset?.name}
                readOnly={!!editAsset}
              />
            </label>
            <label>
              Category
              <input
                name="category"
                required
                maxLength={100}
                defaultValue={editAsset?.category || "Server"}
              />
            </label>
            <div className="form-grid">
              <label>
                Business criticality
                <select
                  name="criticality"
                  defaultValue={editAsset?.criticality || 3}
                >
                  {[1, 2, 3, 4, 5].map((value) => (
                    <option key={value} value={value}>
                      {value} —{" "}
                      {
                        [
                          "Low",
                          "Limited",
                          "Moderate",
                          "Important",
                          "Mission critical",
                        ][value - 1]
                      }
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Exposure
                <select
                  name="exposure"
                  defaultValue={editAsset?.exposure || "internal"}
                >
                  <option value="internal">Internal</option>
                  <option value="internet">Internet-facing</option>
                </select>
              </label>
            </div>
            <label>
              Owner
              <input
                name="owner"
                maxLength={100}
                defaultValue={editAsset?.owner}
                placeholder="Infrastructure team"
              />
            </label>
            <button className="primary full" disabled={busy}>
              <Check size={16} />
              Save asset
            </button>
          </form>
        </Modal>
      )}
      {report && (
        <Modal
          title={`Asset report · ${report.asset.name}`}
          close={() => setReport(null)}
        >
          <div className="detail-metrics">
            <div>
              <span>Total findings</span>
              <strong>{report.total}</strong>
            </div>
            <div>
              <span>Active findings</span>
              <strong>{report.active}</strong>
            </div>
            <div>
              <span>Overdue</span>
              <strong>{report.overdue}</strong>
            </div>
          </div>
          <RiskChart trend={report.trend} />
          <div className="summary-strip">
            Aggregate priority: {report.risk_total} · Verified:{" "}
            {report.verified} · Mean remediation:{" "}
            {report.average_remediation_days ?? "—"} days
          </div>
          <a
            className="primary"
            href={`/api/reports/export?asset_id=${report.asset.id}`}
          >
            <ArrowDownToLine size={16} />
            Export asset findings
          </a>
        </Modal>
      )}
    </div>
  );
}

export default App;
