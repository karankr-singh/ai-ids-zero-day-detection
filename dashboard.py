import time
from collections import deque
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box
from rich.progress_bar import ProgressBar
from rich.align import Align


console = Console()

# ── Colour palette ────────────────────────────────────────────────
C = {
    "cyan":     "bright_cyan",
    "green":    "bright_green",
    "red":      "bright_red",
    "orange":   "dark_orange",
    "yellow":   "bright_yellow",
    "purple":   "medium_purple",
    "blue":     "dodger_blue2",
    "dim":      "grey50",
    "white":    "white",
    "critical": "bright_red",
    "high":     "dark_orange",
    "medium":   "bright_yellow",
    "low":      "bright_cyan",
}

SEV_COLOUR = {
    "CRITICAL": C["critical"],
    "HIGH":     C["high"],
    "MEDIUM":   C["medium"],
    "LOW":      C["low"],
    "NORMAL":   C["green"],
}

SEV_BADGE = {
    "CRITICAL": "[bright_red]● CRITICAL[/]",
    "HIGH":     "[dark_orange]● HIGH    [/]",
    "MEDIUM":   "[bright_yellow]● MEDIUM  [/]",
    "LOW":      "[bright_cyan]● LOW     [/]",
}

SPARKLINE_CHARS = "▁▂▃▄▅▆▇█"


def spark(values: list, width: int = 30) -> str:
    """Turn a list of numbers into a one-line sparkline string."""
    if not values:
        return " " * width
    v = values[-width:]
    mx = max(v) or 1
    return "".join(SPARKLINE_CHARS[int(x / mx * 7)] for x in v)


class Dashboard:
    MAX_ALERTS   = 120
    MAX_TERM     = 60
    MAX_ACTIONS  = 40
    MAX_TRAFFIC  = 80

    def __init__(self):
        self._alerts   = deque(maxlen=self.MAX_ALERTS)
        self._term     = deque(maxlen=self.MAX_TERM)
        self._actions  = deque(maxlen=self.MAX_ACTIONS)

        # Rolling traffic counters (one entry per second)
        self._traffic_normal  = deque(maxlen=self.MAX_TRAFFIC)
        self._traffic_anomaly = deque(maxlen=self.MAX_TRAFFIC)
        self._tick_normal     = 0
        self._tick_anomaly    = 0
        self._last_tick       = time.time()

        self._stats = {
            "packets": 0, "alerts": 0,
            "accuracy": 0.0, "fpr": 0.0,
            "monitoring": False,
        }
        self._sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        self._proto_counts: dict = {}

        self._live = Live(
            self._build_layout(),
            console=console,
            refresh_per_second=4,
            screen=True,
        )
        self._live.start()
        self.log_system("AI-IDS v1.0 initialised", "green")
        self.log_system("Isolation Forest model loaded  (150 estimators)", "green")
        self.log_system("Attack simulator ready  (6 profiles)", "green")
        self.log_system("LLM reasoning engine initialised", "green")
        self.log_system("Awaiting start command...", "yellow")

    # ── Public update API ──────────────────────────────────────────
    def update_stats(self, stats: dict):
        self._stats.update(stats)
        self._refresh()

    def add_alert(self, alert: dict):
        self._alerts.appendleft(alert)
        sev = alert.get("severity", "LOW")
        self._sev_counts[sev] = self._sev_counts.get(sev, 0) + 1
        proto = alert.get("protocol", "TCP")
        self._proto_counts[proto] = self._proto_counts.get(proto, 0) + 1
        self._tick_anomaly += 1

        # Auto-response action log
        action_text = f"{alert.get('threat_type','?')} from {alert.get('src_ip','?')} — {alert.get('action','?')}"
        self._actions.appendleft((sev, action_text, alert.get("timestamp", "")))
        self._refresh()

    def add_normal_tick(self, count: int = 1):
        self._tick_normal += count
        now = time.time()
        if now - self._last_tick >= 1.0:
            self._traffic_normal.append(self._tick_normal)
            self._traffic_anomaly.append(self._tick_anomaly)
            self._tick_normal = self._tick_anomaly = 0
            self._last_tick = now

    def log_system(self, msg: str, colour: str = "dim"):
        ts = time.strftime("%H:%M:%S")
        self._term.append((ts, msg, colour))
        self._refresh()

    def close(self):
        self._live.stop()

    # ── Layout builder ─────────────────────────────────────────────
    def _build_layout(self) -> Layout:
        root = Layout(name="root")
        root.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=8),
        )
        root["body"].split_row(
            Layout(name="left",  ratio=3),
            Layout(name="right", ratio=2),
        )
        root["right"].split_column(
            Layout(name="spark",    ratio=3),
            Layout(name="severity", ratio=2),
            Layout(name="proto",    ratio=2),
        )
        root["footer"].split_row(
            Layout(name="actions", ratio=3),
            Layout(name="terminal", ratio=3),
        )
        self._layout = root
        return root

    def _refresh(self):
        L = self._layout
        L["header"].update(self._render_header())
        L["left"].update(self._render_alerts())
        L["spark"].update(self._render_sparklines())
        L["severity"].update(self._render_severity())
        L["proto"].update(self._render_proto())
        L["actions"].update(self._render_actions())
        L["terminal"].update(self._render_terminal())
        self._live.update(L)

    # ── Header ─────────────────────────────────────────────────────
    def _render_header(self) -> Panel:
        s = self._stats
        status_str = (
            f"[bright_green]● MONITORING[/]"
            if s["monitoring"] else
            "[grey50]○ OFFLINE[/]"
        )
        t = Table.grid(expand=True, padding=(0, 3))
        t.add_column(justify="left",   ratio=3)
        t.add_column(justify="center", ratio=1)
        t.add_column(justify="center", ratio=1)
        t.add_column(justify="center", ratio=1)
        t.add_column(justify="center", ratio=1)
        t.add_column(justify="right",  ratio=2)
        t.add_row(
            f"[bold bright_cyan]AI-IDS[/]  [grey50]Intrusion Detection System v1.0[/]",
            f"[grey50]PACKETS[/]\n[bold bright_cyan]{s['packets']:,}[/]",
            f"[grey50]ALERTS[/]\n[bold bright_red]{s['alerts']:,}[/]",
            f"[grey50]ACCURACY[/]\n[bold bright_green]{s['accuracy']*100:.1f}%[/]",
            f"[grey50]FALSE POS[/]\n[bold bright_yellow]{s['fpr']*100:.1f}%[/]",
            status_str,
        )
        return Panel(t, style="on grey7", border_style="bright_cyan", height=3)

    # ── Alert feed ─────────────────────────────────────────────────
    def _render_alerts(self) -> Panel:
        tbl = Table(
            box=box.SIMPLE_HEAD, expand=True,
            show_header=True, header_style="bold grey50",
            border_style="grey23",
        )
        tbl.add_column("SEV",      width=10)
        tbl.add_column("TIME",     width=9,  style="grey50")
        tbl.add_column("THREAT",   width=28)
        tbl.add_column("SRC → DST",          style="grey70", ratio=2)
        tbl.add_column("SCORE",    width=8,  justify="right", style="grey50")

        for a in list(self._alerts)[:30]:
            sev   = a.get("severity", "LOW")
            tbl.add_row(
                SEV_BADGE.get(sev, sev),
                a.get("timestamp", ""),
                f"[{SEV_COLOUR.get(sev, 'white')}]{a.get('threat_type','?')}[/]",
                f"{a.get('src_ip','?')} [grey50]→[/] {a.get('dst_ip','?')}:{a.get('protocol','?')}",
                f"{a.get('score', 0):.4f}",
            )

        if not self._alerts:
            tbl.add_row("—", "—", "[grey50]No alerts yet[/]", "", "")

        title = f"[bold bright_cyan]🔴 Live Alert Feed[/]  [grey50]{len(self._alerts)} total[/]"
        return Panel(tbl, title=title, border_style="grey23", padding=(0, 0))

    # ── Traffic sparklines ─────────────────────────────────────────
    def _render_sparklines(self) -> Panel:
        w = 50
        norm  = list(self._traffic_normal)
        anom  = list(self._traffic_anomaly)

        t = Text()
        t.append("Normal   [bright_green]", style="grey50")
        t.append(spark(norm, w), style="bright_green")
        t.append("\n")
        t.append("Anomaly  [bright_red]",   style="grey50")
        t.append(spark(anom, w), style="bright_red")

        total_n = sum(norm) or 1
        total_a = sum(anom)
        pct = total_a / (total_n + total_a) * 100 if (total_n + total_a) else 0
        t.append(f"\n\n[grey50]Anomaly rate:[/] [bright_yellow]{pct:.1f}%[/]")

        return Panel(t, title="[bold bright_cyan]📊 Traffic[/]",
                     border_style="grey23", padding=(1, 2))

    # ── Severity bar chart ─────────────────────────────────────────
    def _render_severity(self) -> Panel:
        rows = [
            ("CRITICAL", C["critical"], "■"),
            ("HIGH",     C["high"],     "■"),
            ("MEDIUM",   C["medium"],   "■"),
            ("LOW",      C["low"],      "■"),
        ]
        total = max(sum(self._sev_counts.values()), 1)
        t = Table.grid(expand=True, padding=(0, 1))
        t.add_column(width=9)
        t.add_column(ratio=1)
        t.add_column(width=5, justify="right")

        for label, colour, sym in rows:
            count = self._sev_counts.get(label, 0)
            bar_w = int(count / total * 20)
            bar   = f"[{colour}]{'█' * bar_w}{'░' * (20 - bar_w)}[/]"
            t.add_row(
                f"[{colour}]{label:<9}[/]",
                bar,
                f"[bold]{count}[/]",
            )
        return Panel(t, title="[bold bright_cyan]⚠️  Severity[/]",
                     border_style="grey23", padding=(0, 1))

    # ── Protocol table ─────────────────────────────────────────────
    def _render_proto(self) -> Panel:
        tbl = Table(box=None, expand=True, show_header=False, padding=(0, 1))
        tbl.add_column(width=8,  style="grey70")
        tbl.add_column(ratio=1)
        tbl.add_column(width=5, justify="right", style="bright_cyan")

        items = sorted(self._proto_counts.items(), key=lambda x: -x[1])[:6]
        total = max(sum(self._proto_counts.values()), 1)
        for proto, cnt in items:
            bar_w = int(cnt / total * 18)
            tbl.add_row(proto, f"[bright_cyan]{'▓' * bar_w}[/][grey23]{'░' * (18-bar_w)}[/]", str(cnt))

        if not items:
            tbl.add_row("[grey50]—[/]", "", "")

        return Panel(tbl, title="[bold bright_cyan]🌐 Protocols[/]",
                     border_style="grey23", padding=(0, 0))

    # ── Response actions ───────────────────────────────────────────
    def _render_actions(self) -> Panel:
        tbl = Table(box=None, expand=True, show_header=False, padding=(0, 1))
        tbl.add_column(width=10)
        tbl.add_column(ratio=1, style="grey70")
        tbl.add_column(width=9, style="grey50")

        for sev, text, ts in list(self._actions)[:8]:
            colour = SEV_COLOUR.get(sev, "white")
            tbl.add_row(
                f"[{colour}]{sev}[/]",
                text[:55],
                ts,
            )
        if not self._actions:
            tbl.add_row("[grey50]—[/]", "[grey50]No automated actions yet[/]", "")

        return Panel(tbl, title="[bold bright_cyan]⚙️  Response Actions[/]",
                     border_style="grey23", padding=(0, 0))

    # ── Terminal log ───────────────────────────────────────────────
    def _render_terminal(self) -> Panel:
        lines = list(self._term)[-10:]
        t = Text()
        for ts, msg, colour in lines:
            t.append(f"[{ts}] ", style="grey50")
            t.append(msg + "\n", style=colour)
        return Panel(t, title="[bold bright_cyan]💻 System Log[/]",
                     border_style="grey23", padding=(0, 1))
