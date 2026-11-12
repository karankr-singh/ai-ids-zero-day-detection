import time
from collections import deque

from rich import box
from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


console = Console()

PALETTE = {
    "cyan": "bright_cyan",
    "green": "bright_green",
    "red": "bright_red",
    "orange": "dark_orange",
    "yellow": "bright_yellow",
    "purple": "medium_purple",
    "blue": "dodger_blue2",
    "muted": "grey50",
    "white": "white",
}
SEVERITY_COLOURS = {
    "CRITICAL": PALETTE["red"],
    "HIGH": PALETTE["orange"],
    "MEDIUM": PALETTE["yellow"],
    "LOW": PALETTE["cyan"],
    "NORMAL": PALETTE["green"],
}
SPARKLINE_CHARS = "▁▂▃▄▅▆▇█"


def spark(values: list, width: int = 30) -> str:
    """Render a compact sparkline from recent per-second counts."""
    if not values:
        return " " * width
    recent = values[-width:]
    maximum = max(recent) or 1
    return "".join(
        SPARKLINE_CHARS[min(7, int(value / maximum * 7))]
        for value in recent
    ).rjust(width)


class Dashboard:
    """Rich terminal dashboard for passive monitoring and simulator runs."""

    MAX_ALERTS = 120
    MAX_TERM = 60
    MAX_ACTIONS = 40
    MAX_TRAFFIC = 80

    def __init__(self):
        self._alerts = deque(maxlen=self.MAX_ALERTS)
        self._term = deque(maxlen=self.MAX_TERM)
        self._actions = deque(maxlen=self.MAX_ACTIONS)

        self._traffic_normal = deque(maxlen=self.MAX_TRAFFIC)
        self._traffic_anomaly = deque(maxlen=self.MAX_TRAFFIC)
        self._tick_normal = 0
        self._tick_anomaly = 0
        self._last_tick = time.time()

        self._stats = {
            "packets": 0,
            "alerts": 0,
            "training_status": "synthetic baseline; not independently evaluated",
            "monitoring": False,
        }
        self._sev_counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
        }
        self._proto_counts = {}
        self._scenario = {
            "status": "STANDBY",
            "key": None,
            "label": "No active scenario",
            "description": "Start the simulator demo to display a scripted scenario.",
            "target": 0,
            "generated": 0,
            "candidates": 0,
        }

        self._layout = self._build_layout()
        self._live = Live(
            self._layout,
            console=console,
            refresh_per_second=4,
            screen=True,
            transient=False,
        )
        self._live.start()
        self.log_system("AI-IDS console initialised", "green")
        self.log_system("Detection scores are exploratory, not validated", "yellow")
        self.log_system("Waiting for traffic source...", "cyan")

    # Public update API
    def update_stats(self, stats: dict):
        self._stats.update(stats)
        self._refresh()

    def update_scenario(self, scenario: dict):
        """Set the currently demonstrated synthetic attack scenario."""
        self._scenario.update(scenario)
        self._refresh()

    def record_scenario_record(self, packet: dict, is_candidate: bool):
        """Count generated records belonging to the active scenario."""
        key = packet.get("pkt_type")
        if self._scenario.get("status") != "RUNNING" or key != self._scenario.get("key"):
            return
        self._scenario["generated"] += 1
        if is_candidate:
            self._scenario["candidates"] += 1
        self._refresh()

    def add_alert(self, alert: dict):
        self._alerts.appendleft(alert)
        severity = alert.get("severity", "LOW")
        self._sev_counts[severity] = self._sev_counts.get(severity, 0) + 1

        protocol = alert.get("protocol", "UNKNOWN")
        self._proto_counts[protocol] = self._proto_counts.get(protocol, 0) + 1
        self._record_traffic(anomaly=True)

        action = (
            f"{alert.get('threat_type', 'Unknown candidate')} | "
            f"{alert.get('src_ip', '?')} | "
            f"{alert.get('proposed_response', 'Investigate')}"
        )
        self._actions.appendleft(
            (severity, action, alert.get("timestamp", ""))
        )
        self._refresh()

    def _record_traffic(self, anomaly: bool, count: int = 1):
        if anomaly:
            self._tick_anomaly += count
        else:
            self._tick_normal += count

        now = time.time()
        if now - self._last_tick >= 1.0:
            self._traffic_normal.append(self._tick_normal)
            self._traffic_anomaly.append(self._tick_anomaly)
            self._tick_normal = 0
            self._tick_anomaly = 0
            self._last_tick = now

    def add_normal_tick(self, count: int = 1):
        self._record_traffic(anomaly=False, count=count)

    def log_system(self, msg: str, colour: str = "dim"):
        self._term.append((time.strftime("%H:%M:%S"), msg, colour))
        self._refresh()

    def close(self):
        self._live.stop()

    # Layout
    def _build_layout(self) -> Layout:
        root = Layout(name="root")
        root.split_column(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=10),
        )
        root["body"].split_row(
            Layout(name="feed", ratio=3),
            Layout(name="sidebar", ratio=2),
        )
        root["sidebar"].split_column(
            Layout(name="scenario", size=4),
            Layout(name="traffic", ratio=3),
            Layout(name="severity", ratio=2),
            Layout(name="protocols", ratio=2),
        )
        root["footer"].split_row(
            Layout(name="recommendations", ratio=3),
            Layout(name="system", ratio=2),
        )
        return root

    def _refresh(self):
        layout = self._layout
        layout["header"].update(self._render_header())
        layout["feed"].update(self._render_alerts())
        layout["scenario"].update(self._render_scenario())
        layout["traffic"].update(self._render_traffic())
        layout["severity"].update(self._render_severity())
        layout["protocols"].update(self._render_protocols())
        layout["recommendations"].update(self._render_recommendations())
        layout["system"].update(self._render_system_log())
        self._live.update(layout)

    # Header
    def _render_header(self) -> Panel:
        stats = self._stats
        phase = stats.get("phase", "standby")
        mode = stats.get("mode", "MONITORING")
        if phase == "learning":
            status = "[bright_yellow]● LEARNING BASELINE[/]"
        elif phase == "monitoring":
            colour = "bright_green" if mode == "SIMULATOR DEMO" else "bright_cyan"
            status = f"[{colour}]● {mode}[/]"
        else:
            status = "[grey50]○ STANDBY[/]"

        grid = Table.grid(expand=True, padding=(0, 2))
        grid.add_column(ratio=3)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right", ratio=2)
        grid.add_row(
            "[bold bright_cyan]AI-IDS[/]  [grey62]NETWORK SECURITY CONSOLE[/]",
            f"[grey50]PACKETS[/] [bold bright_cyan]{stats.get('packets', 0):,}[/]",
            f"[grey50]CANDIDATES[/] [bold bright_yellow]{stats.get('alerts', 0):,}[/]",
            status,
        )
        return Panel(
            grid,
            border_style="bright_cyan",
            style="on grey7",
            padding=(0, 1),
        )

    # Candidate anomaly feed
    def _render_alerts(self) -> Panel:
        table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            show_header=True,
            header_style="bold grey62",
            border_style="grey23",
            padding=(0, 1),
        )
        table.add_column("TRIAGE", width=10, no_wrap=True)
        table.add_column("TIME", width=9, style="grey50", no_wrap=True)
        table.add_column("HEURISTIC", min_width=18, ratio=2)
        table.add_column("SOURCE → DESTINATION", min_width=22, ratio=3)
        table.add_column("SCORE", width=8, justify="right", style="grey62")

        for alert in list(self._alerts)[:30]:
            severity = alert.get("severity", "LOW")
            colour = SEVERITY_COLOURS.get(severity, "white")
            table.add_row(
                f"[{colour}]● {severity}[/]",
                str(alert.get("timestamp", "")),
                f"[{colour}]{alert.get('threat_type', 'Unknown')}[/]",
                (
                    f"{alert.get('src_ip', '?')} [grey50]→[/] "
                    f"{alert.get('dst_ip', '?')}:{alert.get('dst_port', 0)} "
                    f"[grey50]{alert.get('protocol', '?')}[/]"
                ),
                f"{float(alert.get('score', 0)):.4f}",
            )

        if not self._alerts:
            table.add_row(
                "[grey50]—[/]", "—", "[grey50]No anomaly candidates yet[/]",
                "Waiting for packet records", "—"
            )

        title = (
            "[bold bright_cyan]ANOMALY CANDIDATES[/]  "
            "[grey50]Heuristic classifications · not confirmed incidents[/]"
        )
        return Panel(
            table,
            title=title,
            border_style="grey23",
            padding=(0, 0),
        )

    # Active simulator scenario
    def _render_scenario(self) -> Panel:
        scenario = self._scenario
        status = scenario.get("status", "STANDBY")
        if status == "RUNNING":
            status_colour = "bright_yellow"
            border_colour = "bright_yellow"
        elif status == "COMPLETE":
            status_colour = "bright_green"
            border_colour = "bright_green"
        else:
            status_colour = "grey50"
            border_colour = "grey23"

        generated = int(scenario.get("generated", 0))
        target = int(scenario.get("target", 0))
        candidates = int(scenario.get("candidates", 0))
        progress = min(1.0, generated / target) if target > 0 else 0.0
        filled = round(progress * 8)
        progress_bar = f"[bright_cyan]{'━' * filled}[/][grey23]{'─' * (8 - filled)}[/]"

        content = Text()
        label = str(scenario.get("label", "No active scenario"))
        content.append(label[:22], style="bold bright_cyan")
        content.append("  |  ")
        content.append(status, style=f"bold {status_colour}")
        content.append("\n")
        if target:
            content.append(f"RECORDS {generated}/{target}", style="bright_white")
            content.append("  ")
            content.append(f"CANDIDATES {candidates}", style="bright_yellow")
            content.append("  ")
            content.append("━" * filled, style="bright_cyan")
            content.append("─" * (8 - filled), style="grey23")
        else:
            content.append("Awaiting a scripted scenario", style="grey50")

        return Panel(
            content,
            title="[bold bright_cyan]ATTACK SCENARIO · SYNTHETIC[/]",
            border_style=border_colour,
            padding=(0, 1),
        )

    # Traffic overview
    def _render_traffic(self) -> Panel:
        normal = list(self._traffic_normal)
        anomaly = list(self._traffic_anomaly)
        normal_total = sum(normal)
        anomaly_total = sum(anomaly)
        observed = normal_total + anomaly_total
        ratio = anomaly_total / observed * 100 if observed else 0.0

        content = Text()
        model_status = str(self._stats.get("training_status", "unknown"))
        content.append("Model status  ", style="grey62")
        content.append(model_status, style="bright_yellow")
        content.append("\n\n")
        content.append("Observed as normal  ", style="grey62")
        content.append(spark(normal, 34), style="bright_green")
        content.append("\n")
        content.append("Anomaly candidates  ", style="grey62")
        content.append(spark(anomaly, 34), style="bright_yellow")
        content.append("\n\n")
        content.append("Recent-window candidate ratio  ", style="grey62")
        content.append(f"{ratio:.1f}%", style="bold bright_yellow")
        content.append("\n")
        content.append(
            "Not an accuracy, precision, or false-positive measurement.",
            style="italic grey50",
        )

        return Panel(
            content,
            title="[bold bright_cyan]TRAFFIC OVERVIEW[/]",
            border_style="grey23",
            padding=(1, 2),
        )

    # Triage distribution
    def _render_severity(self) -> Panel:
        labels = [
            ("CRITICAL", SEVERITY_COLOURS["CRITICAL"]),
            ("HIGH", SEVERITY_COLOURS["HIGH"]),
            ("MEDIUM", SEVERITY_COLOURS["MEDIUM"]),
            ("LOW", SEVERITY_COLOURS["LOW"]),
        ]
        total = max(sum(self._sev_counts.values()), 1)
        table = Table.grid(expand=True, padding=(0, 1))
        table.add_column(width=9)
        table.add_column(ratio=1)
        table.add_column(width=5, justify="right")

        for label, colour in labels:
            count = self._sev_counts.get(label, 0)
            filled = min(16, int(count / total * 16))
            bar = f"[{colour}]{'━' * filled}[/][grey23]{'─' * (16 - filled)}[/]"
            table.add_row(
                f"[{colour}]{label}[/]",
                bar,
                f"[bold]{count}[/]",
            )

        return Panel(
            table,
            title="[bold bright_cyan]HEURISTIC TRIAGE[/]",
            border_style="grey23",
            padding=(0, 1),
        )

    # Protocol distribution
    def _render_protocols(self) -> Panel:
        table = Table(
            box=None, expand=True, show_header=False, padding=(0, 1)
        )
        table.add_column(width=9, style="grey70")
        table.add_column(ratio=1)
        table.add_column(width=5, justify="right", style="bright_cyan")

        items = sorted(
            self._proto_counts.items(), key=lambda item: -item[1]
        )[:6]
        total = max(sum(self._proto_counts.values()), 1)
        for protocol, count in items:
            filled = min(16, int(count / total * 16))
            bar = (
                f"[bright_cyan]{'━' * filled}[/]"
                f"[grey23]{'─' * (16 - filled)}[/]"
            )
            table.add_row(protocol, bar, str(count))

        if not items:
            table.add_row("[grey50]No data[/]", "", "")

        return Panel(
            table,
            title="[bold bright_cyan]PROTOCOL MIX[/]",
            border_style="grey23",
            padding=(0, 0),
        )

    # Suggested responses
    def _render_recommendations(self) -> Panel:
        table = Table(
            box=None, expand=True, show_header=False, padding=(0, 1)
        )
        table.add_column(width=10)
        table.add_column(ratio=1)
        table.add_column(width=9, style="grey50")

        for severity, message, timestamp in list(self._actions)[:6]:
            colour = SEVERITY_COLOURS.get(severity, "white")
            table.add_row(
                f"[{colour}]{severity}[/]",
                message[:100],
                timestamp,
            )

        if not self._actions:
            table.add_row(
                "[grey50]—[/]",
                "[grey50]No suggested investigations yet[/]",
                "",
            )

        return Panel(
            table,
            title="[bold bright_cyan]SUGGESTED INVESTIGATIONS[/]  [grey50]No actions are executed[/]",
            border_style="grey23",
            padding=(0, 0),
        )

    # System log
    def _render_system_log(self) -> Panel:
        lines = list(self._term)[-7:]
        content = Text()
        for timestamp, message, colour in lines:
            content.append(f"[{timestamp}] ", style="grey50")
            content.append(message + "\n", style=colour)

        return Panel(
            content,
            title="[bold bright_cyan]SYSTEM LOG[/]",
            border_style="grey23",
            padding=(0, 1),
        )
