"""Local Flask dashboard for the passive network traffic analyzer."""

from datetime import datetime, timezone
from io import BytesIO
from threading import RLock
from time import monotonic
from typing import Callable

from flask import Flask, jsonify, render_template, request, send_file
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from scapy.all import IFACES

from analyzer.capture import CaptureController
from analyzer.statistics import PacketStatistics


REPORT_RECORD_LIMIT = 10_000
EXCEL_MIME_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def list_interfaces() -> list[dict[str, str]]:
    """Return interface names and descriptions known to Scapy."""
    interfaces = []
    for interface in IFACES.values():
        name = str(interface.name)
        description = str(interface.description or name)
        address = str(getattr(interface, "ip", "") or "")
        interfaces.append({"name": name, "description": description, "address": address})
    return sorted(interfaces, key=lambda item: item["name"].lower())


class DashboardState:
    """Hold shared capture state while packet statistics remain thread-safe."""

    def __init__(
        self,
        interface_provider: Callable[[], list[dict[str, str]]],
        capture_factory: Callable[..., CaptureController],
    ) -> None:
        self.statistics = PacketStatistics(
            recent_limit=100,
            report_limit=REPORT_RECORD_LIMIT,
        )
        self.interface_provider = interface_provider
        self.capture_factory = capture_factory
        self.controller: CaptureController | None = None
        self.selected_interface: str | None = None
        self.session_interface: str | None = None
        self.session_started_at: datetime | None = None
        self.session_ended_at: datetime | None = None
        self.session_started_monotonic: float | None = None
        self.elapsed_seconds = 0.0
        self.lock = RLock()

    def capture_running(self) -> bool:
        with self.lock:
            return self.controller is not None and self.controller.is_running

    def finish_session(self) -> None:
        """Freeze elapsed time and set an end time once capture has stopped."""
        if self.session_started_at is None or self.session_ended_at is not None:
            return
        self.session_ended_at = datetime.now(timezone.utc)
        if self.session_started_monotonic is not None:
            self.elapsed_seconds = max(0.0, monotonic() - self.session_started_monotonic)
        self.session_started_monotonic = None

    def reset_session(self) -> None:
        """Clear the current session and its statistics."""
        self.statistics.reset()
        self.session_interface = None
        self.session_started_at = None
        self.session_ended_at = None
        self.session_started_monotonic = None
        self.elapsed_seconds = 0.0


def _write_text(cell, value: object) -> None:
    """Write captured data as an Excel string, never as a formula."""
    cell.value = "" if value is None else str(value)
    cell.data_type = "s"
    cell.number_format = "@"


def _build_excel_report(snapshot, state: DashboardState) -> BytesIO:
    """Build a report from bounded metadata summaries held in memory."""
    workbook = Workbook()
    summary = workbook.active
    summary.title = "Summary"
    packets_sheet = workbook.create_sheet("Packets")

    start_text = state.session_started_at.isoformat() if state.session_started_at else ""
    end_text = state.session_ended_at.isoformat() if state.session_ended_at else ""
    exported_count = len(snapshot.report_packets)
    omitted_count = snapshot.report_packets_omitted
    duration = max(0.0, state.elapsed_seconds)
    average_rate = snapshot.total_packets / duration if duration > 0 else 0.0
    interface_text = state.session_interface or "Scapy default interface"

    summary.append(["Network Traffic Analyzer — Session Report", ""])
    summary.append(["Session start (UTC)", start_text])
    summary.append(["Session end (UTC)", end_text])
    summary.append(["Duration (seconds)", duration])
    summary.append(["Interface", ""])
    _write_text(summary.cell(row=5, column=2), interface_text)
    summary.append(["Total packets observed", snapshot.total_packets])
    summary.append(["Packet records exported", exported_count])
    summary.append(["Packet records omitted (buffer limit)", omitted_count])
    summary.append(["Report record limit", REPORT_RECORD_LIMIT])
    summary.append(["Average packets per second", average_rate])
    summary.append(["TCP packets", snapshot.protocol_counts["TCP"]])
    summary.append(["UDP packets", snapshot.protocol_counts["UDP"]])
    summary.append(["ICMP packets", snapshot.protocol_counts["ICMP"]])
    summary.append(["Other packets", snapshot.protocol_counts["Other"]])
    summary.append([
        "Coverage note",
        (
            f"The export contains the latest {exported_count:,} metadata records; "
            f"{omitted_count:,} earlier records were discarded by the bounded report buffer."
            if omitted_count
            else f"All {exported_count:,} packet metadata records from this session are included."
        ),
    ])

    headers = [
        "Timestamp (UTC)", "Source IP", "Destination IP", "Source Port",
        "Destination Port", "Protocol", "Packet Length",
    ]
    packets_sheet.append(headers)
    for packet in snapshot.report_packets:
        row_number = packets_sheet.max_row + 1
        values = [
            packet["timestamp"],
            packet["source_ip"],
            packet["destination_ip"],
            packet["source_port"],
            packet["destination_port"],
            packet["protocol"],
            packet["packet_length"],
        ]
        for column_number, value in enumerate(values, start=1):
            _write_text(packets_sheet.cell(row=row_number, column=column_number), value)

    header_fill = PatternFill("solid", fgColor="17344D")
    header_font = Font(color="FFFFFF", bold=True)
    for sheet in (summary, packets_sheet):
        sheet.freeze_panes = "A2" if sheet is packets_sheet else "A2"
        for cell in sheet[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(vertical="center")
    summary.column_dimensions["A"].width = 38
    summary.column_dimensions["B"].width = 92
    for column, width in {"A": 27, "B": 25, "C": 25, "D": 16, "E": 19, "F": 14, "G": 17}.items():
        packets_sheet.column_dimensions[column].width = width
    packets_sheet.auto_filter.ref = packets_sheet.dimensions

    output = BytesIO()
    workbook.save(output)
    output.seek(0)
    return output


def create_app(
    interface_provider: Callable[[], list[dict[str, str]]] = list_interfaces,
    capture_factory: Callable[..., CaptureController] = CaptureController,
) -> Flask:
    """Create the web app; packet capture stays stopped until explicitly requested."""
    app = Flask(__name__)
    state = DashboardState(interface_provider, capture_factory)
    app.extensions["traffic_analyzer_state"] = state

    @app.get("/")
    def dashboard():
        return render_template("index.html")

    @app.get("/api/interfaces")
    def get_interfaces():
        try:
            return jsonify(interfaces=state.interface_provider())
        except Exception as error:
            app.logger.exception("Could not list capture interfaces")
            return jsonify(error=f"Could not list network interfaces: {error}"), 500

    @app.get("/api/stats")
    def get_stats():
        with state.lock:
            running = state.controller is not None and state.controller.is_running
            if not running:
                state.finish_session()
            duration = (
                max(0.0, monotonic() - state.session_started_monotonic)
                if running and state.session_started_monotonic is not None
                else state.elapsed_seconds
            )
            session_started_at = state.session_started_at
            session_ended_at = state.session_ended_at
            session_interface = state.session_interface
            selected_interface = state.selected_interface
            snapshot = state.statistics.snapshot()

        return jsonify(
            total_packets=snapshot.total_packets,
            protocol_counts=snapshot.protocol_counts,
            recent_packets=list(reversed(snapshot.recent_packets))[:50],
            capture_status="running" if running else "stopped",
            selected_interface=selected_interface,
            session_interface=session_interface,
            session_started_at=session_started_at.isoformat() if session_started_at else None,
            session_ended_at=session_ended_at.isoformat() if session_ended_at else None,
            duration_seconds=duration,
            report_record_limit=REPORT_RECORD_LIMIT,
            report_records_exportable=len(snapshot.report_packets),
            report_records_omitted=snapshot.report_packets_omitted,
            can_export=(not running and session_ended_at is not None and snapshot.total_packets > 0),
        )

    @app.post("/api/capture/start")
    def start_capture():
        body = request.get_json(silent=True) or {}
        interface_name = body.get("interface")
        if interface_name is not None and not isinstance(interface_name, str):
            return jsonify(error="Interface name must be text."), 400
        interface_name = interface_name or None

        try:
            available = state.interface_provider()
            available_names = {item["name"] for item in available}
        except Exception as error:
            app.logger.exception("Could not validate capture interface")
            return jsonify(error=f"Could not list network interfaces: {error}"), 500

        if interface_name is not None and interface_name not in available_names:
            return jsonify(error="That network interface is not available."), 400

        with state.lock:
            if state.controller is not None and state.controller.is_running:
                return jsonify(error="Packet capture is already running."), 409

            try:
                new_statistics = PacketStatistics(
                    recent_limit=100,
                    report_limit=REPORT_RECORD_LIMIT,
                )
                session_started_at = datetime.now(timezone.utc)
                session_started_monotonic = monotonic()
                controller = state.capture_factory(new_statistics, interface_name)
                controller.start()
                if not controller.is_running:
                    raise RuntimeError(
                        "Scapy did not start capture; check the interface and Npcap permissions."
                    )
            except Exception as error:
                app.logger.exception("Could not start packet capture")
                return jsonify(error=f"Could not start capture: {error}"), 500

            state.statistics = new_statistics
            state.session_started_at = session_started_at
            state.session_ended_at = None
            state.session_started_monotonic = session_started_monotonic
            state.elapsed_seconds = 0.0
            state.session_interface = interface_name
            state.controller = controller
            state.selected_interface = interface_name

        return jsonify(status="running", interface=interface_name), 200

    @app.post("/api/capture/stop")
    def stop_capture():
        with state.lock:
            controller = state.controller
            if controller is None:
                state.finish_session()
                return jsonify(status="stopped"), 200
            if not controller.is_running:
                state.finish_session()
                state.controller = None
                return jsonify(status="stopped"), 200

            try:
                controller.stop()
            except Exception as error:
                app.logger.exception("Could not stop packet capture")
                return jsonify(error=f"Could not stop capture: {error}"), 500

            state.finish_session()
            state.controller = None

        return jsonify(status="stopped"), 200

    @app.post("/api/stats/reset")
    def reset_statistics():
        with state.lock:
            if state.controller is not None and state.controller.is_running:
                return jsonify(error="Stop packet capture before resetting statistics."), 409
            state.controller = None
            state.reset_session()

        return jsonify(status="reset"), 200

    @app.get("/api/report/export")
    def export_report():
        with state.lock:
            running = state.controller is not None and state.controller.is_running
            if running:
                return jsonify(error="Stop packet capture before exporting a report."), 409
            state.finish_session()
            snapshot = state.statistics.snapshot()
            if state.session_ended_at is None or snapshot.total_packets == 0:
                return jsonify(error="A stopped capture session with packets is required to export."), 409
            output = _build_excel_report(snapshot, state)
            started = state.session_started_at or datetime.now(timezone.utc)

        filename = f"netscope_report_{started.strftime('%Y%m%d_%H%M%S')}.xlsx"
        return send_file(
            output,
            mimetype=EXCEL_MIME_TYPE,
            as_attachment=True,
            download_name=filename,
        )

    return app


app = create_app()


if __name__ == "__main__":
    # Keep the dashboard on this computer only; capture is started by the user.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
