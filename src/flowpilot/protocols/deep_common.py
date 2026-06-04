from __future__ import annotations

import ipaddress
import shutil
from pathlib import Path

from ..decode_as import tshark_decode_as_parameters
from ..models import FlowSummary


def tshark_path() -> str | None:
    path = shutil.which("tshark")
    if path:
        return path
    macos_app_path = Path("/Applications/Wireshark.app/Contents/MacOS/tshark")
    if macos_app_path.exists():
        return str(macos_app_path)
    return None


def field_command(
    tshark: str,
    capture_path: Path,
    display_filter: str,
    fields: list[str],
    *,
    occurrence: str = "f",
    aggregator: str | None = None,
) -> list[str]:
    command = [
        tshark,
        *tshark_decode_as_parameters(),
        "-r",
        str(capture_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        f"occurrence={occurrence}",
    ]
    if aggregator:
        command.extend(["-E", f"aggregator={aggregator}"])
    for field in fields:
        command.extend(["-e", field])
    return command


def parse_field_rows(output: str, fields: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in output.splitlines():
        values = line.split("\t")
        row = {
            field: values[index] if index < len(values) else ""
            for index, field in enumerate(fields)
        }
        row["src"] = row["ip.src"] or row["ipv6.src"]
        row["dst"] = row["ip.dst"] or row["ipv6.dst"]
        rows.append({key: value for key, value in row.items() if value != ""})
    return rows


def tcp_flow_filter(flow: FlowSummary) -> str:
    endpoint_filter = endpoint_filter_for_flow(flow)
    ports = [port for port in (flow.key.port_a, flow.key.port_b) if port is not None]
    if not ports:
        return f"{endpoint_filter} && tcp"
    port_filter = " && ".join(f"tcp.port == {port}" for port in sorted(set(ports)))
    return f"{endpoint_filter} && {port_filter}"


def udp_flow_filter(flow: FlowSummary) -> str:
    endpoint_filter = endpoint_filter_for_flow(flow)
    ports = [port for port in (flow.key.port_a, flow.key.port_b) if port is not None]
    if not ports:
        return f"{endpoint_filter} && udp"
    port_filter = " && ".join(f"udp.port == {port}" for port in sorted(set(ports)))
    return f"{endpoint_filter} && {port_filter}"


def endpoint_filter_for_flow(flow: FlowSummary) -> str:
    family = _endpoint_address_family(flow.key.endpoint_a, flow.key.endpoint_b)
    if family == 6:
        return f"(ipv6.addr == {flow.key.endpoint_a} && ipv6.addr == {flow.key.endpoint_b})"
    if family == 4:
        return f"(ip.addr == {flow.key.endpoint_a} && ip.addr == {flow.key.endpoint_b})"
    return (
        f"((ip.addr == {flow.key.endpoint_a} && ip.addr == {flow.key.endpoint_b}) || "
        f"(ipv6.addr == {flow.key.endpoint_a} && ipv6.addr == {flow.key.endpoint_b}))"
    )


def _endpoint_address_family(endpoint_a: str, endpoint_b: str) -> int | None:
    try:
        address_a = ipaddress.ip_address(endpoint_a)
        address_b = ipaddress.ip_address(endpoint_b)
    except ValueError:
        return None
    if address_a.version == address_b.version:
        return address_a.version
    return None
