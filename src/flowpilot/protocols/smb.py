from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from ..models import CaptureSummary, FlowSummary, PacketObservation
from .deep_common import (
    DEFAULT_EVIDENCE_BATCH_SIZE,
    evidence_batch,
    field_command,
    parse_field_rows,
    tcp_flow_filter,
    tshark_path,
)

SMB_TRANSFER_FILE_MIN_BYTES = 1_048_576

SMB2_DEEP_FIELDS = [
    "frame.number",
    "frame.time_relative",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq",
    "tcp.ack",
    "tcp.len",
    "tcp.analysis.retransmission",
    "tcp.analysis.lost_segment",
    "tcp.analysis.out_of_order",
    "tcp.analysis.zero_window",
    "smb2.cmd",
    "smb2.flags.response",
    "smb2.msg_id",
    "smb2.sesid",
    "smb2.session_id",
    "smb2.tid",
    "smb2.nt_status",
    "smb2.credit.charge",
    "smb2.credit.request_response",
    "smb2.credits.requested",
    "smb2.credits.granted",
    "smb2.read_length",
    "smb2.read.length",
    "smb2.write_length",
    "smb2.write.count",
    "smb2.write.length",
    "smb2.data_length",
    "smb2.data_offset",
    "smb2.file_offset",
    "smb2.offset",
    "smb2.file_id",
    "smb2.filename",
]

SMB2_CREDIT_CHARGE_FIELD = "smb2.credit.charge"
SMB2_CREDIT_REQUEST_RESPONSE_FIELD = "smb2.credit.request_response"
SMB2_CREDIT_REQUEST_FIELDS = ("smb2.credits.requested", SMB2_CREDIT_REQUEST_RESPONSE_FIELD)
SMB2_CREDIT_GRANT_FIELDS = ("smb2.credits.granted", SMB2_CREDIT_REQUEST_RESPONSE_FIELD)
_TSHARK_FIELD_CACHE: dict[str, set[str]] = {}

SMB1_COMMAND_NAMES = {
    "0": "SMBmkdir",
    "0x00": "SMBmkdir",
    "1": "SMBrmdir",
    "0x01": "SMBrmdir",
    "2": "SMBopen",
    "0x02": "SMBopen",
    "3": "SMBcreate",
    "0x03": "SMBcreate",
    "4": "SMBclose",
    "0x04": "SMBclose",
    "5": "SMBflush",
    "0x05": "SMBflush",
    "6": "SMBunlink",
    "0x06": "SMBunlink",
    "7": "SMBmv",
    "0x07": "SMBmv",
    "8": "SMBgetatr",
    "0x08": "SMBgetatr",
    "9": "SMBsetatr",
    "0x09": "SMBsetatr",
    "10": "SMBread",
    "0x0a": "SMBread",
    "11": "SMBwrite",
    "0x0b": "SMBwrite",
    "12": "SMBlock",
    "0x0c": "SMBlock",
    "13": "SMBunlock",
    "0x0d": "SMBunlock",
    "14": "SMBctemp",
    "0x0e": "SMBctemp",
    "15": "SMBmknew",
    "0x0f": "SMBmknew",
    "16": "SMBchkpth",
    "0x10": "SMBchkpth",
    "17": "SMBexit",
    "0x11": "SMBexit",
    "18": "SMBlseek",
    "0x12": "SMBlseek",
    "19": "SMBlockread",
    "0x13": "SMBlockread",
    "20": "SMBwriteunlock",
    "0x14": "SMBwriteunlock",
    "37": "SMBtrans",
    "0x25": "SMBtrans",
    "45": "SMBopenX",
    "0x2d": "SMBopenX",
    "46": "SMBreadX",
    "0x2e": "SMBreadX",
    "47": "SMBwriteX",
    "0x2f": "SMBwriteX",
    "50": "SMBtrans2",
    "0x32": "SMBtrans2",
    "114": "SMBnegprot",
    "0x72": "SMBnegprot",
    "115": "SMBsesssetupX",
    "0x73": "SMBsesssetupX",
    "117": "SMBtconX",
    "0x75": "SMBtconX",
    "162": "SMBntcreateX",
    "0xa2": "SMBntcreateX",
}

SMB2_COMMAND_NAMES = {
    "0": "SMB2negprot",
    "0x0000": "SMB2negprot",
    "1": "SMB2sesssetup",
    "0x0001": "SMB2sesssetup",
    "2": "SMB2logoff",
    "0x0002": "SMB2logoff",
    "3": "SMB2tcon",
    "0x0003": "SMB2tcon",
    "4": "SMB2tdis",
    "0x0004": "SMB2tdis",
    "5": "SMB2create",
    "0x0005": "SMB2create",
    "6": "SMB2close",
    "0x0006": "SMB2close",
    "7": "SMB2flush",
    "0x0007": "SMB2flush",
    "8": "SMB2read",
    "0x0008": "SMB2read",
    "9": "SMB2write",
    "0x0009": "SMB2write",
    "10": "SMB2lock",
    "0x000a": "SMB2lock",
    "11": "SMB2ioctl",
    "0x000b": "SMB2ioctl",
    "12": "SMB2cancel",
    "0x000c": "SMB2cancel",
    "13": "SMB2echo",
    "0x000d": "SMB2echo",
    "14": "SMB2querydir",
    "0x000e": "SMB2querydir",
    "15": "SMB2changenotify",
    "0x000f": "SMB2changenotify",
    "16": "SMB2queryinfo",
    "0x0010": "SMB2queryinfo",
    "17": "SMB2setinfo",
    "0x0011": "SMB2setinfo",
    "18": "SMB2oplockbreak",
    "0x0012": "SMB2oplockbreak",
}

SMB_COMMAND_NAMES = SMB1_COMMAND_NAMES

SMB_STATUS_NAMES = {
    "0": "STATUS_SUCCESS",
    "0x00000000": "STATUS_SUCCESS",
    "0x00000103": "STATUS_PENDING",
    "0x0000010b": "STATUS_NOTIFY_CLEANUP",
    "0x0000010c": "STATUS_NOTIFY_ENUM_DIR",
    "0x4000000f": "STATUS_BUFFER_OVERFLOW",
    "0x80000005": "STATUS_BUFFER_OVERFLOW",
    "0x80000006": "STATUS_NO_MORE_FILES",
    "0x8000000d": "STATUS_PARTIAL_COPY",
    "0xc0000001": "STATUS_UNSUCCESSFUL",
    "0xc0000002": "STATUS_NOT_IMPLEMENTED",
    "0xc0000008": "STATUS_INVALID_HANDLE",
    "0xc000000d": "STATUS_INVALID_PARAMETER",
    "0xc0000010": "STATUS_INVALID_DEVICE_REQUEST",
    "0xc0000011": "STATUS_END_OF_FILE",
    "0xc0000022": "STATUS_ACCESS_DENIED",
    "0xc0000034": "STATUS_OBJECT_NAME_NOT_FOUND",
    "0xc0000035": "STATUS_OBJECT_NAME_COLLISION",
    "0xc000003a": "STATUS_OBJECT_PATH_NOT_FOUND",
    "0xc0000043": "STATUS_SHARING_VIOLATION",
    "0xc0000054": "STATUS_FILE_LOCK_CONFLICT",
    "0xc000006d": "STATUS_LOGON_FAILURE",
    "0xc00000bb": "STATUS_NOT_SUPPORTED",
    "0xc00000cc": "STATUS_BAD_NETWORK_NAME",
    "0xc00000d0": "STATUS_REQUEST_NOT_ACCEPTED",
    "0xc00000e5": "STATUS_INTERNAL_ERROR",
    "0xc0000120": "STATUS_CANCELLED",
    "0xc0000205": "STATUS_INSUFF_SERVER_RESOURCES",
    "0xc0000225": "STATUS_NOT_FOUND",
    "0xc0000234": "STATUS_ACCOUNT_LOCKED_OUT",
    "0xc0000257": "STATUS_PATH_NOT_COVERED",
    "0xc000035c": "STATUS_NETWORK_SESSION_EXPIRED",
}

SMB_READ_LENGTH_FIELDS = (
    "read_length",
    "read_count",
    "read_data_len",
    "read_data_length",
    "data_length",
    "data_len",
    "data_len_low",
    "data_size",
    "file_rw_length",
    "count",
    "count_low",
    "dc",
    "tdc",
    "bcc",
)

SMB_WRITE_LENGTH_FIELDS = (
    "write_length",
    "write_count",
    "write_data_len",
    "write_data_length",
    "data_length",
    "data_len",
    "data_len_low",
    "data_size",
    "file_rw_length",
    "count",
    "count_low",
    "dc",
    "tdc",
    "bcc",
)

SMB_CAPABILITY_FIELDS = {
    "smb2": (
        ("capabilities_dfs", "DFS"),
        ("capabilities_leasing", "leasing"),
        ("capabilities_large_mtu", "large MTU"),
        ("capabilities_multi_channel", "multi-channel"),
        ("capabilities_persistent_handles", "persistent handles"),
        ("capabilities_directory_leasing", "directory leasing"),
        ("capabilities_encryption", "encryption"),
        ("capabilities_notifications", "notifications"),
        ("sec_mode_sign_enabled", "signing enabled"),
        ("sec_mode_sign_required", "signing required"),
        ("ses_flags_encrypt", "session encryption"),
        ("share_flags_encrypt_data", "share encryption required"),
        ("share_flags_compress_data", "compressed IO"),
    ),
    "smb": (
        ("server_cap_large_readx", "large ReadX"),
        ("server_cap_large_writex", "large WriteX"),
        ("flags2_compressed", "compression requested"),
        ("unix_capability_large_read", "unix large read"),
        ("unix_capability_large_write", "unix large write"),
        ("unix_capability_encryption", "unix encryption"),
        ("unix_capability_mandatory_crypto", "unix mandatory encryption"),
    ),
}

SMB2_CAPABILITY_MASKS = {
    0x0001: "DFS",
    0x0002: "leasing",
    0x0004: "large MTU",
    0x0008: "multi-channel",
    0x0010: "persistent handles",
    0x0020: "directory leasing",
    0x0040: "encryption",
    0x0080: "notifications",
}


def extract_smb(packet, helpers) -> dict:
    smb_commands = _smb_commands(packet, helpers)
    return {
        "smb_command": smb_commands[0] if smb_commands else None,
        "smb_commands_seen": smb_commands,
        "smb_status": _smb_value(packet, helpers, "nt_status")
        or _smb_value(packet, helpers, "status"),
        "smb_message_id": _smb_value(packet, helpers, "msg_id")
        or _smb_value(packet, helpers, "mid"),
        "smb_is_response": _smb_is_response(packet, helpers),
        "smb_session_id": _smb_value(packet, helpers, "sesid")
        or _smb_value(packet, helpers, "session_id"),
        "smb_tree_id": _smb_value(packet, helpers, "tid")
        or _smb_value(packet, helpers, "tree_id"),
        "smb_file_id": _smb_file_id(packet, helpers),
        "smb_filename": _smb_value(packet, helpers, "file")
        or _smb_value(packet, helpers, "filename"),
        "smb_create_desired_access": _smb_int_value(
            packet,
            helpers,
            (
                "create.desired_access",
                "create_desired_access",
                "desired_access",
                "create_access_mask",
            ),
        ),
        "smb_create_file_attributes": _smb_int_value(
            packet,
            helpers,
            (
                "create.file_attributes",
                "create_file_attributes",
                "file_attributes",
            ),
        ),
        "smb_read_length": _smb_transfer_length(packet, helpers, SMB_READ_LENGTH_FIELDS),
        "smb_write_length": _smb_transfer_length(packet, helpers, SMB_WRITE_LENGTH_FIELDS),
        "smb_file_offset": _smb_file_offset(packet, helpers),
        "smb_encrypted": _smb_encrypted(packet, helpers),
        "smb_capabilities": _smb_capabilities(packet, helpers),
    }


def deep_smb2_reason(flow: FlowSummary) -> str | None:
    if flow.key.protocol != "TCP":
        return None
    if (
        flow.smb_commands
        or flow.smb_statuses
        or flow.smb_read_ops
        or flow.smb_write_ops
        or flow.smb_encrypted_packets
    ):
        return (
            "SMB metadata observed; inspect SMB2 credit charge, request/grant, "
            "statuses, transfer headers, and related TCP symptoms."
        )
    if 445 in _flow_ports(flow) or 139 in _flow_ports(flow):
        return (
            "Likely SMB flow by TCP port; inspect SMB2 credit behavior, statuses, "
            "transfer headers, and related TCP symptoms."
        )
    return None


def deep_smb2_flow(
    capture_path: Path,
    *,
    flow_id: int,
    flow: FlowSummary,
    reason: str,
    sample_limit: int | None = DEFAULT_EVIDENCE_BATCH_SIZE,
    sample_offset: int = 0,
    timeout: int = 120,
) -> dict[str, Any]:
    if flow.key.protocol != "TCP":
        return {
            "tool": "deep_smb2_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "skipped",
            "message": f"Flow protocol is {flow.key.protocol}, not TCP.",
        }

    tshark = tshark_path()
    if not tshark:
        return {
            "tool": "deep_smb2_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "unavailable",
            "message": "tshark was not found on PATH or in the Wireshark app bundle.",
        }

    display_filter = f"{tcp_flow_filter(flow)} && smb2"
    deep_fields = smb2_deep_fields_for_tshark(tshark)
    command = field_command(tshark, capture_path, display_filter, deep_fields)
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "tool": "deep_smb2_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "error",
            "display_filter": display_filter,
            "message": str(exc),
        }

    if result.returncode != 0:
        return {
            "tool": "deep_smb2_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "error",
            "display_filter": display_filter,
            "message": result.stderr.strip() or f"tshark exited with {result.returncode}",
        }

    rows = parse_field_rows(result.stdout, deep_fields)
    return {
        "tool": "deep_smb2_flow",
        "flow_id": flow_id,
        "reason": reason,
        "status": "ok",
        "display_filter": display_filter,
        "packet_count": len(rows),
        "smb2_credit_counts": smb2_credit_counts(rows),
        "smb2_deep_fields": deep_fields,
        "smb2_deep_samples": rows[
            sample_offset:sample_offset + sample_limit if sample_limit is not None else None
        ],
        "sample_limit": sample_limit,
        "truncated": sample_offset > 0 or (sample_limit is not None and len(rows) > sample_limit),
        "batch": evidence_batch(len(rows), sample_offset, sample_limit),
    }


def smb2_deep_fields_for_tshark(tshark: str) -> list[str]:
    available_fields = _tshark_field_names(tshark)
    if not available_fields:
        return list(SMB2_DEEP_FIELDS)
    return [field for field in SMB2_DEEP_FIELDS if field in available_fields]


def _tshark_field_names(tshark: str) -> set[str]:
    if tshark in _TSHARK_FIELD_CACHE:
        return _TSHARK_FIELD_CACHE[tshark]
    try:
        result = subprocess.run(
            [tshark, "-G", "fields"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        _TSHARK_FIELD_CACHE[tshark] = set()
        return set()
    if result.returncode != 0:
        _TSHARK_FIELD_CACHE[tshark] = set()
        return set()
    field_names = _parse_tshark_field_names(result.stdout)
    _TSHARK_FIELD_CACHE[tshark] = field_names
    return field_names


def _parse_tshark_field_names(fields_output: str) -> set[str]:
    field_names = set()
    for line in fields_output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "F":
            field_names.add(parts[2])
    return field_names


def smb2_credit_counts(rows: list[dict[str, str]]) -> dict[str, int]:
    counters = {
        "smb2_packets": 0,
        "smb2_requests": 0,
        "smb2_responses": 0,
        "credit_charge_total": 0,
        "credit_charge_max": 0,
        "credit_request_total": 0,
        "credit_request_max": 0,
        "credit_grant_total": 0,
        "credit_grant_max": 0,
        "credit_grant_zero_packets": 0,
        "read_packets": 0,
        "write_packets": 0,
        "status_error_packets": 0,
        "tcp_loss_or_retransmission_packets": 0,
        "tcp_zero_window_packets": 0,
    }
    for row in rows:
        if (
            row.get("smb2.cmd")
            or row.get(SMB2_CREDIT_CHARGE_FIELD)
            or _first_row_value(row, SMB2_CREDIT_REQUEST_FIELDS)
            or _first_row_value(row, SMB2_CREDIT_GRANT_FIELDS)
        ):
            counters["smb2_packets"] += 1

        is_response = _truthy_row_value(row.get("smb2.flags.response"))
        if is_response:
            counters["smb2_responses"] += 1
        else:
            counters["smb2_requests"] += 1

        credit_charge = _row_int(row.get(SMB2_CREDIT_CHARGE_FIELD))
        if credit_charge is not None:
            counters["credit_charge_total"] += credit_charge
            counters["credit_charge_max"] = max(counters["credit_charge_max"], credit_charge)

        request_response_credit = _row_int(
            _first_row_value(
                row,
                SMB2_CREDIT_GRANT_FIELDS if is_response else SMB2_CREDIT_REQUEST_FIELDS,
            )
        )
        if request_response_credit is not None:
            if is_response:
                counters["credit_grant_total"] += request_response_credit
                counters["credit_grant_max"] = max(
                    counters["credit_grant_max"],
                    request_response_credit,
                )
                if request_response_credit == 0:
                    counters["credit_grant_zero_packets"] += 1
            else:
                counters["credit_request_total"] += request_response_credit
                counters["credit_request_max"] = max(
                    counters["credit_request_max"],
                    request_response_credit,
                )

        command = _lookup_smb_name(row.get("smb2.cmd", ""), SMB2_COMMAND_NAMES) or ""
        command = command.lower()
        if "read" in command:
            counters["read_packets"] += 1
        if "write" in command:
            counters["write_packets"] += 1
        status = row.get("smb2.nt_status")
        if status and _is_smb_error_status(status):
            counters["status_error_packets"] += 1
        if row.get("tcp.analysis.lost_segment") or row.get("tcp.analysis.retransmission"):
            counters["tcp_loss_or_retransmission_packets"] += 1
        if row.get("tcp.analysis.zero_window"):
            counters["tcp_zero_window_packets"] += 1

    return {key: value for key, value in counters.items() if value}


def _first_row_value(row: dict[str, str], fields: tuple[str, ...]) -> str | None:
    for field in fields:
        if value := row.get(field):
            return value
    return None


def smb_command_label(command: str) -> str:
    return _lookup_smb_name(command, SMB1_COMMAND_NAMES) or command


def record_smb(flow: FlowSummary, packet: PacketObservation) -> None:
    if packet.smb_encrypted:
        flow.smb_encrypted_packets += 1
    commands = _packet_smb_commands(packet)
    for command in commands:
        flow.smb_commands[command] = flow.smb_commands.get(command, 0) + 1
    if packet.smb_status:
        flow.smb_statuses[packet.smb_status] = flow.smb_statuses.get(packet.smb_status, 0) + 1
    _append_unique(flow, "smb_session_ids", packet.smb_session_id)
    _append_unique(flow, "smb_tree_ids", packet.smb_tree_id)
    _append_unique(flow, "smb_filenames", packet.smb_filename)
    command_labels = [smb_command_label(command).lower() for command in commands]
    command_label = " ".join(command_labels)
    _record_smb_create_filename(flow, packet, command_label)
    _record_smb_capabilities(flow, packet)

    if _is_smb_error_response(packet):
        flow.smb_error_count += 1
        return

    allow_packet_filename = len(commands) <= 1
    if "read" in command_label and _should_record_smb_transfer(
        commands,
        packet,
        packet.smb_read_length,
    ):
        _record_smb_transfer(
            flow,
            packet,
            filename_field="smb_read_filenames",
            last_offsets_field="smb_last_read_offset_by_file",
            length=packet.smb_read_length,
            bytes_field="smb_read_bytes",
            ops_field="smb_read_ops",
            unknown_ops_field="smb_read_unknown_bytes_ops",
            inferred_ops_field="smb_read_offset_inferred_ops",
            bytes_by_file_field="smb_read_bytes_by_file",
            allow_packet_filename=allow_packet_filename,
            transfer_direction="read",
        )
    if "write" in command_label and _should_record_smb_transfer(
        commands,
        packet,
        packet.smb_write_length,
    ):
        _record_smb_transfer(
            flow,
            packet,
            filename_field="smb_write_filenames",
            last_offsets_field="smb_last_write_offset_by_file",
            length=packet.smb_write_length,
            bytes_field="smb_write_bytes",
            ops_field="smb_write_ops",
            unknown_ops_field="smb_write_unknown_bytes_ops",
            inferred_ops_field="smb_write_offset_inferred_ops",
            bytes_by_file_field="smb_write_bytes_by_file",
            allow_packet_filename=allow_packet_filename,
            transfer_direction="write",
        )
    if _is_smb_error_status(packet.smb_status):
        flow.smb_error_count += 1


def render_smb_details(
    summary: CaptureSummary,
    *,
    show_flows: int,
    console: Console,
) -> None:
    table = smb_details_table(summary, show_flows=show_flows)
    if table:
        console.print(table)


def smb_details_table(summary: CaptureSummary, *, show_flows: int) -> Table | None:
    rows = [
        (flow_id, flow)
        for flow_id, flow in enumerate(summary.flows[:show_flows], start=1)
        if (
            flow.smb_commands
            or flow.smb_statuses
            or flow.smb_filenames
            or flow.smb_encrypted_packets
        )
    ]
    if not rows:
        return None

    table = Table(title="SMB Details In Top Flows", show_lines=True)
    table.add_column("Flow ID", justify="right")
    table.add_column("Commands", overflow="fold")
    table.add_column("Statuses", overflow="fold")
    table.add_column("Capabilities", overflow="fold")
    table.add_column("Transfer", overflow="fold")
    table.add_column("Issue", overflow="fold")

    for flow_id, flow in rows:
        table.add_row(
            str(flow_id),
            format_smb_counter_lines(flow.smb_commands, SMB1_COMMAND_NAMES),
            format_smb_counter_lines(flow.smb_statuses, SMB_STATUS_NAMES),
            format_smb_capabilities(flow),
            format_smb_transfer(flow),
            "\n".join(flow.smb_diagnostic_hints),
        )
    return table


def format_smb_counter_lines(counts: dict[str, int], names: dict[str, str]) -> str:
    if not counts:
        return ""
    return "\n".join(
        f"{smb_display_value(value, names)}: {count}"
        for value, count in list(counts.items())[:10]
    )


def format_smb_transfer(flow) -> str:
    return "\n".join(
        [
            format_smb_transfer_line(
                "read",
                flow.smb_read_ops,
                flow.smb_read_bytes,
                flow.smb_read_unknown_bytes_ops,
                flow.smb_read_offset_inferred_ops,
                _format_smb_transfer_files("download", flow.smb_read_bytes_by_file),
            ),
            format_smb_transfer_line(
                "write",
                flow.smb_write_ops,
                flow.smb_write_bytes,
                flow.smb_write_unknown_bytes_ops,
                flow.smb_write_offset_inferred_ops,
                _format_smb_transfer_files("upload", flow.smb_write_bytes_by_file),
            ),
            f"smb payload {flow.smb_transfer_mbps:.3f} Mbps",
            f"flow total {flow.throughput_mbps:.3f} Mbps",
        ]
    )


def format_smb_capabilities(flow) -> str:
    capability_sources: dict[str, set[str]] = {}
    for capability in flow.smb_client_capabilities:
        capability_sources.setdefault(capability, set()).add("c")
    for capability in flow.smb_server_capabilities:
        capability_sources.setdefault(capability, set()).add("s")
    lines = [
        f"{capability} ({','.join(source for source in ('c', 's') if source in sources)})"
        for capability, sources in list(capability_sources.items())[:20]
    ]
    return "\n".join(lines)


def format_smb_transfer_line(
    label: str,
    ops: int,
    byte_count: int,
    unknown_ops: int,
    inferred_ops: int = 0,
    files: list[str] | None = None,
) -> str:
    line = f"{label} {ops} ops / {byte_count} bytes"
    notes = []
    if inferred_ops:
        notes.append(f"{inferred_ops} ops inferred from offsets")
    if unknown_ops:
        notes.append(f"{unknown_ops} ops length unavailable")
    if notes:
        line += f" ({', '.join(notes)})"
    if files:
        line += "\n" + "\n".join(files)
    return line


def _format_smb_transfer_files(label: str, bytes_by_file: dict[str, int]) -> list[str]:
    transferred_files = [
        (filename, byte_count)
        for filename, byte_count in bytes_by_file.items()
        if byte_count >= SMB_TRANSFER_FILE_MIN_BYTES
    ]
    transferred_files.sort(key=lambda item: item[1], reverse=True)
    return [
        f"{label} {filename} ({_format_bytes(byte_count)})"
        for filename, byte_count in transferred_files[:10]
    ]


def _format_bytes(byte_count: int) -> str:
    if byte_count >= 1_048_576:
        return f"{byte_count / 1_048_576:.1f} MiB"
    if byte_count >= 1024:
        return f"{byte_count / 1024:.1f} KiB"
    return f"{byte_count} bytes"


def _smb_int_value(packet, helpers, attr_names: tuple[str, ...]) -> int | None:
    match = _smb_int_match(packet, helpers, attr_names)
    return match[1] if match else None


def _smb_int_match(packet, helpers, attr_names: tuple[str, ...]) -> tuple[str, int] | None:
    for attr_name in attr_names:
        value = helpers.safe_int(_smb_value(packet, helpers, attr_name))
        if value is not None:
            return attr_name, value
    return None


def _smb_commands(packet, helpers) -> list[str]:
    smb2_layer = getattr(packet, "smb2", None)
    smb2_commands = [
        *helpers.layer_attr_values(packet, "smb2", "cmd"),
        *helpers.layer_attr_values(packet, "smb2", "command"),
    ]
    if smb2_commands:
        return [SMB2_COMMAND_NAMES.get(command.lower(), command) for command in smb2_commands]
    if smb2_layer is not None:
        commands = [
            *_smb_values(packet, helpers, "cmd"),
            *_smb_values(packet, helpers, "command"),
        ]
        return [SMB2_COMMAND_NAMES.get(command.lower(), command) for command in commands]
    return helpers.layer_attr_values(packet, "smb", "cmd")


def _smb_value(packet, helpers, attr_name: str) -> str | None:
    values = _smb_values(packet, helpers, attr_name)
    return values[0] if values else None


def _smb_values(packet, helpers, attr_name: str) -> list[str]:
    for layer_name in ("smb2", "smb"):
        values = helpers.layer_attr_values(packet, layer_name, attr_name)
        if values:
            return values
    return []


def _smb_is_response(packet, helpers) -> bool | None:
    response_flag = _first_smb_value(packet, helpers, ("flags_response", "flags_response_to"))
    if response_flag is None:
        return None
    return response_flag not in {"0", "False", "false"}


def _smb_file_id(packet, helpers) -> str | None:
    return _first_smb_value(
        packet,
        helpers,
        (
            "file_id",
            "fid",
            "fid_hash",
            "server_fid",
            "create_file_id",
            "create_file_id_64b",
        ),
    )


def _first_smb_value(packet, helpers, attr_names: tuple[str, ...]) -> str | None:
    for attr_name in attr_names:
        value = _smb_value(packet, helpers, attr_name)
        if value:
            return value
    return None


def _smb_transfer_length(packet, helpers, attr_names: tuple[str, ...]) -> int | None:
    match = _smb_int_match(packet, helpers, attr_names)
    if match is None:
        return None
    attr_name, length = match
    base_name = attr_name.removesuffix("_low")
    high = _smb_int_value(packet, helpers, (f"{base_name}_high",))
    if high:
        return length + (high << 32)
    return length


def _smb_file_offset(packet, helpers) -> int | None:
    match = _smb_int_match(
        packet,
        helpers,
        (
            "file_offset",
            "file_rw_offset",
            "offset",
            "offset_low",
        ),
    )
    if match is None:
        return None
    attr_name, offset = match
    base_name = attr_name.removesuffix("_low")
    high = _smb_int_value(packet, helpers, (f"{base_name}_high",))
    if high:
        return offset + (high << 32)
    return offset


def _smb_encrypted(packet, helpers) -> bool:
    smb2_layer = getattr(packet, "smb2", None)
    if smb2_layer is None:
        return False
    encrypted_field_names = (
        "transform_header",
        "transform_session_id",
        "transform_signature",
        "transform_nonce",
        "transform_original_message_size",
    )
    if any(
        helpers.truthy_layer_attr(smb2_layer, field_name)
        for field_name in encrypted_field_names
    ):
        return True
    fields = getattr(smb2_layer, "_all_fields", {})
    return any(
        _is_smb_encrypted_payload_field(key)
        and value not in (None, "", "0", "False", "false")
        for key, value in fields.items()
    )


def _is_smb_encrypted_payload_field(field_name: str) -> bool:
    field_name = field_name.lower()
    return "transform" in field_name


def _smb_capabilities(packet, helpers) -> list[str]:
    capabilities = []
    for layer_name, fields in SMB_CAPABILITY_FIELDS.items():
        layer = getattr(packet, layer_name, None)
        if layer is None:
            continue
        for attr_name, label in fields:
            if helpers.truthy_layer_attr(layer, attr_name):
                capabilities.append(label)
        if layer_name == "smb2":
            capabilities.extend(_smb2_capability_mask_labels(layer, helpers))
        if layer_name == "smb2" and _smb2_encryption_capabilities(layer, helpers):
            capabilities.append("encryption")
    dialect = _smb_value(packet, helpers, "dialect") or _smb_value(
        packet,
        helpers,
        "dialect_name",
    )
    security_mode = _smb_value(packet, helpers, "sec_mode") or _smb_value(
        packet,
        helpers,
        "sm",
    )
    for label, value in (("dialect", dialect), ("security_mode", security_mode)):
        if value:
            capabilities.append(f"{label}={value}")
    return list(dict.fromkeys(capabilities))


def _smb2_capability_mask_labels(layer, helpers) -> list[str]:
    capability_values = [
        *helpers.layer_attr_values_from_layer(layer, "capabilities"),
        *helpers.layer_attr_values_from_layer(layer, "server_cap"),
    ]
    labels = []
    for capability_value in capability_values:
        capability_mask = helpers.safe_int(capability_value)
        if capability_mask is None:
            continue
        labels.extend(
            label
            for bit, label in SMB2_CAPABILITY_MASKS.items()
            if capability_mask & bit
        )
    return labels


def _smb2_encryption_capabilities(layer, helpers) -> bool:
    encryption_capability_fields = (
        "encryption_capabilities",
        "encryption_capabilities_ciphers",
        "encryption_context",
        "negotiate_context_encryption_capabilities",
        "neg_context_encryption_capabilities",
    )
    if any(
        helpers.truthy_layer_attr(layer, field_name)
        for field_name in encryption_capability_fields
    ):
        return True
    fields = getattr(layer, "_all_fields", {})
    for key, value in fields.items():
        key_text = key.lower()
        values = " ".join(helpers.string_values(value)).lower()
        combined = f"{key_text} {values}"
        if "encryption" in combined and ("capabil" in combined or "cipher" in combined):
            return True
        if "smb2_encryption_capabilities" in combined:
            return True
    return False


def _packet_smb_commands(packet: PacketObservation) -> list[str]:
    commands = packet.smb_commands_seen or ([packet.smb_command] if packet.smb_command else [])
    return list(dict.fromkeys(command for command in commands if command))


def _should_record_smb_transfer(
    commands: list[str],
    packet: PacketObservation,
    length: int | None,
) -> bool:
    if len(commands) <= 1:
        return True
    return (
        length is not None
        or packet.smb_file_offset is not None
        or packet.smb_file_id is not None
    )


def _record_smb_transfer(
    flow: FlowSummary,
    packet: PacketObservation,
    *,
    filename_field: str,
    last_offsets_field: str,
    length: int | None,
    bytes_field: str,
    ops_field: str,
    unknown_ops_field: str,
    inferred_ops_field: str,
    bytes_by_file_field: str,
    allow_packet_filename: bool,
    transfer_direction: str,
) -> None:
    count_operation = _should_count_smb_transfer_operation(flow, packet, transfer_direction, length)
    if count_operation:
        setattr(flow, ops_field, getattr(flow, ops_field) + 1)
    filename = _resolved_smb_filename(
        flow,
        packet,
        allow_packet_filename=allow_packet_filename,
        transfer_direction=transfer_direction,
    )
    inferred_length = _infer_transfer_length_from_offset(flow, packet, last_offsets_field, filename)
    if length is not None:
        setattr(flow, bytes_field, getattr(flow, bytes_field) + length)
        if length > 0:
            _append_unique(flow, filename_field, filename)
            _record_bytes_by_file(flow, bytes_by_file_field, filename, length)
    elif inferred_length is not None:
        setattr(flow, bytes_field, getattr(flow, bytes_field) + inferred_length)
        setattr(flow, inferred_ops_field, getattr(flow, inferred_ops_field) + 1)
        if inferred_length > 0:
            _append_unique(flow, filename_field, filename)
            _record_bytes_by_file(flow, bytes_by_file_field, filename, inferred_length)
    elif count_operation:
        setattr(flow, unknown_ops_field, getattr(flow, unknown_ops_field) + 1)


def _should_count_smb_transfer_operation(
    flow: FlowSummary,
    packet: PacketObservation,
    transfer_direction: str,
    length: int | None,
) -> bool:
    counted_ids = (
        flow.smb_counted_read_message_ids
        if transfer_direction == "read"
        else flow.smb_counted_write_message_ids
    )
    if packet.smb_message_id:
        if packet.smb_message_id in counted_ids:
            return False
        counted_ids.add(packet.smb_message_id)
        return True
    if packet.smb_is_response is True:
        return length is not None
    return True


def _is_smb_error_response(packet: PacketObservation) -> bool:
    return packet.smb_is_response is True and _is_smb_error_status(packet.smb_status)


def _is_smb_error_status(status: str | None) -> bool:
    if not status:
        return False
    return status.upper() not in {
        "0",
        "0X00000000",
        "STATUS_SUCCESS",
        "SUCCESS",
    }


def _infer_transfer_length_from_offset(
    flow: FlowSummary,
    packet: PacketObservation,
    last_offsets_field: str,
    filename: str | None,
) -> int | None:
    if packet.smb_file_offset is None:
        return None
    file_key = filename or packet.smb_file_id or "<unknown>"
    last_offsets = getattr(flow, last_offsets_field)
    previous_offset = last_offsets.get(file_key)
    last_offsets[file_key] = packet.smb_file_offset
    if previous_offset is None or packet.smb_file_offset <= previous_offset:
        return None
    return packet.smb_file_offset - previous_offset


def _record_smb_file_id_name(flow: FlowSummary, packet: PacketObservation) -> None:
    if packet.smb_file_id and packet.smb_filename:
        flow.smb_file_id_names[packet.smb_file_id] = packet.smb_filename
        _record_smb_file_id_transfer_names(flow, packet.smb_file_id, packet.smb_filename, packet)
    if packet.smb_file_id and packet.smb_message_id:
        pending_filename = flow.smb_pending_create_names.get(packet.smb_message_id)
        if pending_filename:
            flow.smb_file_id_names[packet.smb_file_id] = pending_filename
        pending_read_filename = flow.smb_pending_create_read_names.get(packet.smb_message_id)
        if pending_read_filename:
            flow.smb_file_id_read_names[packet.smb_file_id] = pending_read_filename
        pending_write_filename = flow.smb_pending_create_write_names.get(packet.smb_message_id)
        if pending_write_filename:
            flow.smb_file_id_write_names[packet.smb_file_id] = pending_write_filename


def _record_bytes_by_file(
    flow: FlowSummary,
    field_name: str,
    filename: str | None,
    byte_count: int,
) -> None:
    if not filename:
        return
    bytes_by_file = getattr(flow, field_name)
    bytes_by_file[filename] = bytes_by_file.get(filename, 0) + byte_count


def _record_smb_create_filename(
    flow: FlowSummary,
    packet: PacketObservation,
    command_label: str,
) -> None:
    if "create" in command_label and packet.smb_message_id and packet.smb_filename:
        flow.smb_pending_create_names[packet.smb_message_id] = packet.smb_filename
        intents = _smb_create_transfer_intents(packet)
        if "read" in intents:
            flow.smb_pending_create_read_names[packet.smb_message_id] = packet.smb_filename
        if "write" in intents:
            flow.smb_pending_create_write_names[packet.smb_message_id] = packet.smb_filename
    _record_smb_file_id_name(flow, packet)


def _record_smb_file_id_transfer_names(
    flow: FlowSummary,
    file_id: str,
    filename: str,
    packet: PacketObservation,
) -> None:
    intents = _smb_create_transfer_intents(packet)
    if "read" in intents:
        flow.smb_file_id_read_names[file_id] = filename
    if "write" in intents:
        flow.smb_file_id_write_names[file_id] = filename


def _smb_create_transfer_intents(packet: PacketObservation) -> set[str]:
    if _is_smb_directory_create(packet):
        return set()
    desired_access = packet.smb_create_desired_access
    if desired_access is None:
        return set()
    intents = set()
    if desired_access & 0x00000001:
        intents.add("read")
    if desired_access & 0x00000002 or desired_access & 0x00000004:
        intents.add("write")
    return intents


def _is_smb_directory_create(packet: PacketObservation) -> bool:
    return bool(packet.smb_create_file_attributes and packet.smb_create_file_attributes & 0x10)


def _resolved_smb_filename(
    flow: FlowSummary,
    packet: PacketObservation,
    *,
    allow_packet_filename: bool,
    transfer_direction: str,
) -> str | None:
    if packet.smb_file_id:
        direction_names = (
            flow.smb_file_id_read_names
            if transfer_direction == "read"
            else flow.smb_file_id_write_names
        )
        if filename := direction_names.get(packet.smb_file_id):
            return filename
    if allow_packet_filename and packet.smb_filename:
        return packet.smb_filename
    return None


def _record_smb_capabilities(flow: FlowSummary, packet: PacketObservation) -> None:
    if not packet.smb_capabilities:
        return
    capability_field = (
        "smb_server_capabilities" if packet.src_port in {139, 445} else "smb_client_capabilities"
    )
    for capability in packet.smb_capabilities:
        _append_unique(flow, capability_field, capability)


def _append_unique(
    flow: FlowSummary,
    field_name: str,
    value: str | None,
    limit: int = 25,
) -> None:
    if not value:
        return
    values = getattr(flow, field_name)
    if value not in values:
        setattr(flow, field_name, [*values, value][:limit])


def smb_display_value(value: str, names: dict[str, str]) -> str:
    if names is SMB_STATUS_NAMES:
        status_name = _status_name_from_display_value(value)
        if status_name:
            return status_name
    label = _lookup_smb_name(value, names)
    if label:
        if names is SMB_STATUS_NAMES:
            return label
        return f"{label}({value})"
    if names is SMB_STATUS_NAMES and _is_hex_value(value):
        return f"NTSTATUS_UNKNOWN({value})"
    return value


def _status_name_from_display_value(value: str) -> str | None:
    status_name = value.split("(", maxsplit=1)[0].strip()
    if status_name.upper().startswith("STATUS_"):
        return status_name
    return None


def _lookup_smb_name(value: str, names: dict[str, str]) -> str | None:
    normalized = value.lower()
    return names.get(value) or names.get(normalized)


def _is_hex_value(value: str) -> bool:
    try:
        int(value, 16)
    except ValueError:
        return False
    return value.lower().startswith("0x")


def _flow_ports(flow: FlowSummary) -> set[int]:
    return {port for port in (flow.key.port_a, flow.key.port_b) if port is not None}


def _row_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    first_value = value.split("|", maxsplit=1)[0].split(",", maxsplit=1)[0].strip()
    try:
        return int(first_value, 0)
    except ValueError:
        return None


def _truthy_row_value(value: str | None) -> bool:
    return value not in (None, "", "0", "False", "false")
