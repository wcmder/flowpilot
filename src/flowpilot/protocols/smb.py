from __future__ import annotations

from rich.console import Console
from rich.table import Table

from ..models import CaptureSummary, FlowSummary, PacketObservation

SMB_TRANSFER_FILE_MIN_BYTES = 1_048_576

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
