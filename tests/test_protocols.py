import importlib

from flowpilot.deep_tools import deep_tool_names
from flowpilot.protocols import PROTOCOL_REGISTRY, protocol_names, protocols
from flowpilot.protocols.registry import deep_tool_hooks, extract_hooks, record_hooks


def test_protocol_registry_lists_existing_protocol_modules() -> None:
    assert protocol_names() == {
        "tcp",
        "udp",
        "tls",
        "smb",
        "sip",
        "dns",
        "dhcp",
        "esp",
    }


def test_protocol_registry_deep_tools_are_registered() -> None:
    allowed_tools = deep_tool_names()

    for protocol in protocols():
        assert set(protocol.deep_tools).issubset(allowed_tools)


def test_protocol_registry_deep_tool_hooks_are_importable() -> None:
    hooked_tool_names = {tool_name for tool_name, _, _ in deep_tool_hooks()}

    assert hooked_tool_names == {
        "deep_tcp_flow",
        "deep_udp_flow",
        "deep_tls_flow",
        "deep_smb2_flow",
    }
    for protocol in protocols():
        assert len(protocol.deep_tools) == len(protocol.deep_tool_runner_hooks)
        if protocol.deep_tools:
            assert protocol.deep_reason_hook
        hook_paths = list(protocol.deep_tool_runner_hooks)
        if protocol.deep_reason_hook:
            hook_paths.append(protocol.deep_reason_hook)
        for hook_path in hook_paths:
            module_name, function_name = hook_path.rsplit(".", 1)
            module = importlib.import_module(module_name)
            assert hasattr(module, function_name)


def test_protocol_registry_render_hooks_are_importable() -> None:
    for protocol in protocols():
        if protocol.render_hook:
            module_name, function_name = protocol.render_hook.rsplit(".", 1)
            module = importlib.import_module(module_name)
            assert hasattr(module, function_name)


def test_protocol_registry_extract_hooks_are_importable() -> None:
    extractable_protocols = {protocol.name for protocol in protocols() if protocol.extract_hook}

    assert extractable_protocols == {"tcp", "tls", "smb", "sip", "dns", "dhcp", "esp"}
    assert len(extract_hooks()) == len(extractable_protocols)
    for protocol in protocols():
        if protocol.extract_hook:
            module_name, function_name = protocol.extract_hook.rsplit(".", 1)
            module = importlib.import_module(module_name)
            assert hasattr(module, function_name)


def test_protocol_registry_record_hooks_are_importable() -> None:
    recordable_protocols = {protocol.name for protocol in protocols() if protocol.record_hook}

    assert recordable_protocols == {"tls", "smb", "sip", "dns", "dhcp", "esp"}
    assert len(record_hooks()) == len(recordable_protocols)
    for protocol in protocols():
        if protocol.record_hook:
            module_name, function_name = protocol.record_hook.rsplit(".", 1)
            module = importlib.import_module(module_name)
            assert hasattr(module, function_name)


def test_tls_protocol_entry_documents_deep_tool_and_metadata_key() -> None:
    tls = PROTOCOL_REGISTRY["tls"]

    assert tls.deep_tools == ("deep_tls_flow",)
    assert tls.compact_metadata_key == "tls"
    assert "tls_certificates" in tls.flow_attributes
    assert "handshake compatibility" in tls.transport_prompt
    assert "certificate validity" in tls.security_prompt


def test_smb_protocol_entry_documents_deep_tool_and_metadata_key() -> None:
    smb = PROTOCOL_REGISTRY["smb"]

    assert smb.deep_tools == ("deep_smb2_flow",)
    assert smb.compact_metadata_key == "smb"
    assert "SMB2 credit request/grant/charge" in smb.transport_prompt
