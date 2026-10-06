import importlib

from flowpilot.deep_tools import deep_tool_names
from flowpilot.protocols import PROTOCOL_REGISTRY, protocol_names, protocols
from flowpilot.protocols.registry import (
    deep_tool_guidance_prompt,
    deep_tool_hooks,
    extract_hooks,
    protocol_name_for_deep_tool,
    record_hooks,
)


def test_protocol_registry_lists_existing_protocol_modules() -> None:
    assert protocol_names() == {
        "ike",
        "rtp",
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
        "deep_ike_flow",
        "deep_rtp_flow",
        "deep_tcp_flow",
        "deep_udp_flow",
        "deep_tls_flow",
        "deep_smb2_flow",
        "deep_esp_flow",
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


def test_protocol_registry_builds_deep_tool_guidance_prompt() -> None:
    prompt = deep_tool_guidance_prompt()

    assert "Allowed tools:" in prompt
    assert "deep_tls_flow" in prompt
    assert "deep_smb2_flow" in prompt
    assert "deep_esp_flow" in prompt
    assert "SMB2 credit request/grant/charge" in prompt


def test_protocol_registry_maps_deep_tool_to_protocol_name() -> None:
    assert protocol_name_for_deep_tool("deep_smb2_flow") == "smb"
    assert protocol_name_for_deep_tool("deep_tls_flow") == "tls"
    assert protocol_name_for_deep_tool("deep_esp_flow") == "esp"
    assert protocol_name_for_deep_tool("missing_tool") is None


def test_protocol_registry_render_hooks_are_importable() -> None:
    for protocol in protocols():
        if protocol.render_hook:
            module_name, function_name = protocol.render_hook.rsplit(".", 1)
            module = importlib.import_module(module_name)
            assert hasattr(module, function_name)


def test_protocol_registry_extract_hooks_are_importable() -> None:
    extractable_protocols = {protocol.name for protocol in protocols() if protocol.extract_hook}

    assert extractable_protocols == {"tcp", "tls", "smb", "sip", "dns", "dhcp", "esp", "rtp", "ike"}
    assert len(extract_hooks()) == len(extractable_protocols)
    for protocol in protocols():
        if protocol.extract_hook:
            module_name, function_name = protocol.extract_hook.rsplit(".", 1)
            module = importlib.import_module(module_name)
            assert hasattr(module, function_name)


def test_protocol_registry_record_hooks_are_importable() -> None:
    recordable_protocols = {protocol.name for protocol in protocols() if protocol.record_hook}

    assert recordable_protocols == {"tls", "smb", "sip", "dns", "dhcp", "esp", "rtp", "ike"}
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


def test_esp_protocol_entry_documents_deep_tool_and_metadata_key() -> None:
    esp = PROTOCOL_REGISTRY["esp"]

    assert esp.deep_tools == ("deep_esp_flow",)
    assert esp.compact_metadata_key == "esp"
    assert "deep_esp_flow" in esp.deep_tool_prompt
    assert "NAT-T" in esp.transport_prompt
