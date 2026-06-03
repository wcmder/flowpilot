import importlib

from flowpilot.deep_tools import deep_tool_names
from flowpilot.protocols import PROTOCOL_REGISTRY, protocol_names, protocols


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


def test_protocol_registry_render_hooks_are_importable() -> None:
    for protocol in protocols():
        if protocol.render_hook:
            module_name, function_name = protocol.render_hook.rsplit(".", 1)
            module = importlib.import_module(module_name)
            assert hasattr(module, function_name)


def test_tls_protocol_entry_documents_deep_tool_and_metadata_key() -> None:
    tls = PROTOCOL_REGISTRY["tls"]

    assert tls.deep_tools == ("deep_tls_flow",)
    assert tls.compact_metadata_key == "tls"
    assert "tls_certificates" in tls.flow_attributes
