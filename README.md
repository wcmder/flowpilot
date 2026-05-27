# FlowPilot

FlowPilot is an agentic data-flow troubleshooting tool for packet captures. It
uses PyShark/TShark to extract network conversations and the OpenAI Responses
API to reason about transfer problems such as TCP retransmissions, UDP reachability,
ESP/IPsec flows, one-way traffic, resets, zero windows, and possible path issues.

## What it does

- Reads `.pcap` / `.pcapng` files with PyShark.
- Aggregates packets into bidirectional flows.
- Highlights top talkers, protocols, ports, DNS names, ESP SPIs, ESP sequence
  gaps/out-of-order/duplicate indicators, and TCP issue counters when TShark
  exposes them.
- Extracts TLS certificate metadata observed in the capture when TShark exposes
  it, including subject, issuer, serial, validity, SAN DNS names, and SHA-256
  fingerprint.
- Extracts SIP call metadata such as call ID, caller, callee, methods, response
  statuses, and failure response issues when visible.
- Extracts SMB/SMB2 metadata such as commands, NT status values, session/tree
  IDs, filenames, read/write operation counts, transfer bytes, and transfer
  efficiency hints when visible.
- Calculates local troubleshooting metrics such as retransmission rate, RTT
  average/max when available, one-way flow detection, packet rate, and maximum
  inter-packet gap.
- Optionally asks an OpenAI model to reason over the flow summary and return
  likely network causes, evidence, and next troubleshooting actions.

## Requirements

- Python 3.10+
- TShark installed and available on `PATH`
- An OpenAI API key for LLM analysis

On macOS, TShark is commonly installed with Wireshark:

```bash
brew install --cask wireshark
```

## Setup

```bash
python3 -m venv env-flowpilot
source env-flowpilot/bin/activate
pip install -e ".[dev]"
export OPENAI_API_KEY="your_api_key_here"
```

FlowPilot also loads a local `.env` file automatically. Create one from the
example and put your real local values there:

```bash
cp .env.example .env
```

OpenAI's Python SDK reads `OPENAI_API_KEY` from the environment after `.env` is
loaded.
By default, FlowPilot uses the standard OpenAI API endpoint. To use an
OpenAI-compatible gateway in a restricted or government network, set:

```bash
export FLOWPILOT_OPENAI_BASE_URL="https://your-openai-compatible-endpoint.example/v1"
```

Some OpenAI-compatible gateways only document `client.chat.completions.create()`
instead of the newer Responses API. In that case, set:

```bash
export FLOWPILOT_LLM_API="chat_completions"
```

You can also use `auto` to try Responses first and retry Chat Completions if the
endpoint returns `404` for Responses:

```bash
export FLOWPILOT_LLM_API="auto"
```

For providers with request-per-minute limits, set a client-side throttle:

```bash
export FLOWPILOT_LLM_REQUESTS_PER_MINUTE="120"
```

## Air-gapped setup with a wheelhouse

For an air-gapped or restricted network, build a local Python wheelhouse on a
machine that has internet access, then move the wheelhouse and FlowPilot source
to the offline machine. Build the wheelhouse on the same OS, CPU architecture,
and Python version as the target machine when possible.

On the internet-connected build machine:

```bash
git clone <your-flowpilot-repo-url>
cd FlowPilot
python3 -m venv build-flowpilot
source build-flowpilot/bin/activate
python -m pip install --upgrade pip wheel
python -m pip wheel -w wheelhouse ".[dev]"
tar -czf flowpilot-wheelhouse.tgz wheelhouse
```

Move these items into the air-gapped network:

- The FlowPilot repository/source directory.
- `flowpilot-wheelhouse.tgz`.
- A TShark/Wireshark installer approved for that network.

On the air-gapped machine:

```bash
cd FlowPilot
tar -xzf /path/to/flowpilot-wheelhouse.tgz
python3 -m venv env-flowpilot
source env-flowpilot/bin/activate
python -m pip install --no-index --find-links wheelhouse -e ".[dev]"
flowpilot --help
```

If you prefer a non-editable install, install the built package wheel instead:

```bash
python -m pip install --no-index --find-links wheelhouse "flowpilot[dev]"
```

TShark is still a system dependency and is not installed by the Python
wheelhouse. After installing Wireshark/TShark, verify it is available:

```bash
tshark --version
```

For an internal OpenAI-compatible LLM gateway, create a local `.env` file on the
air-gapped machine:

```bash
cp .env.example .env
```

Then set values such as:

```bash
OPENAI_API_KEY="your_internal_key"
FLOWPILOT_OPENAI_BASE_URL="https://your-internal-llm-gateway.example/v1"
FLOWPILOT_LLM_API="chat_completions"
FLOWPILOT_MODEL="your-internal-model-name"
FLOWPILOT_LLM_REQUESTS_PER_MINUTE="120"
```

Use `flowpilot models` to confirm the API key, base URL, and model endpoint work
inside the restricted network.

## Usage

Summarize a capture without calling the LLM:

```bash
flowpilot analyze capture.pcap --no-llm
```

Local `--no-llm` output includes packet counts, byte counts, directionality,
retransmission rate, RTT average/max when TShark exposes `tcp.analysis.ack_rtt`,
maximum packet gap, packet rate, TCP issue counters, and visible SIP/SMB
protocol clues.
For ESP/IPsec, FlowPilot also tracks visible ESP sequence numbers per SPI and
direction so the local summary and LLM metadata can flag sequence gaps,
out-of-order packets, and duplicates when those fields are present. In the top
flows table, the Protocol column shows per-direction sequence counters, the
distribution of observed missing-packet gap sizes such as `gap=1(x10) gap=2(x2)`.
SIP and SMB details are shown in separate tables keyed by `Flow ID`, because one
network flow can carry many SIP calls or many SMB operations. SIP details are
split by Call-ID with separate caller, callee, and issue columns. SIP response
codes in the 4xx, 5xx, and 6xx ranges are marked as call failure issues. Each
SIP call also includes a compact call trace so the LLM can reason about call
setup and failure direction. SMB details include read/write operations, transfer
bytes, SMB transfer Mbps, statuses/errors, files, and hints for suboptimal file
transfer behavior such as small read/write sizes, errors, low throughput, or
large idle gaps.

Focus on one flow or a smaller slice before sending anything to the LLM:

```bash
flowpilot analyze capture.pcap --host 10.0.0.5 --peer 198.51.100.20 --protocol tcp --port 443
```

Other useful local filters:

```bash
flowpilot analyze capture.pcap --protocol esp --no-llm
flowpilot analyze capture.pcap --src 10.0.0.5 --dst 198.51.100.20 --no-llm
flowpilot analyze capture.pcap --host 10.0.0.5 --show-flows 50 --no-llm
```

Analyze with OpenAI reasoning:

```bash
flowpilot analyze capture.pcap --model gpt-5-mini
```

When LLM reasoning is enabled, FlowPilot prints `[info]` progress lines, renders
the local summary first, and then sends derived metadata to the model. Raw packet
payloads are not sent.

Start an interactive follow-up chat after the first LLM report:

```bash
flowpilot analyze capture.pcap --chat
```

The chat reuses the same derived metadata and initial LLM report. Type `exit`,
`quit`, or `q` to leave the prompt. `--chat` cannot be used with `--no-llm`.

List models from the configured OpenAI or OpenAI-compatible endpoint:

```bash
flowpilot models
flowpilot models --json
```

Write machine-readable output:

```bash
flowpilot analyze capture.pcap --json report.json
```

## CLI options

The main command is:

```bash
flowpilot analyze CAPTURE_PATH [OPTIONS]
```

Core options:

| Option | Meaning |
| --- | --- |
| `CAPTURE_PATH` | Path to a `.pcap` or `.pcapng` file. |
| `--no-llm` | Only run local PyShark/TShark flow analysis. No metadata is sent to the LLM endpoint. |
| `--chat` | After the first LLM report, open an interactive follow-up chat over the same derived metadata. |
| `--model TEXT` | OpenAI or OpenAI-compatible model used for reasoning. Defaults to `FLOWPILOT_MODEL` or `gpt-5-mini`. |
| `--json PATH` | Write the summary and optional LLM report to a JSON file. |
| `--packet-limit INTEGER` | Stop reading after this many packets. Useful for quick checks on very large captures. |
| `--tls-keylog-file PATH` | Pass a TLS key log file to TShark for decryption, usually an `SSLKEYLOGFILE` generated during capture. |
| `--max-flows INTEGER` | Maximum top flows included in the LLM request. Defaults to `25`. |
| `--show-flows INTEGER` | Maximum flows shown in the terminal table. Defaults to `10`. |

Model discovery:

| Command | Meaning |
| --- | --- |
| `flowpilot models` | Calls the configured `/v1/models` endpoint and prints available model IDs. |
| `flowpilot models --json` | Prints the model list as JSON. |

Local packet filters:

| Option | Direction | Meaning |
| --- | --- | --- |
| `--host IP` | Bidirectional | Include packets where this IP is either source or destination. |
| `--peer IP` | Bidirectional | Use with `--host` to isolate traffic between two endpoints. |
| `--src IP` | One-way | Include packets from this source IP only. |
| `--dst IP` | One-way | Include packets to this destination IP only. |
| `--protocol TEXT` | Either | Include only this protocol, for example `tcp`, `udp`, `esp`, `ah`, `gre`, or `icmp`. |
| `--port INTEGER` | Either | Include packets where this TCP/UDP source or destination port appears. |
| `--src-port INTEGER` | One-way | Include packets from this TCP/UDP source port only. |
| `--dst-port INTEGER` | One-way | Include packets to this TCP/UDP destination port only. |
| `--include-redirects` | Related flows | With filters, include follow-on flows for decrypted HTTP redirect `Location` targets. |
| `--sip-phone TEXT` | SIP calls | Include SIP calls where caller or callee contains this phone number. Keeps the full matching Call-ID trace. |

For bidirectional analysis of one conversation, prefer `--host` with `--peer`:

```bash
flowpilot analyze capture.pcap --host 10.0.0.5 --peer 198.51.100.20 --no-llm
```

For one direction only, use `--src` and `--dst`:

```bash
flowpilot analyze capture.pcap --src 10.0.0.5 --dst 198.51.100.20 --no-llm
```

For one SIP phone number, use `--sip-phone`. Partial numbers are supported and
separators are ignored, so `0100` or `555-0100` can match SIP URIs containing
`+1-555-0100`:

```bash
flowpilot analyze capture.pcap --sip-phone 0100 --no-llm
```

If a decrypted HTTPS response redirects to a new URL and you want the redirected
traffic included too, combine TLS decryption, your starting flow filter, and
`--include-redirects`:

```bash
flowpilot analyze capture.pcap \
  --tls-keylog-file ~/Downloads/sslkeys.log \
  --host 10.0.0.5 \
  --peer 198.51.100.20 \
  --include-redirects
```

FlowPilot extracts decrypted HTTP `Location` headers from the filtered traffic,
then adds matching DNS, HTTP host, TLS SNI, and resolved-IP flows for those
redirect targets when they are visible in the same capture.

FlowPilot can also summarize certificate metadata exchanged in visible TLS or
DTLS handshakes. The certificate table groups bidirectional authentication under
a stable flow ID and shows which endpoint presented each certificate, so mutual
certificate authentication can appear as multiple endpoint rows for the same
flow. This is capture-based analysis: it reports the certificates observed in
the pcap, not a fresh live probe of the server. If the handshake or certificate
message is missing from the capture, certificate details may not be available.

## TLS decryption

If you have a TLS key log file from the client or server, FlowPilot can pass it
to TShark while reading the capture:

```bash
flowpilot analyze capture.pcap --tls-keylog-file ~/Downloads/sslkeys.log --no-llm
```

The key log file must match the captured TLS sessions, and the capture normally
needs the TLS handshake packets. This uses TShark's `tls.keylog_file` preference;
when decryption succeeds, decrypted protocol layers such as HTTP may become
visible to PyShark. FlowPilot still summarizes metadata and does not send raw
payloads to the LLM.

## Notes

FlowPilot sends derived flow metadata to OpenAI, not raw packet payloads. Review
the generated summary before using LLM reasoning on sensitive captures.
