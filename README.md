# FlowPilot

FlowPilot is an agentic data-flow troubleshooting tool for packet captures. It
uses PyShark/TShark to extract network conversations and OpenAI-compatible LLM
reasoning to diagnose transfer problems such as TCP retransmissions, UDP
reachability, RTP/SRTP media headers, ESP/IPsec flows, one-way traffic, resets, zero windows, and possible
path issues. Optional LangGraph agent mode routes LLM reasoning and follow-up
chat through a stateful workflow that can be extended with targeted rereads.

## What it does

- Reads `.pcap` / `.pcapng` files with PyShark.
- Aggregates packets into bidirectional flows.
- Highlights top talkers, protocols, ports, DNS names, ESP SPIs, ESP sequence
  gaps/out-of-order/duplicate indicators, and TCP issue counters when TShark
  exposes them.
- Extracts TLS certificate metadata observed in the capture when TShark exposes
  it, including subject, issuer, serial, validity, SAN DNS names, and SHA-256
  fingerprint.
- Analyzes RTP/SRTP headers per direction and SSRC, including sequence holes,
  duplicates, and reordering. Supports explicit media-port decoding and batched
  deep evidence. See [RTP and SRTP media headers](#rtp-and-srtp-media-headers).
- Extracts SIP call metadata such as call ID, caller, callee, methods, response
  statuses, and failure response issues when visible.
- Extracts SMB/SMB2 metadata such as commands, NT status values, session/tree
  IDs, filenames, read/write operation counts, transfer bytes, and transfer
  efficiency hints when visible.
- Extracts DNS metadata such as queries, query types, response codes, answers,
  and DNS error indicators when visible.
- Extracts DHCP metadata such as message types, transaction IDs, client MACs,
  hostnames, requested/offered IPs, server IDs, and lease times when visible.
- Calculates local troubleshooting metrics such as retransmission/loss rates,
  local RTT fields when available, one-way flow detection, packet rate, and
  throughput.
- Optionally asks an OpenAI model to reason over the flow summary and return
  likely network causes, evidence, and next troubleshooting actions.
- Optionally uses LangGraph for agentic LLM reasoning and interactive follow-up
  chat while keeping packet analysis deterministic.

## Architecture notes

See [structure.md](structure.md) for the module map and required behavior for
flow identity, directional metrics, saved summaries, chat context, and deep evidence.

FlowPilot is moving toward protocol and deep-tool registries so new protocol
support can be added with fewer cross-cutting edits. Deep reread tools are
registered in `src/flowpilot/deep_tools.py`. Protocol metadata is registered in
`src/flowpilot/protocols/`; at this stage it documents existing protocol
capabilities and extension points while the current parser and renderer behavior
remains unchanged.

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

FlowPilot also loads a local `private/.env` file automatically. Create one from
the example and put your real local values there:

```bash
mkdir -p private
cp .env.example private/.env
```

OpenAI's Python SDK reads `OPENAI_API_KEY` from the environment after
`private/.env` is loaded. A legacy root `.env` is still loaded as a fallback, but
new local secrets should live under `private/`.
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

For slow models or gateways, set the per-request timeout:

```bash
export FLOWPILOT_LLM_TIMEOUT_SECONDS="300"
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

For an internal OpenAI-compatible LLM gateway, create a local `private/.env` file
on the air-gapped machine:

```bash
mkdir -p private
cp .env.example private/.env
```

Then set values such as:

```bash
OPENAI_API_KEY="your_internal_key"
FLOWPILOT_OPENAI_BASE_URL="https://your-internal-llm-gateway.example/v1"
FLOWPILOT_LLM_API="chat_completions"
FLOWPILOT_MODEL="your-internal-model-name"
FLOWPILOT_LLM_REQUESTS_PER_MINUTE="120"
FLOWPILOT_LLM_TIMEOUT_SECONDS="300"
```

Use `flowpilot models` to confirm the API key, base URL, and model endpoint work
inside the restricted network.

## Windows exe packaging

Build the Windows executable on a Windows machine with Python installed:

```powershell
git clone <your-flowpilot-repo-url>
cd FlowPilot
python -m venv build-flowpilot
.\build-flowpilot\Scripts\Activate.ps1
.\packaging\build_windows.ps1 -Clean
```

The distributable folder is:

```text
dist\FlowPilot\
```

Give users that whole folder. The expected layout is:

```text
FlowPilot\
  flowpilot.exe
  README.md
  private\
    .env
```

Users should only need to edit:

```text
FlowPilot\private\.env
```

Example `private\.env` values:

```text
OPENAI_API_KEY="your_api_key_here"
FLOWPILOT_OPENAI_BASE_URL="https://your-openai-compatible-endpoint.example/v1"
FLOWPILOT_LLM_API="chat_completions"
FLOWPILOT_MODEL="your-model-name"
FLOWPILOT_LLM_REQUESTS_PER_MINUTE="120"
FLOWPILOT_LLM_TIMEOUT_SECONDS="300"
```

Run from PowerShell:

```powershell
.\flowpilot.exe models
.\flowpilot.exe analyze C:\captures\sample.pcap --no-llm
```

TShark is still required on the Windows system. Install Wireshark/TShark and
make sure `tshark.exe` is on `PATH`, or run FlowPilot from a shell where
Wireshark's install directory is already in `PATH`. If deep tools report that
TShark was not found, set the full path in `private\.env`:

```text
FLOWPILOT_TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
```

## Usage

Summarize a capture without calling the LLM:

```bash
flowpilot analyze capture.pcap --no-llm
```

Local `--no-llm` output includes packet counts, byte counts, directionality,
retransmission/loss rates, local RTT fields when TShark exposes them, packet
rate, TCP issue counters, and visible SIP/SMB protocol clues.
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
bytes, SMB transfer Mbps, readable command/status labels, files, and hints for
suboptimal file transfer behavior such as small read/write sizes, errors, low
throughput, or large idle gaps.
DNS details include query names, query types, response codes, answers, and error
counts such as NXDOMAIN/SERVFAIL/refused when visible. DHCP details include
message types such as Discover/Offer/Request/ACK, client identifiers, requested
and offered addresses, server IDs, and lease times.

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

Run LLM reasoning and chat through the LangGraph workflow:

```bash
flowpilot analyze capture.pcap --agent --chat
```

Agent mode runs local packet analysis first, then uses a LangGraph state graph for
LLM reasoning and tool routing. By default, the LLM decides whether to request
deep rereads through structured `evidence_requests`; FlowPilot only honors
allow-listed tools and caps reread loops.

In interactive `--agent --chat`, FlowPilot also detects explicit user requests
before sending the question to the LLM. To force a deep reread reliably, include
one of the allow-listed tool names and a Flow ID in the chat prompt:

```text
use deep_tls_flow for flow id 2
run deep tls flow for flow 2
run deep_tcp_flow for flow 5
for flow id 7 use deep_udp_flow
run deep_rtp_flow for flow id 1
run deep smb tool for flow 8
```

The supported deep tools are `deep_tcp_flow`, `deep_udp_flow`, `deep_tls_flow`,
`deep_smb2_flow`, `deep_esp_flow`, and `deep_rtp_flow`. Spaced or hyphenated forms such as `deep tls flow`,
`deep-smb2-flow`, `deep smb2 tool`, and `deep smb tool` are also accepted.
When one of those tool names appears with a Flow ID, LangGraph runs the tool
first and sends the result back to the LLM as `additional_tool_evidence`.

To also run the deterministic pre-router before the first LLM request, add:

```bash
flowpilot analyze capture.pcap --agent --agent-auto-tools --chat
```

`--agent-auto-tools` calls allow-listed tools when local protocol symptoms need
packet-header detail: `deep_tcp_flow` for TCP loss, retransmission, reset,
zero-window, one-way, or low-throughput indicators; `deep_udp_flow` for DNS/DHCP
errors, incomplete DHCP exchanges, visible DNS transactions, or one-way UDP
flows; and `deep_tls_flow` for TLS/DTLS SNI, certificate chains, alerts,
handshake fields, cipher/hash/signature/group algorithms, and related TCP or UDP
headers; and `deep_smb2_flow` for SMB2 credit charge, request/grant, statuses,
read/write lengths, offsets, file IDs, filenames, and related TCP symptoms. The
TCP tool sends sequence, ACK, flags, window, TCP length, and Wireshark TCP
analysis markers. The UDP tool sends UDP ports, length, checksum status, DNS
transaction ID/query/type/rcode/answers/timing, and DHCP
transaction/message/client/server/lease metadata.

List models from the configured OpenAI or OpenAI-compatible endpoint:

```bash
flowpilot models
flowpilot models --json
```

`flowpilot models` prints the `/models` URL it called before listing models.
With `--json`, the output includes both `url` and `models`.

FlowPilot always writes machine-readable output:

```bash
flowpilot analyze capture.pcap --no-llm
flowpilot analyze capture.pcap --json report.json
```

JSON reports are written under the local `private/` folder on every `analyze`
run. By default, FlowPilot uses the capture filename with `.json`, so
`capture.pcap --no-llm` writes `private/capture.json`. Use `--json report.json`
only when you want a different output filename, such as `private/report.json`.
The JSON also records the source capture path so loaded summaries can still
point agent deep tools back to the original pcap. The JSON summary stores all
summarized flows; the `--show-flows` setting only limits terminal display, and
`--max-flows` limits the initial flow selection sent to the LLM. A follow-up
explicitly naming a Flow ID also includes that flow when it is outside the limit,
preserving the same ID shown in the CLI.

For large captures, you can do the expensive local pass once, review the local
tables, then reuse that saved summary for a later LLM/agent run:

```bash
flowpilot analyze capture.pcap --no-llm
flowpilot analyze capture.pcap --load-summary --agent --chat --port 443
```

With `--load-summary`, directional options (`--src`, `--dst`, `--src-port`,
`--dst-port`) select whole flows with an observed direction matching all criteria.
Addresses and ports stay paired; both directions' counters, duration, and metrics
are retained. Directions without saved packet counts cannot match. Omit
`--load-summary` when you need a packet-level directional subset.

`--load-summary` skips the initial PyShark packet walk and applies flow filters
to the saved flow metadata. If you omit the filename, it loads the same
capture-derived summary name, such as `private/capture.json`. Deep tools reread the command-line capture path
when it is available; if that path is missing, FlowPilot falls back to the
`source_capture_path` recorded in the loaded summary.

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
| `--agent` | Route LLM reasoning and interactive chat through the LangGraph workflow. Deep TCP/UDP/TLS/SMB2 rereads run only when the LLM requests an allow-listed tool. |
| `--agent-auto-tools` | With `--agent`, run deterministic deep TCP/UDP/TLS/SMB2/ESP/RTP rereads before the first LLM request when local symptoms indicate packet-header detail is useful. |
| `--model TEXT` | OpenAI or OpenAI-compatible model used for reasoning. Defaults to `FLOWPILOT_MODEL` or `gpt-5-mini`. |
| `--analysis-focus transport\|security` | Select the LLM reasoning lens. `transport` is the default for data-transfer troubleshooting; `security` asks the LLM to prioritize security-relevant metadata such as TLS certificates/ciphers/alerts and SMB encryption/signing clues. Local packet analysis is unchanged. |
| `--json [PATH]` | Set the JSON output filename under `private/`. Fresh analysis saves automatically to `<capture>.json`. With `--load-summary`, nothing is saved unless `--json` is supplied. An output targeting the loaded source is redirected to a separate `.filtered.json` or `.reanalyzed.json` report, numbered if necessary, to preserve the source. |
| `--detailed-summary` | Save to `<capture>-detailed.json` (or append `-detailed` to a custom `--json` filename). On a fresh analysis, retain every selected packet observation and all extracted rows from supported deep tools in the saved JSON. Filter to the flow(s) you need first. |
| `--load-detailed-summary [PATH]` | Load detailed JSON, defaulting to `private/<capture>-detailed.json`. Skip the initial PCAP read and reuse saved details. Does not save unless `--json` is supplied. Mutually exclusive with `--load-summary`. |
| `--load-summary [PATH]` | Load a previous `--json` summary and skip the initial pcap read. Defaults to the capture filename with `.json`, such as `private/capture.json`. Flow filters such as `--port`, `--host`, `--peer`, and `--protocol` are applied to summarized flows. |
| `--cache-pcap` | Copy the capture into a temporary FlowPilot session workspace before analysis. This preserves full captured packet bytes and headers for future agentic rereads during the run. |
| `--keep-cache` | Keep the temporary session workspace after analysis for debugging. Implies `--cache-pcap`. |
| `--packet-limit INTEGER` | Stop reading after this many packets. Useful for quick checks on very large captures. |
| `--tls-keylog-file PATH` | Pass a TLS key log file to TShark for decryption, usually an `SSLKEYLOGFILE` generated during capture. |
| `--esp-udp-port [INTEGER]` | Decode UDP as UDPENCAP/ESP. Omit the integer for all UDP ports, or repeat with specific ports. |
| `--rtp-udp-port INTEGER` | Decode a known UDP media port as RTP. Repeat for multiple ports; applies to initial reads and deep rereads. |
| `--srtp-udp-port INTEGER` | Decode visible RTP headers on a known SRTP port and mark it as SRTP based on the explicit setting. Repeatable; does not decrypt media. |
| `--offset INTEGER` | Starting zero-based matching-packet offset per flow/tool, including initial automatic evidence and saved previews. Default `0`; full-flow metrics remain unchanged. |
| `--max-request INTEGER` | Maximum additional LLM-requested tool rounds per analysis/chat turn. Default `2`; `0` disables additional rounds. Initial automatic tools are separate. |
| `--max-flows INTEGER` | Initial flow selection limit for LLM requests; chat additionally includes an explicitly requested Flow ID outside this limit. Does not limit `--json` output. Defaults to `25`. |
| `--show-flows INTEGER` | Maximum flows shown in the terminal table. Does not limit `--json` output. Defaults to `10`. |

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

## ESP over UDP decode-as

Some tunnels, including Cisco SD-WAN deployments, carry ESP-like traffic inside
UDP ports other than NAT-T UDP/4500. If Wireshark only shows UDP until you use
Decode As, pass the same UDP port to FlowPilot:

```bash
flowpilot analyze capture.pcap --esp-udp-port 12346 --protocol esp --no-llm
```

For multiple encapsulation ports, repeat the option:

```bash
flowpilot analyze capture.pcap --esp-udp-port 12346 --esp-udp-port 12366 --agent
```

To apply UDPENCAP decoding to all UDP ports, omit the integer:

```bash
flowpilot analyze capture.pcap --esp-udp-port --agent
```

This forces decoding on every UDP port; it does not automatically distinguish
ESP from unrelated UDP traffic such as DNS or QUIC. Prefer explicit ports for
mixed captures. A bare flag takes precedence if combined with specific ports.

FlowPilot passes `-d udp.port==PORT,udpencap` to TShark/PyShark during the initial
read and to deep TShark rereads, so decoded packets are summarized as ESP while
retaining the outer UDP ports for filtering and deep-tool targeting.
The UDP decode target is `udpencap`, not `esp`; using `esp` directly causes
TShark to reject the command before reading packets.
The bare flag uses `-d udp.port==0-65535,udpencap` for both initial and deep reads.

Decode settings are explicit for each run and are not restored from saved
summaries. Repeat the option with `--load-summary` when using deep tools on
UDP-encapsulated ESP:

```bash
flowpilot analyze capture.pcap --load-summary --esp-udp-port 12366 --agent --chat
```

Repeat the bare flag instead if all-port decoding is intended. The flag is not
needed just to inspect saved ESP metrics; deep rereads also require the PCAP.

## Notes

### Detailed summaries for selected flows

Use normal flow filters with `--detailed-summary` to build a reusable analysis
package. For example, for one ESP-over-UDP conversation:

```bash
flowpilot analyze capture.pcap --host 10.0.0.1 --peer 10.0.0.2 --port 12366 --protocol ESP --esp-udp-port 12366 --detailed-summary --no-llm
flowpilot analyze capture.pcap --load-detailed-summary --agent --chat
```

Each saved flow contains `packet_details` (all selected extracted observations)
and `deep_details` (complete supported tool results, without the 1,000-row storage
limit). TCP captures include TCP, TLS, and SMB tool results; UDP captures include
UDP, TLS/DTLS, and RTP/SRTP header results; ESP captures include ESP results. Extraction failures
are recorded explicitly and reported in the CLI. Unsupported protocols retain
their packet observations but do not gain new deep-tool capabilities.

The LLM receives first-batch previews automatically and can request additional
saved batches. Successful saved tool results do not require the PCAP, TShark, or
decode flags to be supplied again. Missing tool details still require the original
PCAP and explicit decode options. The original capture remains necessary for
fields and packet bytes that FlowPilot did not extract.

Detailed collection performs additional TShark reads during creation. Deep-tool
rows cover the full matching flow for that tool's protocol filter; packet
observations reflect the initial packet limit and packet-level filters. Prefer
whole-flow filters and omit packet limits when building a complete flow package.
Use `--detailed-summary` on a fresh read, without either loading option. Load the
result with `--load-detailed-summary`; `--load-summary` continues to default to the
regular `<capture>.json`. Older detailed files can be loaded by supplying their
filename explicitly to `--load-detailed-summary`. Large saved flows are still sent in batches,
not as one unbounded LLM request.

Deep tools deliver packet details in batches of 1,000 matching packets. Results
include total packet count, current offset, `has_more`, and `next_offset`, with an
explicit hint that more details are available. The agent can request the same tool
and Flow ID with `sample_offset` set to `next_offset`. Full-flow counters are
repeated in each batch and must not be summed across batches.

If a turn reaches its tool limit, ask “continue reviewing the next batch for flow
ID 1.” Earlier batches and completed offsets are retained within the chat session.
Pagination uses saved detailed results when available; otherwise it rereads the
original PCAP, which must remain available and unchanged.
It does not automatically send every packet in a single LLM request or guarantee
that the model has reviewed the complete flow.

FlowPilot sends derived flow metadata to OpenAI, not raw packet payloads. Review
the generated summary before using LLM reasoning on sensitive captures.

`--max-request NUMBER` controls the maximum LLM-requested deep-tool rounds with
`--agent` (default `2`, minimum `0`). It applies separately to initial analysis
and each chat turn. Each round may request multiple tools. Automatic initial
tools from `--agent-auto-tools` are separate; `--max-request 0` disables only subsequent
LLM-requested tools. For example, `--agent --agent-auto-tools --max-request 1` allows
one additional round after the initial evidence. This limits rounds, not tokens.

Use `--offset 5000` to skip the first 5,000 matching packet rows when retrieving
deep evidence (including saved detailed previews). Each flow/tool starts at its
own zero-based offset; this is not a capture frame number. Later batches continue
from their absolute offsets (5,000, 6,000, 7,000 with 1,000-row batches). Earlier
sample requests are clamped to the starting offset. Full-flow metrics and saved
summary contents are unchanged. An offset past the matching packets returns an
empty batch. No summary regeneration is needed.

```bash
flowpilot analyze capture.pcap --load-summary --agent --agent-auto-tools --offset 5000 --max-request 2
```

## RTP and SRTP media headers

FlowPilot recognizes RTP/SRTP when TShark decodes it (for example, from captured
SIP/SDP signaling). Media stays on its underlying **UDP Flow ID**; select it using
`--protocol UDP`, endpoints, and ports. The RTP/SRTP Streams table and LLM metadata
separate direction and SSRC, with packet counts, payload types, duplicates,
out-of-order arrivals, and observed sequence holes. Directional rates retain the
same whole-flow interval as other protocols.

For captures without signaling, explicitly decode known media ports:

```bash
flowpilot analyze media.pcap --rtp-udp-port 5004 --agent --agent-auto-tools
flowpilot analyze media.pcap --srtp-udp-port 5004 --detailed-summary --no-llm
flowpilot analyze media.pcap --load-detailed-summary --agent --chat --offset 1000
```

Both port options are repeatable and require an integer. `--srtp-udp-port` means
the user knows that port carries SRTP; it decodes visible RTP headers and labels
that security assumption, without decrypting media. Do not force arbitrary UDP
traffic to RTP. RTP/SRTP ports must not overlap ESP decode-as ports. Repeat decode
options for actual PCAP rereads; successful saved deep details need no decode flags.

`deep_rtp_flow` is available to the agent and explicit chat requests. It uses exact
bidirectional address/port matching and preserves frame numbers, capture-relative
times, SSRC, sequence, RTP timestamp, marker, and payload type. It supports the
same 1,000-row batches, `--offset`, `--max-request`, and saved-detail retrieval as
other tools. Detailed creation retains all extracted media header rows for UDP
flows. It never extracts media payload bytes into the tool result.

Sequence numbers wrap at 65,536. FlowPilot extends them to the nearest sequence
cycle and reconciles late arrivals; restarts and gaps of half a sequence space or
more remain ambiguous. Holes in the observed sequence range do not prove network
loss. Dynamic payload types alone do not identify codec or clock rate. This version
does not resolve clock rates, calculate RTP jitter/latency/MOS, decrypt SRTP, analyze
RTCP reports, or support RTP over TCP. Missing SRTP detection does not prove cleartext.

Existing summaries still load. Regenerate from the PCAP to populate new RTP stream
metadata; old summaries can request `deep_rtp_flow` explicitly when the capture is
available. Header definitions follow the [Wireshark RTP field reference](https://www.wireshark.org/docs/dfref/r/rtp.html)
and [SRTP specification](https://www.rfc-editor.org/rfc/rfc3711.html).
