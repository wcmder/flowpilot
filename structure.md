# FlowPilot structure and required behavior

This document records the architecture and requirements that changes must preserve.
Requirements describe the intended contract; regression tests must verify it. See
[README.md](README.md) for installation, configuration, and CLI usage.

## Project structure

| Location | Responsibility |
| --- | --- |
| `src/flowpilot/cli.py` | Commands, saved-summary loading, tables, interactive chat, report output. |
| `src/flowpilot/capture.py` | Read captures through PyShark/TShark and extract packet observations. |
| `src/flowpilot/analysis.py` | Group observations into bidirectional flows and build the summary. |
| `src/flowpilot/models.py` | Packet and flow models, deterministic metrics, compact LLM metadata. |
| `src/flowpilot/reasoning.py` | Provider requests, prompts, chat context, response guards, local metric lookups. |
| `src/flowpilot/workflow.py` | LangGraph orchestration, tool routing, flow targeting, evidence collection. |
| `src/flowpilot/deep_tools.py` | Allow-listed deep-tool registry and dispatch. |
| `src/flowpilot/protocols/registry.py` | Protocol hooks, capabilities, tool registration, analysis guidance. |
| `src/flowpilot/protocols/deep_common.py` | Shared TShark commands, field parsing, endpoint filters. |
| `src/flowpilot/protocols/` | Protocol extraction, aggregation, deep evidence, and detail rendering. |
| `src/flowpilot/filters.py` | Flow and protocol-specific filtering. |
| `src/flowpilot/decode_as.py` | Decode-as settings, including ESP over UDP. |
| `src/flowpilot/paths.py` | Runtime and private-data locations. |
| `tests/` | Model, analysis, CLI, protocol, provider-request, and workflow regressions. |
| `private/` | Local configuration and generated reports; not public documentation. |

## Data flow

```text
PCAP → packet observations → bidirectional CaptureSummary
                                      ↑
                               saved summary JSON
                                      ↓
                            compact LLM metadata
                                      ↓
                       initial analysis / follow-up chat
                                      ↕
                 agent workflow → deep tools → PCAP reread
```

Saved summaries and LLM metadata are different representations. Derived rates are
calculated from the stored counters and timestamps when compact metadata is built.

Detailed creation must save as `<capture>-detailed.json`; custom `--json` names
must also receive the `-detailed` suffix exactly once. `--load-detailed-summary`
must default to this filename, separately from `--load-summary` (`<capture>.json`).
The loading options must be mutually exclusive and must not write JSON unless
`--json` is explicit. Neither loading option may be combined with creation via
`--detailed-summary`. Explicit paths must support older detailed filenames.

Optional `--detailed-summary` adds all selected packet observations and complete
supported deep-tool results to each flow. Compact metadata includes an availability
manifest, not the entire stored dataset. Provider requests attach first-batch
previews and retrieve subsequent saved batches through existing deep tools.

## Must: flow identity and direction

- Flow IDs must refer to the same flow in the CLI, LLM metadata, local answers,
  and deep-tool results. Sorting or limiting the displayed flows must not change
  the identity of a referenced flow.
- A is `endpoint_a`, the first endpoint in the Flow column. B is `endpoint_b`,
  the second endpoint. Include ports when needed to distinguish conversations.
- Directional lists must use `[A_to_B, B_to_A]` consistently.
- Answers must use the requested Flow ID's endpoints and evidence. Never borrow
  an endpoint, metric, or sample from another flow or invent a missing identity.
- An unavailable Flow ID must be reported explicitly. An ambiguous reference
  must be clarified rather than silently mapped to another flow.
- An explicitly requested flow that exists locally must be included in chat
  context even when it falls outside the initial `max_flows` selection.
- The current summary's list order defines its IDs. Compact metadata must not
  independently sort or renumber flows. Add an out-of-limit requested flow with
  its existing ID, and include its endpoints in response validation. This applies
  to both provider APIs and chat fallback requests.

## Must: directional metrics for every protocol

- Shared metric behavior must apply to every flow type, including TCP, UDP, ESP,
  TLS/DTLS, SMB, SIP, DNS, DHCP, ICMP, and unknown protocols. Do not special-case
  ESP for basic directional packet rates or throughput.
- LLM metadata must include both directions in:
  - `packet_rate_per_second_by_direction`, in packets/s.
  - `throughput_mbps_by_direction`, in decimal Mbps.
- Both directions must use the same full-flow first-to-last-packet duration:
  - Packet rate = directional packet count / duration in seconds.
  - Throughput = directional observed bytes × 8 / duration / 1,000,000.
- Missing or zero duration must produce unavailable (`null`) directional rates.
  Zero observed traffic with a valid duration must produce zero.
- LLM flow metadata must omit aggregate `packet_rate_per_second`,
  `byte_rate_per_second`, and `throughput_mbps`, including nested transport
  metadata. Protocol-specific metadata must not reintroduce combined rates,
  such as SMB's former `transfer_mbps` field.
- Internal aggregate calculations and total packet/byte counters may remain
  for diagnostics and bookkeeping. They must not replace directional rates
  in LLM answers.
- The Top Flows Metrics column must omit aggregate `rate` and `thr`.
  Direction must show `thr x/y Mbps` and explain the direction order and interval.
- ESP throughput measures observed encrypted traffic, not inner application
  goodput. Other protocols must also distinguish observed bytes from payload
  goodput where relevant.

## Must: saved-summary compatibility

- `--load-summary` must use saved directional counters and timestamps to derive
  current metrics without an initial PCAP reread.
- Adding derived metadata must not require regenerating a complete saved summary
  that already contains the necessary counters and timestamps.
- Missing source measurements must be treated as unavailable; never invent them.
- Deep tools still require access to the capture file for packet rereads. A saved
  ordinary summary is not a substitute for raw packet evidence. Detailed summaries
  can serve successful saved tool results without a PCAP or TShark; absent details
  still require rereads. Preserve full rows locally and mark the evidence source.
- Detailed summaries must retain selected observations and all supported tool
  rows, record extraction failures, and label their scope. Deep-tool results cover
  the full matching flow; observations may reflect packet-level filters/limits.
  Saving details must not silently place the entire dataset into the LLM context.
- Observation retention applies to every analyzed flow, including ICMP/ICMPv6,
  AH, GRE, and unknown protocols. Application metadata (TLS/DTLS, SMB, SIP, DNS,
  DHCP) is retained on the underlying TCP/UDP observations. Do not claim dedicated
  deep support for protocols without a registered tool. Mark observation-only
  coverage explicitly; failure of one tool must not discard observations or
  prevent collecting the remaining tools.
- Inspecting or filtering a loaded summary must not silently overwrite the
  source summary. Save derived subsets separately unless replacement is explicit.
- `--load-summary` must not write JSON unless `--json` is explicitly supplied,
  whether or not filters are active. Fresh PCAP analysis still saves automatically.
- Write JSON to a temporary file in the destination directory, flush and sync it,
  then atomically replace the destination. Serialization failures, write failures,
  and interrupted writes must not truncate an existing report or publish an empty
  new one. Only announce success after replacement; preserve all detailed rows.
- An explicit `--json` targeting the loaded source redirects to
  `private/<summary>.filtered.json` with filters or `<summary>.reanalyzed.json`
  otherwise. Number existing derived names from `.2.json` onward; distinct explicit
  output filenames remain supported.
- Loaded-summary filters must preserve endpoint/port pairing and document any
  packet-level filtering semantics they cannot reproduce from aggregated data.
- Directional saved-summary filters select whole flows only when one observed
  direction satisfies all source/destination criteria together. Preserve both
  directions' metrics and explain this scope in the CLI. Directions with no saved
  packet count cannot match. Packet-level subsets require a fresh capture read.
- ESP decode settings are explicit per invocation and must not be automatically
  restored from a saved summary. With `--load-summary`, users must repeat
  `--esp-udp-port PORT` (or the bare flag for all ports) when deep rereads require
  UDPENCAP decoding. Reading saved metrics alone does not require this flag.

## Must: follow-up context reaches the provider

- Each follow-up must be self-contained. Do not rely on provider session memory.
- Preserve newly collected deep evidence and completed tool requests across
  chat turns; an answer string alone is not sufficient session state.
- Interactive chat must use `run_agent_chat_state()` and carry its evidence and
  completed request keys into the next turn. `run_agent_chat()` remains a
  standalone answer-only convenience API. Initial-analysis evidence seeds the
  session; a new chat session starts fresh. Reread budgets reset each turn.
- Put retained chat history first, then one final user message containing the
  current question, current summary, requested-flow context, initial report when
  available, and attached deep evidence.
- Keep the question and its evidence together. Do not place prior assistant
  replies between current metadata and a bare follow-up question.
- Current metadata must take precedence over conflicting prior answers,
  including earlier claims that context was missing.
- Retain the latest 12 history messages under the current implementation;
  resending the entire conversation is not required for factual flow lookups.
- This contract must hold for plain and agent chat, Responses and Chat
  Completions, and provider fallback requests.
- Tests must inspect the actual provider-call arguments, not only prompt text.
  Mocked request tests do not establish live provider answer quality.
- Do not solve general context failures by adding a separate hardcoded matcher
  for every question. Local deterministic metric lookups may remain for their
  supported wording; other questions must receive the same authoritative data.

## Must: analyze evidence before giving instructions

- Start diagnostic answers with an assessment of the requested flow, cite actual
  values, and explain what those values support. Recommendations follow analysis.
- Return available calculated results instead of telling users to do arithmetic.
- Do not say the flow table or capture context was not supplied when it is
  attached to the current request.
- Distinguish a supported issue, lack of supporting evidence, and insufficient
  measurement. Missing data does not prove a healthy path.
- For latency, use available initial RTT and matching deep timing evidence.
  Initial TCP RTT measures the handshake; it does not establish sustained or
  excessive latency without an appropriate baseline.
- ACK RTT is currently excluded from compact LLM metadata because it depends on
  capture position. Do not assume it was supplied.
- Throughput, long duration, sequence gaps, and inter-packet spacing alone must
  not be presented as direct latency measurements. Outer ESP timestamps do not
  identify inner request/response latency.
- Keep the default focus on transport troubleshooting. Security analysis must
  follow the selected analysis focus or an explicit user request.

## Must: deep evidence is traceable and bounded

- Route requests through registered, allow-listed tools and validate Flow IDs.
- Match complete endpoint pairs: `(A address/source port → B address/destination
  port) OR (B address/source port → A address/destination port)`. Independent
  `ip.addr` and `tcp.port`/`udp.port` membership tests are insufficient.
- Apply the same pairing rules to IPv4 and IPv6 and to tools layered on TCP/UDP,
  including TLS/DTLS, SMB, and UDP-encapsulated ESP. Bind every known port to its
  endpoint; missing ports must not be invented. Port zero is a valid filter value.
- ESP rereads must require an ESP layer, excluding IKE and NAT keepalives sharing
  UDP/4500. Native ESP filters must exclude UDP-encapsulated ESP conversations.
- UDP-encapsulated ESP must use TShark's `udpencap` decode target for both initial
  reads and deep rereads (`-d udp.port==PORT,udpencap`), not `udp.port==PORT,esp`.
- A bare `--esp-udp-port` must decode all UDP ports using
  `udp.port==0-65535,udpencap`. Explicit port values must remain supported, and
  documentation must explain that forcing all ports can misdecode unrelated UDP.
- Attach `flow_id` and `target_flow` identity to tool results. Use evidence only
  for its matching flow and distinguish successful results from errors.
- Preserve `frame.time_relative` in packet samples where available. It represents
  seconds since capture start, not an absolute date/time.
- TCP, UDP, ESP, TLS, and SMB tools return packet details in batches of 1,000 by
  default. Each result must include `batch.offset`, `returned`,
  `total_matching_packets`, `has_more`, `next_offset`, and a continuation hint.
  Offset counts matching packets in capture order, not global frame numbers.
- The LLM can request the same tool/Flow ID with `sample_offset=next_offset`.
  Deduplication keys must include the offset so later batches are not suppressed.
  Batch evidence and completed offsets persist across chat turns. Keep existing
  per-turn reread budgets and explain when requested batches remain unexamined.
- Each batch's aggregate counters cover all matching packets. Do not sum these
  repeated counters across batches or claim a single batch represents the whole
  flow. Every extracted packet row must remain retrievable from the unchanged
  PCAP or successful saved deep details. Prefer saved rows when available and
  preserve the current Flow ID when a saved result's historical ID differs.
- Request an appropriate available tool when more evidence is needed, rather
  than merely telling the user to run it. Do not claim a tool can recover
  measurements that the capture cannot expose.
- Respect reread limits and avoid repeating completed tool requests.

## Must: large-capture resource use

- Accuracy and preservation of all available data and details take precedence
  over CPU and memory savings. High resource use alone is not a defect for this
  project's intended use.
- Do not discard observations, cap retained RTT data, approximate statistics, or
  reduce evidence merely to save resources. Any performance optimization must
  preserve the same data, detail, and exact results.
- Removing redundant copying (such as copying a growing RTT list on every append)
  is acceptable only when behavior and retained data remain unchanged.
- The 1,000-packet batch size is an LLM delivery size, not a total evidence cap.
  Additional details are retrieved on request. Pagination does not guarantee the
  model has inspected all packets; state remaining coverage honestly.

## Review findings and implementation status

The 2026-09-30 review identified the following gaps. Requirements above are the
target contract; an open row must not be interpreted as already implemented.

| Finding | Status | Required verification |
| --- | --- | --- |
| 1. Deep filters mix distinct conversations | Fixed in this change | Real TShark tests accept both intended directions and reject swapped port/address pairings, wrong peers, and wrong ports on IPv4/IPv6. |
| 2. New deep evidence is lost between chat turns | Fixed | Interactive regression checks retain evidence and completed requests, suppress repeated explicit/provider requests, reuse initial evidence, and isolate new sessions. |
| 3. Loaded-summary filtering can overwrite its source | Fixed | CLI regressions preserve source bytes, repeated derived reports, and source aliases even with explicit JSON output. |
| 4. Flow ID sorting and context limits disagree | Fixed | Unsorted saved summaries retain CLI/tool IDs; an explicitly requested out-of-limit flow and its endpoints reach plain/agent provider requests and pass response validation. |
| 5. Loaded-summary filters differ from packet filters | Fixed | Shared predicates bind addresses to ports, require an observed matching direction, handle port zero, and explain whole-flow retention for saved summaries. |
| 6. ESP decode settings are not persisted | Accepted by design | Decode settings remain explicit per invocation; users repeat `--esp-udp-port` with `--load-summary` when deep rereads require it. No automatic restoration. |
| 7. Large captures incur excessive retention and copying | Accepted resource cost | Prioritize complete data and exact results over resource savings. Only lossless optimizations are appropriate; reduced retention or approximate statistics are not required. |

The review also found an import-formatting lint issue in
`packaging/flowpilot_entry.py`; Windows packaging and live provider behavior were
not verified by that review.

## Must: validation and maintenance

- Exercise shared metadata changes across multiple protocols, including unknown
  flows, and through saved-summary loading.
- Verify direction order, units, missing/zero duration, and one-way traffic.
- Verify exact flow identity and current evidence survive stale chat history,
  provider API selection, and fallback behavior.
- Use regression tests for behavioral changes and run relevant lint checks.
  Documentation-only changes do not require new tests.
- State whether validation used mocks or a live provider. Never claim live LLM
  behavior was verified solely from unit-test results.
- Update this document when an intentional change revises these contracts.

- The Deep Evidence table’s Packets column must show `batch.returned`, the packet
  rows included in that evidence batch for the LLM, not full-flow `packet_count`.
  Include `batch.offset` alongside the count, e.g. `1000 (offset 2000)`.
  Offsets are zero-based matching packet indices, not capture frame numbers.
  Zero must display as `0`; missing batch metadata must display as unknown (`-`).

- `--max-request N` must bound LLM-requested tool rounds per analysis/chat turn
  (default 2, nonnegative), independently of automatic initial tools. Graph
  recursion limits must accommodate the configured number of rounds.

- LLM requests must serialize packet evidence without pretty-print indentation.
  Chat must attach each evidence payload once, with the current question and
  flow identity context; do not duplicate it in a second fenced JSON block.

- `--offset N` must be nonnegative and set the minimum zero-based matching packet
  offset for deep evidence per flow/tool, including cached previews and chat.
  Apply it before completed-request deduplication; later offsets stay absolute.
  It must not filter initial analysis, full-flow counters, or saved packet data.

## Must: RTP/SRTP media support

- Keep media on underlying UDP Flow IDs and shared directional rates. Extract
  visible RTP v2 headers, never media payloads; retain SSRC, sequence, timestamp,
  marker, payload type, and observed/explicit SRTP classification in observations.
- Separate streams by direction and SSRC. Extend 16-bit sequences across rollover,
  count duplicates and reordered unique packets separately, and reconcile late
  arrivals when reporting observed holes. Preserve sequence state in saved JSON.
  Explain ambiguity at restarts/large gaps; observed holes are not proven loss.
- `deep_rtp_flow` must use the registry, exact UDP endpoint pairing and RTP layer
  filter, shared batch/offset semantics, full-flow statistics, and cached detailed
  rows. Detailed UDP collection must include this tool. No RTP/SRTP payload,
  authentication tag, or key material may be included in its evidence fields.
- `--rtp-udp-port` and `--srtp-udp-port` require repeatable integer ports. Both decode
  visible RTP headers; the secure option explicitly marks the user's SRTP knowledge.
  Reject conflicting ESP decode rules. Actual rereads require explicit flags again.
- Do not infer cleartext from missing SRTP indicators, codecs from dynamic payload
  types, or latency/media quality from header timestamps. Clock-rate negotiation,
  jitter calculation, RTCP, decryption, and RTP over TCP remain unsupported.
- Older summaries default to empty media streams; new source measurements require
  a fresh read or explicit deep evidence. Verify real TShark IPv4/IPv6 targeting,
  SDP SRTP recognition, wrapping/reordering, complete saving, and cached batches.
