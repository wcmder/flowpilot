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
  summary is not a substitute for raw packet evidence.

## Must: follow-up context reaches the provider

- Each follow-up must be self-contained. Do not rely on provider session memory.
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
- Attach `flow_id` and `target_flow` identity to tool results. Use evidence only
  for its matching flow and distinguish successful results from errors.
- Preserve `frame.time_relative` in packet samples where available. It represents
  seconds since capture start, not an absolute date/time.
- Current TCP, UDP, ESP, TLS, and SMB tools return up to the first 200 matching
  packet samples by default. Preserve `sample_limit` and `truncated` indicators;
  do not imply those samples contain the entire flow or its worst event.
- Request an appropriate available tool when more evidence is needed, rather
  than merely telling the user to run it. Do not claim a tool can recover
  measurements that the capture cannot expose.
- Respect reread limits and avoid repeating completed tool requests.

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
