# Roadmap

ClearGate's job is to make an AgntID deployment reviewable before an agent team goes from pilot to production, for any agent that moves money, changes code or touches customer data. AgntID stays the enforcement point in every item below.

## What exists, and what comes next for each

| Piece | Today | Next |
|---|---|---|
| Bank voice agent (`cleargate bank`) | Five sub-agents, five demo calls, a scripted Hindi-English caller campaign, sandbox ledger; `/bank` page with hold-to-talk; a public call page (https://trycleargate.vercel.app/try.html) for typed and spoken calls | A dial-in phone number, and the call page running through a hosted AgntID runtime instead of the stand-in |
| Attack suite (`cleargate attack-suite`) | 20 fixed attacks in `attacks/catalog.yaml`, fired at stock and through the runtime; 5 spoken attacks replayed through text-to-speech (`scripts/tts_replay.py`: stock 5 of 5, gated 0 of 5) | An adversary agent that writes new attacks for a given task and tool catalogue (tool-description poisoning, scope creep through a legitimate tool, delegation tricks, approval reuse, calls after close) |
| Policy fuzzer (`cleargate evolve`) and coverage matrix (`cleargate coverage`) | Deterministic mutation of every stopped attack; survivors become the CI regression set; attack class × control with an OWASP mapping (86 cases, 0 gated gaps). All-day run on the local stand-in: 118,694 cases across 1,130 generations, 0 gaps (14:34 IST) | Run both through the runtime by default (`--target agntid`) |
| Policy writer (`cleargate propose-policy`) | Proposes the tightest portal configuration from a signed record; shadow replay with the stand-in evaluator | Re-run the attack suite through the runtime under the proposal; apply it to the portal once AgntID offers a policy API |
| CI gate (`cleargate gate`) | Runs on PRs that touch agents, MCP servers, policy or attacks; SARIF output; self-hosted runner next to the runtime; `action.yml` lets any repo add it with `uses: ashutosh887/cleargate@main` | Show results next to AgntID Observatory's metadata scan: Observatory reports what a server exposes, the gate reports what happened at runtime |
| Bring your own agent | Tools implement `ToolClient` (`cleargate/tools/base.py`) and are wired in `build_tools`; MCP servers connect with `CLEARGATE_TOOLS=mcp`; rules in `policy.yaml`; attacks in `attacks/catalog.yaml` | A plug-in registry for tools, and action inputs for your own attack catalogue and task |
| Evidence pack (`cleargate evidence`) | Signed folder for a go-live review, with a claim-checked report | Include the runtime's own Reporting export once one exists |
| Catalog drift ([`attacks/RUGPULL.md`](../attacks/RUGPULL.md)) | Manual demo of AgntID's Catalog Drift view, not yet observed on the runtime | Record the tool list and schemas at every task open (the snapshot id is already in the record) and re-run the attack suite when they change |

OWASP Agentic ids these cover: ASI01, ASI02, ASI03, ASI04, ASI07, ASI08, ASI09, ASI10.

## AgntID-native approvals and signed decisions

Approvals are app-layer today: ClearGate binds them to the argument digest, the spoken code is an HMAC of that digest, and `--durable` keeps a pending approval on disk across restarts. If AgntID holds pending reviews natively, ClearGate becomes the approval UI (the `/oncall` call, web, Slack) and stops being the binder. If the runtime signs its own decisions, the record no longer rests on ClearGate's key.

## Multi-team

One runtime, several agent teams, each with its own task intent, policies, delegation rules and signed record: payments incidents and card disputes, support agents that issue credits, DevOps agents that deploy, healthcare and insurance agents that read patient or claim records, order and returns agents. A per-team GO / NO-GO view for the platform team.

## Portal policy API

Policies are set in the portal by hand and mirrored in `policy.yaml`. With a portal policy API, the policy writer and `cleargate evolve` could apply a proposed rule straight after its shadow replay passes, and the CI gate could diff the portal against the repo.

## Smaller items

- Dual intent matchers: run Standard and LLM-based intent side by side on the same call and record where they disagree.
- Per-run ceiling on state-changing calls (for example, at most one merge per task).
- String parameter rules (channel, branch prefix, recipient domain) once the policy editor supports them, replacing the narrow-tool workaround.
- Output filtering on allowed calls, when AgntID ships it.
