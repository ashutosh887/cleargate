# Recording the 3-minute demo video (macOS)

The beats follow `docs/DEMO.md` ("On stage"). These notes cover the capture mechanics.

## Before you record (15 min)

1. Close Slack, Mail and Messages, and turn on Focus (Do Not Disturb) from Control Center.
2. Set the display to 1920x1080 or 1600x900 (System Settings > Displays). Use Chrome zoom 110% on `/bank` and the main UI, and 100% elsewhere.
3. In terminal 1, start the services:
   ```bash
   source .venv/bin/activate
   export CLEARGATE_LLM=scripted PAYEE_CHECK=off
   python scripts/runtime_proof.py        # exit 0: live; otherwise record the stand-in and say so
   cleargate serve --stub --port 8700      # live: CLEARGATE_ENFORCER=agntid cleargate serve --port 8700
   ```
   With `--stub` the badge reads "Local stand-in: simulation, not AgntID". Don't say "AgntID decided" over that footage. `serve` prints an approver key, so keep that terminal off screen.
4. Write the "before" policy for the campaign beat outside the repo (`policy.yaml` minus the `bank-destination-allowlist` rule), and export its path as `BEFORE`.
5. Run the payments incident once in the main UI (**Run incident**, then wait for "run done"), so that **G** has a Go-live screen to show.
6. Open the Chrome tabs in this order:
   1. title or `site/index.html`
   2. `localhost:8700/bank`
   3. a copy of `docs/evolution.html`
   4. PR #3, Checks tab
   5. `localhost:8700`

   Click inside each ClearGate page once, so that the keys B, G and R work.
7. In terminal 2, set the font to 20 pt or larger and put three commands in the history:
   - `CLEARGATE_POLICY=$BEFORE cleargate bank --campaign --stub --seed 7 | tail -12`
   - `cleargate bank --campaign --stub --seed 7 | tail -10`
   - `python verify.py records/<run>-gated.jsonl`
8. Do a mic and speaker test: record 10 seconds plus one spoken agent reply, then play it back on headphones. macOS doesn't capture system audio, so either let the mic pick up the speakers (volume about 60%, no headphones) or add the reply WAV in the edit. To get the WAV: `cleargate bank --demo branch --stub --mode gated --speak --save-audio reply.wav`.

## Start the recording

- Press Cmd+Shift+5 and choose **Record Entire Screen**. Under Options, pick your mic, turn on **Show Mouse Clicks**, and set Save to Desktop. Then click Record.
- QuickTime Player > File > New Screen Recording opens the same toolbar.

## Beats (target times)

| Time | Window | Action |
|---|---|---|
| 0:00–0:15 | Title | "7 of 12 sub-agents lost 'do not modify'." Say the opening line. |
| 0:15–0:32 | `/bank` | Click the LEGIT line. Both panes refund ₹2,340 to the account on file. |
| 0:32–1:05 | `/bank` | Hold **Hold to talk** and say the branch line, or click BRANCH. Stock sends ₹48,000. Gated shows a BLOCK card, and the agent speaks the refusal. Let the audio play. |
| 1:05–1:40 | Terminal 2 | Run the before campaign (stock ₹2,22,840, gated ₹15,580), then the after campaign (gated ₹0). |
| 1:40–2:02 | `evolution.html` | Generation 2: 5 spellings of `main` got through. Then 0 gaps in 585 cases. |
| 2:02–2:20 | PR #3 | Checks tab, red: "NO-GO: merged by the agent with no human approval". |
| 2:20–2:45 | Main UI, then Terminal 2 | Press **G** for the Go-live screen, then press Enter on `verify.py` to show MATCH. |
| 2:45–3:00 | `/bank` | Closing line: "The agent acts. AgntID decides. The engineer signs." |

Stop the recording from the menu-bar stop button, or press Cmd+Ctrl+Esc.

## If something goes wrong

- **The bank call fails.** Click the BRANCH line instead of speaking. If the server is down, run `cleargate bank --demo branch --stub` in the terminal.
- **The incident run stalls.** Press **R** in the main UI. It replays the last signed record in the same UI and the badge changes to "replay". Say so on camera.
- **The Go-live overlay doesn't open.** Press **G**. Esc closes it.
- **Sarvam fails (no audio).** The reply text is still on the card, so read it aloud.

## After recording

- Trim to 3:00 or less in QuickTime with Edit > Trim (Cmd+T). Export with File > Export As > 1080p.
- Watch it once with sound and check:
  - No tokens, approver key, `.env` contents or `/Users/...` paths are readable.
  - Every claim that says "AgntID decided" sits over footage that ran on the runtime.
