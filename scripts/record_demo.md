# Recording the 3-minute demo video (macOS)

The narration and beats follow `docs/DEMO.md`. These are the capture mechanics.

## Before you record (5 min)

1. Close Slack, Mail, and any other app that pops notifications. Turn on Focus (Do Not Disturb) from Control Center.
2. Set the display to 1600x900 or 1920x1080 (System Settings > Displays). Chrome zoom 100%.
3. Terminal 1, start the server:
   - Real runtime: `CLEARGATE_ENFORCER=agntid .venv/bin/cleargate serve --approve web --port 8700`
   - Fallback: `.venv/bin/cleargate serve --stub --approve web --port 8700`. The header badge will read "Local policy stand-in, not AgntID". Don't say "AgntID decides" over that footage.
4. Chrome window 1, full screen (Ctrl+Cmd+F): `http://localhost:8700`. Click the page once so the keys R and G work.
5. Chrome window 2: AgntID portal with Reporting and the Simulator open in tabs.
6. Phone: open the `/oncall` URL printed on the ESCALATE card (same Wi-Fi). Keep it unlocked, volume up.
7. Terminal 2: `python verify.py records/<run>-gated.jsonl` typed but not run. Font size 20pt or larger (Cmd +).
8. Mic: run a 10-second test recording and play it back.

## Start the recording

- Press Cmd+Shift+5, choose **Record Entire Screen**. Under Options pick your mic, turn **Show Mouse Clicks** on, and set Save to Desktop. Click Record.
- Alternative: QuickTime Player > File > New Screen Recording opens the same toolbar.
- To capture the phone, connect it by USB and use QuickTime > File > New Movie Recording, then pick the iPhone as the camera. Record it as a separate clip, or film it with a second phone.

## Beats (target times)

| Time | Window | Action |
|---|---|---|
| 0:00–0:20 | ClearGate | Title strip is visible. Say the opening line. |
| 0:20–0:45 | ClearGate | Click the mic and speak the incident (or click **Run incident**). Point at NARROW "49 → 11" and the green ALLOW cards. |
| 0:45–1:15 | ClearGate | Scroll the right pane to the red BLOCK cards (export, email, write to main). Left pane shows the same calls EXECUTED. |
| 1:15–1:50 | ClearGate + phone | ESCALATE card shows "Say approve `xxxx`". Answer on the phone, or click the card's mic, and say "approve x x x x". The merge goes green, then the swapped target turns red with "Approval is not a bypass". |
| 1:50–2:10 | Chrome window 2 | Switch with Cmd+` to show Reporting, then the Simulator audit for the export. Skip this beat if the run used the stand-in. |
| 2:10–2:35 | Terminal 2 | Press Enter on `verify.py` and show MATCH. |
| 2:35–3:00 | ClearGate | Press **G** for the Go-live screen. Say the closing line only if every check is green. |

Stop the recording from the menu-bar stop button, or press Cmd+Ctrl+Esc.

## If something goes wrong live

- If the run stalls or errors, press **R** in the ClearGate window. It replays the last signed record at the same pace in the same UI, and the badge changes to "replay". Say so on camera.
- If voice approval fails, click **Approve** on the card. The record still binds the approval to the arguments digest.
- If the Go-live overlay doesn't open, press **G**. Esc closes it.
- If the take can't be saved, use the 90-second shot list at the bottom of `demo-script-final.md` with the stills in `docs/screenshots/` (regenerate them with `python scripts/capture.py`).

## After recording

- Trim with QuickTime > Edit > Trim (Cmd+T) to 3:00 or less. Export with File > Export As > 1080p.
- Watch it once with sound. Check that the code you spoke matches the code on screen, and that no tokens, `.env` contents, or `/Users/...` paths are readable. The Go-live footer prints the absolute record path.
