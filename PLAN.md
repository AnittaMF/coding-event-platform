# Coding & Debugging Event Platform — Build Plan

Expand the existing Express app into an **event platform** with a full admin control panel
(only you) and a locked-down participant view.

## Chosen defaults (no preference given — easily changeable)
- **Hosting:** Render.com free tier (public URL to share) + JSON persistence via Render Disk.
  Also documented: run locally over LAN.
- **Evaluation:** Manual scoring by admin now; code structured so auto test-case grading can
  be added later without a rewrite.
- **Accounts:** You create/bulk-generate participant logins in the admin panel.

## Roles & access control
- `admin` (you): full control panel. Cannot be reached by participants.
- `participant`: only sees login + exam. All admin APIs reject non-admins (already the pattern
  via the `auth` + role check in server.js).
- Admin credentials come from environment variables in production (not hard-coded).

## Question model (supports Coding AND Debugging, 5 questions)
Each question: `id`, `type` ("coding" | "debugging"), `title`, `description`, `marks`,
`starterCode` (buggy code to fix, for debugging type), `language` label.
Admin adds the 5 questions your guide sends. Config also allows setting the event to exactly 5.

## Admin control panel (new `public/admin.html`)
1. **Questions manager** — add / edit / delete / reorder the 5 questions (coding or debugging),
   set marks, starter/buggy code. Stored in `data/questions.json`.
2. **Participants manager** — add single participant, bulk-generate N accounts (auto
   usernames + random passwords), view list, delete, download credentials as CSV.
3. **Event control** — set duration & max tab-switches; Start / Stop event (participants can
   only log in while event is open); live status.
4. **Evaluation dashboard** — table of all submissions; open any participant's answers per
   question, assign marks, add remarks, see auto-calculated totals and a leaderboard;
   export results to CSV.

## Backend changes (`server.js`)
- Move questions to `data/questions.json` (admin-editable) instead of a hard-coded array.
- Add `data/config.json` (duration, maxViolations, eventOpen).
- New admin-only APIs: manage questions, manage participants, event start/stop, list
  submissions, save scores, export CSV.
- Participant APIs respect `eventOpen` and return questions **without** any hidden fields.
- Keep scrypt hashing; admin password from `ADMIN_USER`/`ADMIN_PASS` env vars.

## Participant view (existing `public/index.html`)
- Keep current features (one-by-one display, switch/skip/next, tab-switch anti-cheat,
  timer, unattended summary).
- Add debugging-question rendering: show buggy starter code preloaded in the editor to fix.

## Deployment
- Add `render.yaml`, `.gitignore`, `.env.example`, and a README with click-by-click
  Render deploy steps (GitHub → Render → set env vars → share URL), plus local-LAN steps.

## Testing before handoff
- Start server, exercise every admin API (create question, bulk users, start/stop event,
  submit as participant, score it, export CSV) via curl + browser preview.

## Out of scope for now (notable)
- Sandboxed code execution / auto-grading (kept as a clean extension point).
- Real database (JSON files are enough for a single event; Render Disk persists them).
