/**
 * Coding & Debugging Event Platform — Backend
 * -------------------------------------------------
 * Express server with two roles:
 *   - admin (you)        : full control panel (questions, participants, event, evaluation)
 *   - participant        : login + take the exam only; no admin access
 *
 * Storage: plain JSON files under ./data (no database needed).
 *   data/config.json        -> event settings (duration, max violations, open/closed)
 *   data/questions.json     -> the questions you add (coding + debugging)
 *   data/participants.json  -> participant accounts (username + hashed password)
 *   data/submissions/*.json -> one file per participant submission (with scores)
 *
 * Admin credentials come from environment variables in production:
 *   ADMIN_USER (default "admin")   ADMIN_PASS (default "admin@123")
 */
const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const axios = require("axios");
// Allow overriding where data lives (Render Disk mounts at /var/data, for example)
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const SUBMISSIONS_DIR = path.join(DATA_DIR, "submissions");
const CONFIG_FILE = path.join(DATA_DIR, "config.json");
const QUESTIONS_FILE = path.join(DATA_DIR, "questions.json");
const PARTICIPANTS_FILE = path.join(DATA_DIR, "participants.json");

const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS ||"admin@123";


app.use(express.json({ limit: "2mb" }));
const cors=require("cors");

app.use(cors());

app.use(express.json({ limit:"2mb" }));
app.use(express.static(path.join(__dirname,"public")));


/* =======================================================================
   Small JSON file helpers
   ======================================================================= */
function readJSON(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

/* =======================================================================
   Password hashing (scrypt — built into Node, no extra dependency)
   ======================================================================= */
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const check = crypto.scryptSync(password, salt, 64).toString("hex");
  const a = Buffer.from(check, "hex");
  const b = Buffer.from(hash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/* =======================================================================
   First-run data bootstrap
   ======================================================================= */
function ensureData() {
  fs.mkdirSync(SUBMISSIONS_DIR, { recursive: true });

  if (!fs.existsSync(CONFIG_FILE)) {
    writeJSON(CONFIG_FILE, {
      eventName: "Coding & Debugging Event",
      durationMinutes: 30,
      maxViolations: 1,
      eventOpen: false, // participants can only log in when you start the event
    });
  }
  if (!fs.existsSync(QUESTIONS_FILE)) {
    // Two sample questions so the platform works immediately — replace via admin panel.
    writeJSON(QUESTIONS_FILE, [
      {
        id: genId(),
        type: "coding",
        title: " ",
        marks: 10,
        language: " ",
        description:
          "  ",
        starterCode: "",
      },
      {
        id: genId(),
        type: "debugging",
        title: "Fix the Sum Function",
        marks: 10,
        language: "Python",
        description:
          "The function below should return the sum of a list but has a bug. Find and fix it.",
        starterCode:
          "def sum_list(nums):\n    total = 0\n    for n in nums:\n        total = n      # BUG: should add, not assign\n    return total",
      },
    ]);
  }
  if (!fs.existsSync(PARTICIPANTS_FILE)) {
    writeJSON(PARTICIPANTS_FILE, []);
  }
}

function genId() {
  return crypto.randomBytes(6).toString("hex");
}

ensureData();

/* =======================================================================
   Data accessors
   ======================================================================= */
const getConfig = () => readJSON(CONFIG_FILE, {});
const setConfig = (c) => writeJSON(CONFIG_FILE, c);
const getQuestions = () => readJSON(QUESTIONS_FILE, []);
const setQuestions = (q) => writeJSON(QUESTIONS_FILE, q);
const getParticipants = () => readJSON(PARTICIPANTS_FILE, []);
const setParticipants = (p) => writeJSON(PARTICIPANTS_FILE, p);

/* =======================================================================
   Auth — token sessions kept in memory
   ======================================================================= */
const sessions = new Map(); // token -> { username, role, violations }

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}
function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  const session = sessions.get(token);
  if (!session) return res.status(401).json({ error: "Not logged in" });
  req.session = session;
  req.token = token;
  next();
}
function adminOnly(req, res, next) {
  if (req.session.role !== "admin")
    return res.status(403).json({ error: "Admin access only" });
  next();
}

/* =======================================================================
AUTH ROUTES
======================================================================= */

// Unified login for admin and participants

app.post("/api/login", (req, res) => {

    const { username, password } = req.body || {};

    if (!username || !password) {
        return res.status(400).json({
            error: "Username and password required"
        });
    }


    // Admin login

    if (
        username === ADMIN_USER &&
        password === ADMIN_PASS
    ) {

        const token = makeToken();

        sessions.set(token, {
            username,
            role: "admin",
            violations: 0
        });


        return res.json({
            token,
            username,
            role: "admin"
        });

    }


    // Participant login

    const participants = getParticipants();

    const user = participants.find(
        p => p.username === username
    );


    if (!user) {
        return res.status(401).json({
            error:"Invalid username or password"
        });
    }


    const valid = verifyPassword(
        password,
        user.salt,
        user.hash
    );


    if (!valid) {
        return res.status(401).json({
            error:"Invalid username or password"
        });
    }


    const token = makeToken();

    sessions.set(token,{
        username,
        role:"participant",
        violations:0
    });


    res.json({
        token,
        username,
        role:"participant"
    });

});

/* =======================================================================
   PARTICIPANT ROUTES
   ======================================================================= */

// Questions WITHOUT any admin-only fields; participants get what they need to answer.
app.get("/api/questions", auth, (req, res) => {
  const questions = getQuestions().map((q, i) => ({
    id: q.id,
    number: i + 1,
    type: q.type,
    title: q.title,
    marks: q.marks,
    language: q.language,
    description: q.description,
    starterCode: q.type === "debugging" ? q.starterCode || "" : "",
  }));
  res.json({ questions });
});

// Record a tab-switch violation server-side (can't be reset by refreshing)
app.post("/api/violation", auth, (req, res) => {
  const s = req.session;
  s.violations = (s.violations || 0) + 1;
  const max = getConfig().maxViolations || 1;
  res.json({ violations: s.violations, autoSubmit: s.violations >= max });
});

// Submit answers. One submission file per participant (latest overwrites).
app.post("/api/submit", auth, (req, res) => {
  const { answers, autoSubmitted } = req.body || {};
  if (!Array.isArray(answers))
    return res.status(400).json({ error: "answers array required" });

  const questions = getQuestions();
  const submission = {
    username: req.session.username,
    submittedAt: new Date().toISOString(),
    autoSubmitted: !!autoSubmitted,
    violations: req.session.violations || 0,
    answers: answers.map((a) => ({
      id: a.id,
      status: a.status,
      answer: String(a.answer || "").slice(0, 100000),
    })),
    // Scoring is filled in by the admin later
    scores: {}, // { questionId: marksAwarded }
    remarks: "",
    totalScore: null,
    maxScore: questions.reduce((s, q) => s + (Number(q.marks) || 0), 0),
  };

  const safeName = req.session.username.replace(/[^a-z0-9_-]/gi, "_");
  writeJSON(path.join(SUBMISSIONS_DIR, `${safeName}.json`), submission);

  const attended = submission.answers.filter((a) => a.status === "answered").length;
  res.json({ ok: true, attended, total: questions.length, notAttended: questions.length - attended });
});

app.post("/api/run", auth, async (req, res) => {
    try {
        const { source_code, language_id, stdin } = req.body || {};

        // Validate code
        if (!source_code || !String(source_code).trim()) {
            return res.status(400).json({
                output: "Please enter some code first.",
                status: "Error"
            });
        }

        // Validate language
        if (!language_id) {
            return res.status(400).json({
                output: "Please select a programming language.",
                status: "Error"
            });
        }

        // Your local Judge0 Docker server
        const JUDGE0_URL =
            process.env.JUDGE0_URL || "http://localhost:2358";

        // Token from judge0.conf / environment
        const JUDGE0_TOKEN =
            process.env.JUDGE0_TOKEN ||
            "MyJudge0Secret_2026_ChangeThis";

        console.log("================================");
        console.log("Running code with Judge0");
        console.log("Judge0 URL:", JUDGE0_URL);
        console.log("Language ID:", language_id);
        console.log("================================");

        const response = await axios.post(
            `${JUDGE0_URL}/submissions`,
            {
                source_code: String(source_code),
                language_id: Number(language_id),
                stdin: stdin ? String(stdin) : ""
            },
            {
                params: {
                    base64_encoded: "false",
                    wait: "true"
                },
                headers: {
                    "Content-Type": "application/json",
                    "X-Judge0-Token": JUDGE0_TOKEN
                },
                timeout: 30000
            }
        );

        const result = response.data || {};

        console.log("Judge0 response:", result);

        // Runtime error
        if (result.stderr) {
            return res.json({
                output: result.stderr,
                status: result.status?.description || "Runtime Error"
            });
        }

        // Compilation error
        if (result.compile_output) {
            return res.json({
                output: result.compile_output,
                status: result.status?.description || "Compilation Error"
            });
        }

        // Normal output
        if (
            result.stdout !== undefined &&
            result.stdout !== null
        ) {
            return res.json({
                output: result.stdout,
                status: result.status?.description || "Accepted"
            });
        }

        // Judge0 error message
        if (result.message) {
            return res.status(400).json({
                output: result.message,
                status: result.status?.description || "Error"
            });
        }

        return res.json({
            output: "",
            status: result.status?.description || "Finished"
        });

    } catch (err) {
        console.error("========== JUDGE0 ERROR ==========");
        console.error("Status:", err.response?.status);
        console.error("Response:", err.response?.data);
        console.error("Message:", err.message);
        console.error("==================================");

        if (err.response) {
            return res.status(500).json({
                output:
                    "Judge0 error (" +
                    err.response.status +
                    "):\n\n" +
                    JSON.stringify(
                        err.response.data,
                        null,
                        2
                    ),
                status: "Error"
            });
        }

        if (err.code === "ECONNABORTED") {
            return res.status(504).json({
                output: "Code execution timed out.",
                status: "Timeout"
            });
        }

        return res.status(500).json({
            output:
                "Could not connect to Judge0.\n\n" +
                err.message,
            status: "Connection Error"
        });
    }
});


/* =======================================================================
   ADMIN ROUTES — all gated by auth + adminOnly
   ======================================================================= */
const admin = express.Router();
admin.use(auth, adminOnly);
app.use("/api/admin", admin);

/* ---- Config / event control ---- */
admin.get("/config", (req, res) => res.json(getConfig()));

admin.put("/config", (req, res) => {
  const c = getConfig();
  const { eventName, durationMinutes, maxViolations } = req.body || {};
  if (eventName !== undefined) c.eventName = String(eventName);
  if (durationMinutes !== undefined) c.durationMinutes = Math.max(1, Number(durationMinutes) || 30);
  if (maxViolations !== undefined) c.maxViolations = Math.max(1, Number(maxViolations) || 3);
  setConfig(c);
  res.json(c);
});

admin.post("/event/:action", (req, res) => {
  const c = getConfig();
  c.eventOpen = req.params.action === "start";
  setConfig(c);
  res.json({ eventOpen: c.eventOpen });
});

/* ---- Questions manager (full CRUD) ---- */
admin.get("/questions", (req, res) => res.json({ questions: getQuestions() }));

admin.post("/questions", (req, res) => {
  const { type, title, marks, language, description, starterCode } = req.body || {};
  if (!title || !description)
    return res.status(400).json({ error: "Title and description are required" });
  const questions = getQuestions();
  const q = {
    id: genId(),
    type: type === "debugging" ? "debugging" : "coding",
    title: String(title),
    marks: Math.max(0, Number(marks) || 0),
    language: String(language || "Any"),
    description: String(description),
    starterCode: String(starterCode || ""),
  };
  questions.push(q);
  setQuestions(questions);
  res.json(q);
});

admin.put("/questions/:id", (req, res) => {
  const questions = getQuestions();
  const q = questions.find((x) => x.id === req.params.id);
  if (!q) return res.status(404).json({ error: "Question not found" });
  const { type, title, marks, language, description, starterCode } = req.body || {};
  if (type !== undefined) q.type = type === "debugging" ? "debugging" : "coding";
  if (title !== undefined) q.title = String(title);
  if (marks !== undefined) q.marks = Math.max(0, Number(marks) || 0);
  if (language !== undefined) q.language = String(language);
  if (description !== undefined) q.description = String(description);
  if (starterCode !== undefined) q.starterCode = String(starterCode);
  setQuestions(questions);
  res.json(q);
});

admin.delete("/questions/:id", (req, res) => {
  const questions = getQuestions().filter((x) => x.id !== req.params.id);
  setQuestions(questions);
  res.json({ ok: true, count: questions.length });
});

// Reorder questions given an array of ids in the new order
admin.post("/questions/reorder", (req, res) => {
  const { order } = req.body || {};
  if (!Array.isArray(order)) return res.status(400).json({ error: "order array required" });
  const questions = getQuestions();
  const byId = Object.fromEntries(questions.map((q) => [q.id, q]));
  const reordered = order.map((id) => byId[id]).filter(Boolean);
  // Keep any not mentioned at the end
  questions.forEach((q) => { if (!order.includes(q.id)) reordered.push(q); });
  setQuestions(reordered);
  res.json({ ok: true });
});

/* ---- Participants manager ---- */
admin.get("/participants", (req, res) => {
  // Never send hashes to the client
  res.json({
    participants: getParticipants().map((p) => ({ username: p.username, createdAt: p.createdAt })),
  });
});

// Add a single participant with a chosen or given password
admin.post("/participants", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: "Username and password required" });
  const participants = getParticipants();
  if (participants.find((p) => p.username === username))
    return res.status(409).json({ error: "Username already exists" });
  const { salt, hash } = hashPassword(String(password));
  participants.push({ username: String(username), salt, hash, createdAt: new Date().toISOString() });
  setParticipants(participants);
  res.json({ ok: true, username, password }); // return plaintext once so you can hand it out
});

// Bulk-generate N accounts with random passwords; returns credentials once.
admin.post("/participants/bulk", (req, res) => {
  const { count, prefix } = req.body || {};
  const n = Math.min(500, Math.max(1, Number(count) || 0));
  const pfx = String(prefix || "user").replace(/[^a-z0-9_-]/gi, "") || "user";
  const participants = getParticipants();
  const existing = new Set(participants.map((p) => p.username));
  const created = [];
  let i = 1;
  while (created.length < n) {
    const username = `${pfx}${i++}`;
    if (existing.has(username)) continue;
    const password = crypto.randomBytes(4).toString("hex"); // 8-char password
    const { salt, hash } = hashPassword(password);
    participants.push({ username, salt, hash, createdAt: new Date().toISOString() });
    existing.add(username);
    created.push({ username, password });
  }
  setParticipants(participants);
  res.json({ ok: true, created });
});

admin.delete("/participants/:username", (req, res) => {
  const participants = getParticipants().filter((p) => p.username !== req.params.username);
  setParticipants(participants);
  res.json({ ok: true, count: participants.length });
});

/* ---- Evaluation ---- */
function loadSubmissions() {
  return fs
    .readdirSync(SUBMISSIONS_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => readJSON(path.join(SUBMISSIONS_DIR, f), null))
    .filter(Boolean);
}

admin.get("/submissions", (req, res) => {
  const questions = getQuestions();
  const subs = loadSubmissions().map((s) => ({
    ...s,
    answeredCount: s.answers.filter((a) => a.status === "answered").length,
  }));
  res.json({ submissions: subs, questions });
});

// Save marks + remarks for one participant
admin.post("/score/:username", (req, res) => {
  const safeName = req.params.username.replace(/[^a-z0-9_-]/gi, "_");
  const file = path.join(SUBMISSIONS_DIR, `${safeName}.json`);
  const sub = readJSON(file, null);
  if (!sub) return res.status(404).json({ error: "Submission not found" });

  const { scores, remarks } = req.body || {};
  if (scores && typeof scores === "object") sub.scores = scores;
  if (remarks !== undefined) sub.remarks = String(remarks);
  sub.totalScore = Object.values(sub.scores || {}).reduce((s, v) => s + (Number(v) || 0), 0);
  writeJSON(file, sub);
  res.json({ ok: true, totalScore: sub.totalScore });
});

// Export all results (with scores) as CSV
admin.get("/export.csv", (req, res) => {
  const questions = getQuestions();
  const subs = loadSubmissions();
  const header = [
    "username",
    "submittedAt",
    "autoSubmitted",
    "violations",
    ...questions.map((q, i) => `Q${i + 1}_marks`),
    "total",
    "maxScore",
    "remarks",
  ];
  const rows = subs.map((s) => {
    const cells = [
      s.username,
      s.submittedAt,
      s.autoSubmitted ? "yes" : "no",
      s.violations,
      ...questions.map((q) => (s.scores && s.scores[q.id] != null ? s.scores[q.id] : "")),
      s.totalScore != null ? s.totalScore : "",
      s.maxScore != null ? s.maxScore : "",
      `"${String(s.remarks || "").replace(/"/g, '""')}"`,
    ];
    return cells.join(",");
  });
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", "attachment; filename=results.csv");
  res.send([header.join(","), ...rows].join("\n"));
});

/* =======================================================================
   Fallback + start
   ======================================================================= */

// Admin page
app.get("/admin", (req, res) => {
    res.sendFile(
        path.join(__dirname, "public", "admin.html")
    );
});


// Render health check
app.get("/health", (req, res) => {
    res.json({
        status: "OK",
        service: "Coding Platform"
    });
});


// Start server ONLY ONCE
app.listen(PORT, () => {

    console.log(
        `Coding & Debugging Event Platform running on port ${PORT}`
    );

    console.log("Participant page : /");
    console.log("Admin panel      : /admin");

});





