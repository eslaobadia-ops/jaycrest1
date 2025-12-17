import express from "express";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const { Pool } = pkg;

const app = express();
app.use(express.json());

// ================== DATABASE ==================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ================== INIT DATABASE ==================
async function initDatabase() {
  const sql = `
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT CHECK (role IN ('student','lecturer','admin')) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS students (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    matric_no TEXT UNIQUE NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    department TEXT,
    level INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS lecturers (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    staff_id TEXT UNIQUE NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    department TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS courses (
    id SERIAL PRIMARY KEY,
    course_code TEXT UNIQUE NOT NULL,
    course_title TEXT NOT NULL,
    unit INTEGER NOT NULL,
    department TEXT,
    level INTEGER,
    semester TEXT
  );

  CREATE TABLE IF NOT EXISTS course_registrations (
    id SERIAL PRIMARY KEY,
    student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
    course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
    session TEXT,
    semester TEXT,
    UNIQUE (student_id, course_id)
  );

  CREATE TABLE IF NOT EXISTS results (
    id SERIAL PRIMARY KEY,
    student_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
    course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
    score INTEGER,
    grade TEXT,
    grade_point NUMERIC(3,2),
    session TEXT,
    semester TEXT
  );
  `;

  await pool.query(sql);
  console.log("✅ Database initialized");
}

initDatabase().catch(err => {
  console.error("❌ DB init error:", err);
  process.exit(1);
});

// ================== AUTH MIDDLEWARE ==================
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token" });

  const token = header.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// ================== AUTH ROUTES ==================

/**
 * REGISTER
 * body: { email, password, role }
 */
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password, role } = req.body;

    if (!email || !password || !role) {
      return res.status(400).json({ error: "All fields required" });
    }

    const hash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (email, password_hash, role)
       VALUES ($1, $2, $3)
       RETURNING id, email, role`,
      [email, hash, role]
    );

    res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(400).json({ error: "Email already exists" });
    }
    res.status(500).json({ error: "Registration failed" });
  }
});

/**
 * LOGIN
 * body: { email, password }
 */
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query(
    "SELECT * FROM users WHERE email = $1",
    [email]
  );

  if (result.rows.length === 0) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const user = result.rows[0];
  const valid = await bcrypt.compare(password, user.password_hash);

  if (!valid) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );

  res.json({
    token,
    user: { id: user.id, email: user.email, role: user.role }
  });
});

// ================== STUDENT PROFILE ==================
/**
 * CREATE STUDENT PROFILE
 * headers: Authorization: Bearer TOKEN
 */
app.post("/students/profile", auth, async (req, res) => {
  if (req.user.role !== "student") {
    return res.status(403).json({ error: "Only students allowed" });
  }

  const { matric_no, first_name, last_name, department, level } = req.body;

  const result = await pool.query(
    `INSERT INTO students
     (user_id, matric_no, first_name, last_name, department, level)
     VALUES ($1,$2,$3,$4,$5,$6)
     RETURNING *`,
    [req.user.id, matric_no, first_name, last_name, department, level]
  );

  res.status(201).json(result.rows[0]);
});

// ================== TEST ROUTE ==================
app.get("/", (req, res) => {
  res.json({ status: "Jaycrest backend running" });
});

// ================== START SERVER ==================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
