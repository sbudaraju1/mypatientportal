const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const PDFDocument = require('pdfkit');

const PORT = 3000;
const DB_FILE = path.join(__dirname, "database.db");

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static("public"));

app.use(session({
  secret: "mysecretkey",
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    // Create unique filename: timestamp-userId-originalname
    const uniqueName = Date.now() + "-" + req.session.user.id + "-" + file.originalname;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: function (req, file, cb) {
    // Allow specific file types
    const allowedTypes = /jpeg|jpg|png|pdf|doc|docx/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error("Only images, PDFs, and Word documents are allowed"));
    }
  }
});

// Initialize DB (create tables if not exist)
const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) return console.error(err);
  console.log("Connected to SQLite DB.");
});

const initSql = `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  role TEXT CHECK(role IN ('patient','doctor')) DEFAULT 'patient',
  name TEXT,
  birthday TEXT,
  email TEXT,
  phone TEXT,
  address TEXT,
  emergency_contact TEXT,
  emergency_phone TEXT,
  blood_type TEXT,
  allergies TEXT
);

CREATE TABLE IF NOT EXISTS health_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_id INTEGER,
  doctor_id INTEGER,
  diagnosis TEXT,
  notes TEXT,
  date TEXT,
  weight TEXT,
  height TEXT,
  blood_pressure TEXT,
  heart_rate TEXT,
  temperature TEXT,
  oxygen TEXT,
  FOREIGN KEY(patient_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(doctor_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS documents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_id INTEGER,
  uploaded_by INTEGER,
  filename TEXT,
  original_name TEXT,
  file_type TEXT,
  file_size INTEGER,
  description TEXT,
  upload_date TEXT,
  visibility TEXT CHECK(visibility IN ('public','private')) DEFAULT 'public',
  FOREIGN KEY(patient_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE SET NULL
);
`;

db.exec(initSql, (err) => {
  if (err) console.error("DB init error:", err);
  else console.log("DB initialized (tables ready).");
});

///////////////////////
// Auth & Session helpers
///////////////////////

function requireLoggedIn(req, res, next) {
  if (req.session.user) return next();
  return res.status(401).json({ error: "Not logged in" });
}

function requirePatient(req, res, next) {
  if (req.session.user && req.session.user.role === "patient") return next();
  return res.status(403).json({ error: "Patient access required" });
}

function requireDoctor(req, res, next) {
  if (req.session.user && req.session.user.role === "doctor") return next();
  return res.status(403).json({ error: "Doctor access required" });
}

///////////////////////
// Routes: Auth
///////////////////////

// Signup (patients) - NOW USES DATABASE
app.post("/signup", async (req, res) => {
  const { username, password, name, birthday } = req.body;

  // Check if username exists
  db.get("SELECT id FROM users WHERE username = ?", [username], async (err, row) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ error: "Database error. Please try again." });
    }
    if (row) {
      return res.status(400).json({ error: "Username already exists." });
    }

    // Hash password and insert
    const hashed = await bcrypt.hash(password, 10);
    db.run(
      "INSERT INTO users (username, password, role, name, birthday) VALUES (?, ?, ?, ?, ?)",
      [username, hashed, "patient", name, birthday || null],
      function(err) {
        if (err) {
          console.error("Error creating user:", err);
          return res.status(500).json({ error: "Error creating account. Please try again." });
        }
        console.log("Patient signed up with ID:", this.lastID);
        return res.json({ ok: true, message: "Signup successful" });
      }
    );
  });
});

// Login (patients) - NOW USES DATABASE
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT id, username, password, role, name FROM users WHERE username = ?", [username], async (err, user) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(400).json({ error: "Database error. Please try again." });
    }
    if (!user) {
      return res.status(400).json({ error: "Username does not exist." });
    }

    // Check if user is a doctor trying to log in as patient
    if (user.role !== "patient") {
      return res.status(400).json({ error: "Invalid username or password." });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: "Invalid username or password." });
    }

    req.session.user = { id: user.id, username: user.username, role: user.role, name: user.name };
    req.session.loggedIn = true;

    return res.json({ ok: true });
  });
});

// Physician login
app.post("/api/physician-login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing username or password" });

  db.get("SELECT id, username, password, role, name FROM users WHERE username = ? AND role = 'doctor'", [username], async (err, row) => {
    if (err) return res.status(500).json({ error: "db_error" });
    if (!row) return res.status(400).json({ error: "invalid" });

    const match = await bcrypt.compare(password, row.password);
    if (!match) return res.status(400).json({ error: "invalid" });

    req.session.user = { id: row.id, username: row.username, role: row.role, name: row.name };
    return res.json({ ok: true });
  });
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error("Session destroy error:", err);
      return res.send("Error logging out");
    }
    // Send HTML with popup and redirect
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Logout Successful!</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f0f0f0;
          }
          .popup {
            background: white;
            padding: 30px 50px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
          }
          .popup h2 {
            color: #4CAF50;
            margin-bottom: 10px;
          }
          .checkmark {
            font-size: 48px;
            color: #4CAF50;
          }
        </style>
      </head>
      <body>
        <div class="popup">
          <div class="checkmark">✓</div>
          <h2>Logout Successful!</h2>
          <p>Redirecting to login page...</p>
        </div>
        <script>
          setTimeout(() => {
            window.location.href = "/login_page.html";
          }, 2000);
        </script>
      </body>
      </html>
    `);
  });
});

// Current session info
app.get("/api/user", (req, res) => {
  if (!req.session.user) return res.json({ loggedIn: false });
  return res.json({ loggedIn: true, user: req.session.user });
});

// Upload document (patient or doctor)
app.post("/api/documents/upload", requireLoggedIn, upload.single("document"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }
  
  const { patient_id, description, visibility } = req.body;
  const uploaderId = req.session.user.id;
  const userRole = req.session.user.role;
  
  // If patient is uploading, patient_id is their own ID and visibility is always public
  // If doctor is uploading, they specify patient and visibility
  let finalPatientId = patient_id;
  let finalVisibility = visibility || "public";
  
  if (userRole === "patient") {
    finalPatientId = uploaderId;
    finalVisibility = "public"; // Patients can only upload public documents
  }
  
  if (!finalPatientId) {
    return res.status(400).json({ error: "Patient ID required" });
  }
  
  const uploadDate = new Date().toISOString().slice(0, 10);
  
  db.run(
    `INSERT INTO documents (patient_id, uploaded_by, filename, original_name, file_type, file_size, description, upload_date, visibility)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [finalPatientId, uploaderId, req.file.filename, req.file.originalname, req.file.mimetype, req.file.size, description || "", uploadDate, finalVisibility],
    function(err) {
      if (err) {
        console.error("Error saving document:", err);
        return res.status(500).json({ error: "Failed to save document" });
      }
      console.log("Document uploaded with ID:", this.lastID);
      return res.json({ 
        ok: true, 
        id: this.lastID,
        message: "Document uploaded successfully" 
      });
    }
  );
});

// Get documents for a patient (patient view - only public docs)
app.get("/api/patient/documents", requireLoggedIn, requirePatient, (req, res) => {
  const patientId = req.session.user.id;
  
  db.all(
    `SELECT d.*, u.name as uploaded_by_name, u.username as uploaded_by_username, u.role as uploaded_by_role
     FROM documents d
     LEFT JOIN users u ON d.uploaded_by = u.id
     WHERE d.patient_id = ? AND d.visibility = 'public'
     ORDER BY d.upload_date DESC`,
    [patientId],
    (err, rows) => {
      if (err) {
        console.error("Error fetching documents:", err);
        return res.status(500).json({ error: "db_error" });
      }
      return res.json({ documents: rows });
    }
  );
});

// Get documents for a patient (doctor view - all docs)
app.get("/api/doctor/documents/:patientId", requireLoggedIn, requireDoctor, (req, res) => {
  const patientId = req.params.patientId;
  
  db.all(
    `SELECT d.*, u.name as uploaded_by_name, u.username as uploaded_by_username, u.role as uploaded_by_role
     FROM documents d
     LEFT JOIN users u ON d.uploaded_by = u.id
     WHERE d.patient_id = ?
     ORDER BY d.upload_date DESC`,
    [patientId],
    (err, rows) => {
      if (err) {
        console.error("Error fetching documents:", err);
        return res.status(500).json({ error: "db_error" });
      }
      return res.json({ documents: rows });
    }
  );
});

// Download document
app.get("/api/documents/download/:id", requireLoggedIn, (req, res) => {
  const docId = req.params.id;
  const userId = req.session.user.id;
  const userRole = req.session.user.role;
  
  db.get("SELECT * FROM documents WHERE id = ?", [docId], (err, doc) => {
    if (err || !doc) {
      return res.status(404).json({ error: "Document not found" });
    }
    
    // Check permissions
    // Doctor can download any document for their patients
    // Patient can only download their own PUBLIC documents
    if (userRole === "patient") {
      if (doc.patient_id !== userId) {
        return res.status(403).json({ error: "Access denied" });
      }
      if (doc.visibility === "private") {
        return res.status(403).json({ error: "This document is restricted" });
      }
    }
    
    const filePath = path.join(uploadsDir, doc.filename);
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "File not found" });
    }
    
    res.download(filePath, doc.original_name);
  });
});

// Delete document
app.delete("/api/documents/:id", requireLoggedIn, (req, res) => {
  const docId = req.params.id;
  const userId = req.session.user.id;
  const userRole = req.session.user.role;
  
  db.get("SELECT * FROM documents WHERE id = ?", [docId], (err, doc) => {
    if (err || !doc) {
      return res.status(404).json({ error: "Document not found" });
    }
    
    // Check permissions: can only delete if you uploaded it or you're the patient
    if (doc.uploaded_by !== userId && (userRole === "patient" && doc.patient_id !== userId)) {
      return res.status(403).json({ error: "Access denied" });
    }
    
    // Delete file from filesystem
    const filePath = path.join(uploadsDir, doc.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
    
    // Delete from database
    db.run("DELETE FROM documents WHERE id = ?", [docId], function(err) {
      if (err) {
        console.error("Error deleting document:", err);
        return res.status(500).json({ error: "Failed to delete document" });
      }
      return res.json({ ok: true, message: "Document deleted successfully" });
    });
  });
});

///////////////////////
// Patient routes (protected)
///////////////////////

// Get reports for currently logged patient
app.get("/api/patient/reports", requireLoggedIn, requirePatient, (req, res) => {
  const pid = req.session.user.id;
  db.all(
    `SELECT hr.id, hr.diagnosis, hr.notes, hr.date, u.username as doctor_username, u.name as doctor_name
     FROM health_reports hr
     LEFT JOIN users u on hr.doctor_id = u.id
     WHERE hr.patient_id = ?
     ORDER BY hr.date DESC`, [pid],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "db_error" });
      return res.json({ reports: rows });
    }
  );
});

// View Full Report as Webpage
app.get("/api/report/:id", requireLoggedIn, (req, res) => {
  const id = req.params.id;

  db.get(
    `SELECT hr.*, 
            p.name as patient_name, p.username as patient_username,
            d.name as doctor_name, d.username as doctor_username
     FROM health_reports hr
     LEFT JOIN users p on hr.patient_id = p.id
     LEFT JOIN users d on hr.doctor_id = d.id
     WHERE hr.id = ?`,
    [id],
    (err, row) => {
      if (err) return res.status(500).json({ error: "db_error" });
      if (!row) return res.status(404).json({ error: "not_found" });
      return res.json({ report: row });
    }
  );
});

// Export report as PDF (both patient and doctor can export)
app.get("/api/report/pdf/:id", requireLoggedIn, (req, res) => {
  const reportId = req.params.id;
  const userId = req.session.user.id;
  const userRole = req.session.user.role;
  
  // Get report with all details
  db.get(
    `SELECT hr.*, 
            p.name as patient_name, p.username as patient_username, p.birthday, p.email, p.phone,
            d.name as doctor_name, d.username as doctor_username
     FROM health_reports hr
     LEFT JOIN users p ON hr.patient_id = p.id
     LEFT JOIN users d ON hr.doctor_id = d.id
     WHERE hr.id = ?`,
    [reportId],
    (err, report) => {
      if (err || !report) {
        return res.status(404).json({ error: "Report not found" });
      }
      
      // Check permissions
      if (userRole === "patient" && report.patient_id !== userId) {
        return res.status(403).json({ error: "Access denied" });
      }
      
      // Create PDF
      const doc = new PDFDocument({ margin: 50 });
      
      // Set response headers
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename=health-report-${reportId}.pdf`);
      
      // Pipe PDF to response
      doc.pipe(res);
      
      // Add content to PDF
      // Header
      doc.fontSize(24)
         .fillColor('#2196F3')
         .text('Health Report', { align: 'center' })
         .moveDown();
      
      // Report details box
      doc.fontSize(10)
         .fillColor('#666')
         .text(`Report ID: ${report.id}`, { align: 'right' })
         .text(`Generated: ${new Date().toLocaleDateString()}`, { align: 'right' })
         .moveDown(2);
      
      // Patient Information Section
      doc.fontSize(16)
         .fillColor('#333')
         .text('Patient Information', { underline: true })
         .moveDown(0.5);
      
      doc.fontSize(12)
         .fillColor('#000')
         .text(`Name: ${report.patient_name || report.patient_username || 'N/A'}`)
         .text(`Date of Birth: ${report.birthday || 'N/A'}`)
         .text(`Contact: ${report.email || 'N/A'} | ${report.phone || 'N/A'}`)
         .moveDown(2);
      
      // Report Details Section
      doc.fontSize(16)
         .fillColor('#333')
         .text('Report Details', { underline: true })
         .moveDown(0.5);
      
      doc.fontSize(12)
         .fillColor('#000')
         .text(`Date: ${report.date || 'N/A'}`)
         .text(`Doctor: ${report.doctor_name || report.doctor_username || 'N/A'}`)
         .moveDown(1);
      
      // Diagnosis Section
      doc.fontSize(14)
         .fillColor('#333')
         .text('Diagnosis:', { underline: true })
         .moveDown(0.3);
      
      doc.fontSize(12)
         .fillColor('#000')
         .text(report.diagnosis || 'No diagnosis provided', { align: 'left' })
         .moveDown(2);
      
      // Notes Section
      doc.fontSize(14)
         .fillColor('#333')
         .text('Notes:', { underline: true })
         .moveDown(0.3);
      
      doc.fontSize(12)
         .fillColor('#000')
         .text(report.notes || 'No notes provided', { align: 'left' })
         .moveDown(3);
      
      // Footer
      doc.fontSize(8)
         .fillColor('#999')
         .text('This is a confidential medical document. Please keep it secure.', 
               50, 
               doc.page.height - 50, 
               { align: 'center' });
      
      // Finalize PDF
      doc.end();
    }
  );
});

// Get patient profile
app.get("/api/patient/profile", requireLoggedIn, requirePatient, (req, res) => {
  const userId = req.session.user.id;
  db.get(
    `SELECT id, username, name, birthday, email, phone, address, 
            emergency_contact, emergency_phone, blood_type, allergies 
     FROM users WHERE id = ?`,
    [userId],
    (err, row) => {
      if (err) return res.status(500).json({ error: "db_error" });
      if (!row) return res.status(404).json({ error: "user_not_found" });
      return res.json({ profile: row });
    }
  );
});

// Update patient profile
app.put("/api/patient/profile", requireLoggedIn, requirePatient, (req, res) => {
  const userId = req.session.user.id;
  const { name, birthday, email, phone, address, emergency_contact, emergency_phone, blood_type, allergies } = req.body;
  
  db.run(
    `UPDATE users SET 
      name = ?, birthday = ?, email = ?, phone = ?, address = ?,
      emergency_contact = ?, emergency_phone = ?, blood_type = ?, allergies = ?
     WHERE id = ?`,
    [name, birthday, email, phone, address, emergency_contact, emergency_phone, blood_type, allergies, userId],
    function(err) {
      if (err) {
        console.error("Error updating profile:", err);
        return res.status(500).json({ error: "Failed to update profile" });
      }
      // Update session name if changed
      if (name) req.session.user.name = name;
      return res.json({ ok: true, message: "Profile updated successfully" });
    }
  );
});

///////////////////////
// Doctor routes (protected)
///////////////////////

// Dashboard: list all reports
app.get("/api/doctor/reports", requireLoggedIn, requireDoctor, (req, res) => {
  db.all(
    `SELECT hr.id, hr.diagnosis, hr.notes, hr.date, hr.weight, hr.height, hr.blood_pressure, hr.heart_rate, hr.temperature, hr.oxygen,
            p.id as patient_id, p.username as patient_username, p.name as patient_name,
            d.id as doctor_id, d.username as doctor_username, d.name as doctor_name
     FROM health_reports hr
     LEFT JOIN users p on hr.patient_id = p.id
     LEFT JOIN users d on hr.doctor_id = d.id
     ORDER BY hr.date DESC`,
    [], (err, rows) => {
      if (err) return res.status(500).json({ error: "db_error" });
      return res.json({ reports: rows });
    }
  );
});

// Create report (doctor)
app.post("/api/doctor/report", requireLoggedIn, requireDoctor, (req, res) => {
  const doctorId = req.session.user.id;
  const { 
    patient_id, 
    diagnosis = "", 
    notes = "", 
    date = new Date().toISOString().slice(0,10),
    weight = "",
    height = "",
    blood_pressure = "",
    heart_rate = "",
    temperature = "",
    oxygen = ""
  } = req.body;
  
  if (!patient_id) return res.status(400).json({ error: "need_patient_id" });

  db.run(
    `INSERT INTO health_reports 
     (patient_id, doctor_id, diagnosis, notes, date, weight, height, blood_pressure, heart_rate, temperature, oxygen) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [patient_id, doctorId, diagnosis, notes, date, weight, height, blood_pressure, heart_rate, temperature, oxygen],
    function(err) {
      if (err) {
        console.error("Error creating report:", err);
        return res.status(500).json({ error: "db_error" });
      }
      return res.json({ ok: true, id: this.lastID });
    }
  );
});

// Update report (doctor)
app.put("/api/doctor/report/:id", requireLoggedIn, requireDoctor, (req, res) => {
  const id = req.params.id;
  const { diagnosis = "", notes = "", date = null } = req.body;
  const sql = "UPDATE health_reports SET diagnosis = ?, notes = ?, date = COALESCE(?, date) WHERE id = ?";
  db.run(sql, [diagnosis, notes, date, id], function(err) {
    if (err) return res.status(500).json({ error: "db_error" });
    return res.json({ ok: true, changes: this.changes });
  });
});

// Delete report (doctor)
app.delete("/api/doctor/report/:id", requireLoggedIn, requireDoctor, (req, res) => {
  const id = req.params.id;
  db.run("DELETE FROM health_reports WHERE id = ?", [id], function(err) {
    if (err) return res.status(500).json({ error: "db_error" });
    return res.json({ ok: true, changes: this.changes });
  });
});

// Get single report for doctor
app.get("/api/doctor/report/:id", requireLoggedIn, requireDoctor, (req, res) => {
  const reportId = req.params.id;
  
  db.get(
    `SELECT hr.*, 
            p.name as patient_name, p.username as patient_username, p.birthday, p.email, p.phone,
            d.name as doctor_name, d.username as doctor_username
     FROM health_reports hr
     LEFT JOIN users p ON hr.patient_id = p.id
     LEFT JOIN users d ON hr.doctor_id = d.id
     WHERE hr.id = ?`,
    [reportId],
    (err, row) => {
      if (err) {
        console.error("Error fetching report:", err);
        return res.status(500).json({ error: "db_error" });
      }
      if (!row) {
        return res.status(404).json({ error: "Report not found" });
      }
      return res.json({ report: row });
    }
  );
});

// Get single report for patient (only their own)
app.get("/api/patient/report/:id", requireLoggedIn, requirePatient, (req, res) => {
  const reportId = req.params.id;
  const patientId = req.session.user.id;
  
  db.get(
    `SELECT hr.*, 
            p.name as patient_name, p.username as patient_username, p.birthday, p.email, p.phone,
            d.name as doctor_name, d.username as doctor_username
     FROM health_reports hr
     LEFT JOIN users p ON hr.patient_id = p.id
     LEFT JOIN users d ON hr.doctor_id = d.id
     WHERE hr.id = ? AND hr.patient_id = ?`,
    [reportId, patientId],
    (err, row) => {
      if (err) {
        console.error("Error fetching report:", err);
        return res.status(500).json({ error: "db_error" });
      }
      if (!row) {
        return res.status(403).json({ error: "Access denied or report not found" });
      }
      return res.json({ report: row });
    }
  );
});

// Get list of patients (doctor)
app.get("/api/doctor/patients", requireLoggedIn, requireDoctor, (req, res) => {
  db.all("SELECT id, username, name, birthday FROM users WHERE role = 'patient' ORDER BY username", [], (err, rows) => {
    if (err) return res.status(500).json({ error: "db_error" });
    return res.json({ patients: rows });
  });
});

// Create patient (doctor only)
app.post("/api/doctor/patient", requireLoggedIn, requireDoctor, async (req, res) => {
  const { username, password, name, email, dob, phone } = req.body;
  
  console.log("Received create patient request:", { username, name });
  
  if (!username || !password || !name) {
    return res.status(400).json({ error: "Username, password, and name are required" });
  }

  // Check if username already exists
  db.get("SELECT id FROM users WHERE username = ?", [username], async (err, row) => {
    if (err) {
      console.error("Database error checking username:", err);
      return res.status(500).json({ error: "Database error" });
    }
    if (row) {
      console.log("Username already exists:", username);
      return res.status(400).json({ error: "Username already exists" });
    }

    try {
      // Hash the password
      const hashed = await bcrypt.hash(password, 10);

      // Insert the new patient into the database
      db.run(
        "INSERT INTO users (username, password, role, name, birthday) VALUES (?, ?, ?, ?, ?)",
        [username, hashed, "patient", name, dob || null],
        function(err) {
          if (err) {
            console.error("Error inserting patient:", err);
            return res.status(500).json({ error: "Failed to create patient" });
          }
          console.log("✓ Patient created successfully with ID:", this.lastID);
          return res.json({ ok: true, id: this.lastID, message: "Patient created successfully" });
        }
      );
    } catch (error) {
      console.error("Error hashing password:", error);
      return res.status(500).json({ error: "Server error" });
    }
  });
});

///////////////////////
// Serve index
///////////////////////
app.get("/", (req, res) => {
  res.redirect("/login_page.html");
});

// Start server
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));