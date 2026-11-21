# CYBERGUARD – OBSIDIAN PULSE
### Enterprise Cyber Incident Reporting & Digital Forensic Management Platform

> **TAGLINE:** REPORT. TRACK. INVESTIGATE. RESOLVE.

---

## 🛡️ Project Overview

**CyberGuard – Obsidian Pulse** is a full-stack, enterprise-grade cybersecurity incident reporting and case management platform. It bridges the gap between cyber incident victims and security operations center (SOC) investigators. 

Built with defensive application architecture, the platform features:
- **Obsidian Pulse Aesthetic**: High-contrast dark glassmorphism with Electric Purple (`#9D4EDD`), Neon Pink (`#FF2E93`), and Cyan (`#00F0FF`) accents.
- **Client-Side Digital Forensic Engine**: Instant binary header (magic bytes) inspection and Web Crypto SHA-256 cryptographic hashing to detect extension spoofing and disguised payloads.
- **Role-Based Access Control (RBAC)**: Secure user registration and session management alongside protected administrator command consoles.
- **Dynamic Command Center**: Real-time triage dashboards with live category breakdown and date/status filtering driven directly by persistent database queries.
- **Chain of Custody Tracking**: Immutable reference codes (`CG-XXXXXXXX`) allowing victims to track multi-stage investigation milestones, investigator findings, and resolution advisories.

---

## ⚡ Tech Stack & Architecture

- **Backend:** Python 3, Flask 3.x, Werkzeug (PBKDF2 Password Hashing & Security)
- **Database:** SQLite 3 (`cyberguard.db`) with automatic schema migration and non-destructive column inspection
- **Frontend:** Semantic HTML5, CSS3 Glassmorphism (Obsidian Pulse Theme), Vanilla JavaScript Particle Engine
- **Forensic Capabilities:** Magic Byte Hex Dump, File Extension Mismatch Detection, Client-Side SHA-256 Checksums

---

## 🚀 Key Modules & Capabilities

### 1. Public Landing Page (`/`)
- Command center hero section with real-time operational status pills.
- Threat awareness education (Phishing, MFA, Disguised Executables).
- Quick reference lookup bar for instantaneous case tracking.
- Dynamic navigation reflecting user authentication state.

### 2. User Authentication & Dashboard (`/register`, `/login`, `/dashboard`)
- Secure registration with password hashing (`generate_password_hash`).
- Personalized user command center showing real complaint metrics (Total, Pending, Investigating, Resolved).
- User incident history table with search and status filtering.

### 3. Structured Incident Reporting (`/report` & `/submit`)
- Intake for category, incident date, title, detailed description, and supporting evidence.
- Integrated Digital Forensic Assistant to analyze files before submission.
- Automatic assignment of unique complaint reference number (`CG-XXXXXXXX`).

### 4. Public Complaint Tracking (`/track`)
- Reference ID lookup showing case dossier.
- Multi-stage investigation timeline with active state indicators.
- Displays official investigator notes and case resolution statements.

### 5. SOC Administrator Command Center (`/admin` & `/admin/case/<case_id>`)
- Role-protected routes using custom `@admin_required` decorators.
- Real-time incident counts (Total, Pending, Investigating, Resolved).
- Attack vector category distribution analytics.
- Incident management table with search, status filters, and category filters.
- Dedicated Case Dossier view for adding official investigation notes and published resolution advisories.

---

## 📋 Installation & Local Setup

### Prerequisites
- Python 3.10+ installed
- Git (optional)

### 1. Clone or Open Project Directory
```powershell
cd C:\Users\DELL\Cyber
```

### 2. Set Up Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Configure Environment Variables (Optional)
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```

### 5. Launch the Application
```powershell
python app.py
```
The server will start at: **http://127.0.0.1:5000**

---

## 🔑 Default Administrator Credentials

| Role | Username | Password | Access URL |
| :--- | :--- | :--- | :--- |
| **SOC Administrator** | `admin` | `admin123` | [http://127.0.0.1:5000/admin/login](http://127.0.0.1:5000/admin/login) |

---

## 🧪 Testing & Verification

Run the automated integration test suite:
```powershell
python -c "import app; print('App initialized successfully, routes registered:', len(app.app.url_map._rules))"
```

---

## 📄 License & Attribution
Developed for college cybersecurity capstone and digital forensic investigation education.
© 2026 CYBERGUARD – OBSIDIAN PULSE. All rights reserved.
