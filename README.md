# 🛡 SecretGuard: Source Code Secret & API Key Scanner

**Status:** 🟢 Working Prototype  ·  Cybersecurity  ·  BCA Minor Project  ·  2026

[![View Source Code](https://img.shields.io/badge/💻_View_Source_Code-GitHub-181717?style=for-the-badge&logo=github)](https://github.com/khushisharma20101-design/SecretGuard)
[![Project Preview](https://img.shields.io/badge/📸_Project_Preview-Screenshots-6f42c1?style=for-the-badge)](#-project-preview)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Khushi_Sharma-blue?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/khushi-sharma-ab9827309)

> **A Python command-line tool and Streamlit dashboard that scans project folders for hardcoded passwords, API keys, tokens, and private keys using regex rules, entropy analysis, and context checks.**

---

## ⚠ Caution & Disclaimers

> **IMPORTANT — EDUCATIONAL USE ONLY**
> This project is built for **EDUCATIONAL AND LEARNING PURPOSES ONLY**, as part of a BCA minor project.
> The author is not responsible for any misuse. Scan only code and repositories that you own or have permission to scan.

**Notes:**

* SecretGuard is a **learning prototype**, not a replacement for mature secret-scanning tools such as gitleaks or TruffleHog.
* It relies on pattern matching and heuristics, so it can **miss real secrets** and **report false positives**. Verify every finding manually.
* The files in `SecretGuard_TestData` contain fake values for testing only. Never reuse them as real credentials.
* The dashboard and the JSON report both show **redacted** values, so the full secret is never repeated in the output.

---

## 🛡 Introduction

Hardcoded secrets are one of the most common causes of credential leaks. A developer may paste an API key, a database password, or a private key directly into source code, and once that code is committed or shared, the secret is exposed.

**SecretGuard** scans a project folder and flags values that look like secrets. It combines three checks:

1. **Regex Detection**: known patterns such as AWS access key IDs, private key headers, and database connection strings.
2. **Entropy Analysis**: quoted values that look too random to be ordinary text are flagged as possible secrets.
3. **Context Analysis**: variable names and placeholder words adjust how confident the scanner is in each finding.

The project offers two interfaces: a command-line scanner for quick checks and CI pipelines, and a Streamlit dashboard for interactive scans.

---

## 🚀 Installation & Running

**Requirements:** Python 3.10+ · Virtual Environment recommended

The command-line scanner uses only the Python standard library. The dashboard and the tests need the packages listed in `requirements.txt`.

### Step 1 — Clone the Repository

```bash
git clone https://github.com/khushisharma20101-design/SecretGuard.git
cd SecretGuard
```

### Step 2 — Create a Virtual Environment

**Windows PowerShell:**

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

If Python is available through the `python` command:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Step 3 — Install Dependencies

```powershell
py -m pip install -r requirements.txt
```

### Step 4 — Run the Tests (Optional)

```powershell
py -m pytest -q
```

### Step 5 — Launch the Dashboard

```powershell
streamlit run dashboard.py
```

### Step 6 — Scan a Project

Open the dashboard at `http://localhost:8501`, paste the path of a project folder into the **Project folder path** field, and select **🔍 Run Security Scan**.

### Command-Line Usage

```powershell
py main.py <project-folder>
py main.py <project-folder> --json report.json
py main.py <project-folder> --no-color
py main.py <project-folder> --fail-on-critical
```

| Option | Purpose |
| --- | --- |
| `--json FILE` | Also write a JSON report to the given file |
| `--no-color` | Disable colored console output |
| `--fail-on-critical` | Exit with code 2 if any Critical finding is present (useful in CI) |

Exit codes: `0` means the scan completed, `1` means the path is invalid, and `2` means a Critical finding was found while `--fail-on-critical` was set.

---

## 📊 Folder Structure

```mermaid
graph TD
    Root[SecretGuard] --> Main[main.py]
    Root --> Dash[dashboard.py]
    Root --> Req[requirements.txt]
    Root --> Src[src]
    Root --> Tests[tests]
    Root --> TD[SecretGuard_TestData]
    Root --> CTD[SecretGuard_Clean_TestData]

    Src --> Scanner[scanner.py]
    Src --> Models[models.py]
    Src --> Reporter[reporter.py]
    Src --> Detectors["detectors/ — regex_rules.py, entropy_check.py, context_check.py"]
```

| Folder / File | Role |
| --- | --- |
| `main.py` | Command-line entry point: argument parsing, console output, JSON export, and exit codes |
| `dashboard.py` | Streamlit dashboard for running scans and browsing findings (presentation layer only) |
| `requirements.txt` | Dependencies for the dashboard and tests (Streamlit, Plotly, pytest) |
| `src/scanner.py` | Walks the project folder and runs the detectors line by line |
| `src/models.py` | Data classes for `Finding` and `ScanSummary`, plus the severity and detection-method enums |
| `src/reporter.py` | Formats console output and JSON reports |
| `src/detectors/regex_rules.py` | Known secret patterns: AWS keys, private key blocks, connection strings, and generic API keys |
| `src/detectors/entropy_check.py` | Flags quoted values with high randomness |
| `src/detectors/context_check.py` | Adjusts confidence using variable names and placeholder words |
| `tests/` | pytest suite for the scanner, models, and context checks |
| `SecretGuard_TestData/` | Synthetic files containing fake secrets for demonstration |
| `SecretGuard_Clean_TestData/` | Ordinary code with no secrets, expected to produce 0 findings |

---

## 📌 Project Information

| Category | Details |
| --- | --- |
| Project Name | SecretGuard |
| Project Type | Cybersecurity Command-Line Tool & Web Dashboard |
| Domain | Source Code Security / Secret Detection |
| Language | Python 3.10+ |
| Interfaces | Command-line (`main.py`) and Streamlit dashboard (`dashboard.py`) |
| Detection Approach | Regex Rules + Entropy Analysis + Context Checks |
| Output | Console report, JSON report, dashboard view |
| Storage | No database; results are held in memory during a scan |
| Status | Working Prototype |
| Context | BCA Minor Project |
| Developed By | Khushi Sharma |
| Year | 2026 |

---

## 🛠 Technologies & Techniques

| Category | Technology | Purpose |
| --- | --- | --- |
| Language | Python 3 | Core scanning and detection logic |
| Core Libraries | `re`, `math`, `json`, `pathlib`, `argparse`, `dataclasses` | Pattern matching, entropy math, file handling, CLI, and data models |
| Dashboard | Streamlit | Web interface for running scans and viewing findings |
| Charts | Plotly | Detection overview charts on the dashboard |
| Testing | pytest | Unit tests for the scanner, models, and context checks |
| Architecture | Modular `src/` package | Separation of scanner, detectors, models, and reporting |

### Detection Rules

**Stage 1: Regex Rules**

| Rule | Severity | Base Confidence |
| --- | --- | --- |
| AWS Access Key ID | Critical | 0.95 |
| AWS Secret Access Key | Critical | 0.95 |
| Private Key Block | Critical | 0.98 |
| Database Connection String | High | 0.85 |
| Generic API Key Assignment | Medium | 0.55 |

The generic rule matches `api_key`, `api_secret`, `secret`, `token`, `password`, and `passwd` when they are assigned a quoted value of 16 to 64 characters.

**Stage 2: Entropy Analysis**

Entropy runs only on lines where no regex rule matched. It checks quoted values of at least 20 characters that follow `=` or `:` and contain no spaces. Each value's Shannon entropy is compared with a threshold based on its character set: hex (3.0), base64-like (4.5), or generic text (3.5). Entropy findings are rated High or lower, never Critical.

**Stage 3: Context Analysis**

Context checks never create a finding. They adjust the confidence of an existing one:

* **+0.05** when the variable or key name suggests a secret, such as `api_key`, `password`, or `github_token`
* **−0.15** when the line contains a placeholder word, such as `example`, `dummy`, `change_me`, or `placeholder`

### Scan Scope

* Scans 35 source, config, and text file types, including `.py`, `.js`, `.java`, `.yml`, `.json`, and `.txt`
* Skips folders such as `.git`, `node_modules`, `venv`, `.venv`, `build`, and `dist`
* Skips files larger than 2 MB and binary files

---

## ✨ Features & Functions

### 1. 💻 Command-Line Scanner

* Scans any project folder recursively
* Console report sorted by severity (Critical first), with redacted values and remediation advice
* `--json` option writes a machine-readable report
* `--fail-on-critical` returns exit code 2, so a CI pipeline can stop the build

### 2. 🖥 Streamlit Dashboard

* Dark, security-themed interface built with Streamlit
* Scan controls on the main page: enter a folder path and select **Run Security Scan**
* Scan overview metrics and detection charts showing where the findings came from
* Findings list with severity badges, file location, redacted value, and fix recommendation
* Filters for severity, detection method, and free-text search
* Status banners: **System Ready** before a scan, **Threats Detected** when findings exist, and **Scan Clear** when nothing is found
* One-click **Download JSON report** button

### 3. 🧠 Hybrid Detection Engine

Regex rules run first. If a line matches a rule, the entropy check is skipped for that line. Otherwise, the entropy check runs. Context analysis then adjusts the confidence of every finding.

### 4. 🙈 Redacted Output

Matched values are masked so reports never repeat the full secret. For values longer than six characters, the first four and last two characters stay visible. Shorter values are fully masked.

### 5. 🧪 Built-in Test Data

* `SecretGuard_TestData/` contains fake AWS-style keys, a private key header, a database URL, and API tokens, spread across several files
* `SecretGuard_Clean_TestData/` contains ordinary code and is expected to produce 0 findings
* A pytest suite covers file discovery, detection, context analysis, and data models

---

## 📈 System Flow

```mermaid
sequenceDiagram
    participant User
    participant UI as CLI or Dashboard
    participant Scanner as Scanner
    participant Regex as Regex Rules
    participant Entropy as Entropy Check
    participant Context as Context Check
    participant Report as Reporter

    User->>UI: Provide project folder
    UI->>Scanner: scan_directory(path)

    loop Each eligible file and line
        Scanner->>Regex: Check known patterns
        alt Regex match
            Regex-->>Scanner: Findings
            Scanner->>Context: Refine confidence
        else No regex match
            Scanner->>Entropy: Check quoted values
            Entropy-->>Scanner: Findings (if any)
            Scanner->>Context: Refine confidence
        end
    end

    Scanner-->>UI: ScanSummary
    UI->>Report: Format results
    Report-->>User: Console, dashboard, or JSON report
```

---

## 🔄 Example Detection Scenarios

### Clean Code

Ordinary values with no secret-like names or random-looking content produce no findings.

```python
username = "student"
message = "SecretGuard test file"
```

### Known Pattern: AWS Access Key

```python
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
```

Reported as **Critical · AWS Access Key ID**. Its confidence drops from 0.95 to 0.80 because the value contains the placeholder word `EXAMPLE`.

### Connection String

```python
DATABASE_URL = "postgresql://app_user:S3cur3Pass@db.internal:5432/orders"
```

Reported as **High · Database Connection String** with confidence 0.85.

### Random-Looking Value (Entropy)

```python
checksum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
```

No regex rule matches this line, but the 64-character hex string has high entropy (about 3.79 bits per character, above the 3.0 hex threshold). Reported as **Medium · High-Entropy String (hex)** with confidence 0.657. Hashes and checksums can trigger this check too, so verify findings manually.

### Private Key Header

```text
-----BEGIN PRIVATE KEY-----
```

Reported as **Critical · Private Key Block** with confidence 0.98.

---

## 🔭 Project Overview

SecretGuard works in two ways. The command-line tool prints a severity-sorted report to the terminal and can export JSON for scripts or CI. The Streamlit dashboard runs the same scan in a browser: you enter a project folder, and the dashboard summarizes the results as cards and charts, then lists each finding with its location, redacted value, and fix recommendation.

The dashboard shows the outcome of each scan in its status banner. Before a scan, it shows **System Ready**. A scan that finds secrets shows **Threats Detected**, along with the files scanned, the number of findings, the critical count, and the scan time. A clean scan shows **Scan Clear** and reports that no secrets were detected.

---

## 📸 Project Preview

<table>
<tr>
<td width="50%" align="center"><img src="./output-screenshots/SecretGuard1.png" width="100%"><br><sub><b>System Ready:</b> the dashboard before a scan</sub></td>
<td width="50%" align="center"><img src="./output-screenshots/SecretGuard3.png" width="100%"><br><sub><b>Scan Clear:</b> the clean test project, with no findings</sub></td>
</tr>
<tr>
<td colspan="2" align="center"><img src="./output-screenshots/SecretGuard2.png" width="65%"><br><sub><b>Threats Detected:</b> the test-data project, with 7 findings, filters, charts, and redacted values</sub></td>
</tr>
</table>

---

## 🎓 What I Learned & Market Value

**Context:** Built as a BCA minor project and refined into a working prototype with a command-line interface and a dashboard.

### Learning Outcomes

* Designed a modular scanner with separate detector, model, and reporting layers.
* Implemented regex rules, Shannon entropy analysis, and context-based confidence scoring.
* Built a command-line tool with JSON export and CI-friendly exit codes.
* Built a Streamlit dashboard with filters, charts, and a JSON download.
* Modeled findings as immutable dataclasses with validation rules.
* Redacted sensitive values so reports never expose complete secrets.
* Wrote a pytest suite covering the scanner, models, and context checks.

### Market Value

Secret leaks in source code are a common security problem. Secret scanning is a standard step in DevSecOps pipelines, and tools such as gitleaks and TruffleHog are widely used for it. Building a scanner from first principles shows how such tools find secrets, and why false positives happen.

---

## 🔮 Future Enhancements

Possible future improvements include:

* Scanning dotfiles such as `.env`, which are currently skipped by the file-extension filter.
* Loading custom detection rules from `config/rules.yaml`.
* Adding provider-specific rules for services such as GitHub, Slack, and Stripe tokens.
* Supporting unquoted values and multi-line secrets.
* Adding a false-positive filter to reduce noise from hashes and example values.
* Scanning git history, not only the current files.
* Adding a pre-commit hook for scanning staged changes.

---

## 🏷 Tags

`#CyberSecurity` `#SecretScanning` `#Python` `#Streamlit` `#DevSecOps` `#APIKeys` `#StaticAnalysis`

---

## ⭐ Support & Engagement

If you find this project useful, please consider:

* ⭐ **Starring** the repository
* 🔁 **Sharing** it within your network
* 👤 **Following** for future projects

— **Khushi Sharma**

[![GitHub followers](https://img.shields.io/github/followers/khushisharma20101-design?label=Follow%20on%20GitHub&style=social)](https://github.com/khushisharma20101-design)
[![LinkedIn](https://img.shields.io/badge/Connect%20on%20LinkedIn-blue?style=social&logo=linkedin)](https://www.linkedin.com/in/khushi-sharma-ab9827309)