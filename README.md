# Security Header Detection Tool

A command-line tool for scanning and reporting security-related HTTP headers for a given URL across HTTP/1.0, HTTP/1.1, HTTPS/1.0, and HTTPS/1.1 protocols. The tool evaluates the presence and values of important security headers and checks for best practice configurations.

---

## 🚀 Features

- Detects security headers across both HTTP and HTTPS protocols
- Scans using both HTTP/1.0 and HTTP/1.1
- Distinguishes headers by scheme and version
- Reports missing headers and misconfigurations with severity notes
- Highlights best practice recommendations
- Supports export to:
  - Terminal (color-coded)
  - Plain text
  - CSV
  - HTML (optional, with colorized formatting)
- Logs with color-coded statuses and errors
- Designed with modular and extensible structure
- Compatible with both internal and external scans (`--internal` flag)

---

## 🛠 Installation

```bash
# Clone the repository
git clone https://github.com/yourname/security-header-scanner.git
cd security-header-scanner

# Set up virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
````

---

## 🧪 Usage

```bash
python main.py <url> [options]
```

### Examples:

```bash
# Basic usage (output to terminal)
python main.py https://example.com

# Export to text and CSV
python main.py https://example.com --text report.txt --csv report.csv

# Treat target as internal (affects CSP evaluation)
python main.py https://internal.example --internal
```

---

## 📊 Output

### Terminal Output

* Color-coded table indicating header presence across protocols
* Severity notes and best practice comments displayed below the table

### Text & CSV

* Same table output, with notes appended

### HTML (optional)

* Beautiful, colorized report
* To enable: use `--html report.html` (if feature is active)

---

## 🔐 Headers Checked

The following headers are analyzed with contextual best practices per scheme/version:

* Content-Security-Policy (CSP)
* Strict-Transport-Security (HSTS)
* X-Content-Type-Options
* Cache-Control
* Set-Cookie
* Expires
* X-Frame-Options

See `scanner/detector.py` for full details on rules and checks.

---

## 📦 File Structure

```
.
├── main.py                  # Entry point
├── scanner/                 # Protocol and header detection logic
├── report/                  # Output generation modules
├── requirements.txt         # Python dependencies
└── README.md
```

---

## 🧩 Extending the Tool

To add or modify:

* Headers: update `scanner/detector.py`
* Output format: add or edit modules in `report/`
* Protocol logic: modify `scanner/protocol_scanner.py`

---

## 🙋 FAQ

**Q: Why are some headers missing in HTTP results?**
A: Many security headers (like HSTS) are only sent over HTTPS, or after redirection. The tool accounts for this and reports accordingly.

**Q: Why does CSP have different severities?**
A: If you mark a system as `--internal`, missing CSP is an observation; otherwise, it’s a medium risk.

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repo
2. Create a feature branch
3. Submit a pull request with your changes
