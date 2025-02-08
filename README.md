# Domain Security Evaluation Suite

This repository contains a set of **Python** scripts for performing security evaluations on one or more domains (or IP addresses). The suite includes:

1. **Shodan-based scanner** (`shodan.py`)  
2. **Sucuri-based scanner** (`sucuri.py`)  
3. **OWASP ZAP-based scanner** (`zap.py`)  
4. **Report merger** (`merge_script.py`)  
5. **Master orchestrator** (`master_script.py`)

Each script can run **individually** for its respective tool or be orchestrated **collectively** through the **master script**.  

---

## 1. Overview of Scripts

### **shodan.py**
- **Purpose**:  
  - Queries [Shodan](https://www.shodan.io) to gather information such as hostnames, domains, geolocation details, and open ports, along with associated vulnerabilities (CVE references).  
- **Input**:  
  - Reads from `domains_test.txt`, or prompts the user to manually input `IP : domain`.  
- **Output**:  
  - JSON file and a PDF report in the folder `shodan_reports`.  
  - PDF includes general information (Country, ISP, etc.) plus port-specific vulnerabilities.

### **sucuri.py**
- **Purpose**:  
  - Uses [Sucuri SiteCheck](https://sitecheck.sucuri.net) to check for malware, blacklisting, and other security issues.  
- **Input**:  
  - Reads from `domains_test.txt`, or prompts the user to manually input `IP : domain`.  
- **Operation**:  
  - Navigates to Sucuri’s URL for each domain, captures a truncated PDF (removing everything after the “Hacked? Get help now.” section).  
- **Output**:  
  - A PDF report saved in `sucuri_reports`.

### **zap.py**
- **Purpose**:  
  - Automates [OWASP ZAP](https://www.zaproxy.org/) in **headless mode** to perform spider and active scans on each domain.  
  - Generates both a *raw* PDF (converted from an HTML ZAP report) and a *final* summarized PDF with selected alerts.  
- **Input**:  
  - Reads from `domains_test.txt`, or prompts the user to manually input `IP : domain`.  
- **Output**:  
  - Two PDFs per domain in `zap_reports`: a `raw_` file (full ZAP scan output) and a cleaned-up final PDF.

### **merge_script.py**
- **Purpose**:  
  - Merges individual PDF reports from Shodan, Sucuri, and ZAP into one consolidated PDF per domain.  
  - By default, it tries to find reports that use consistent naming (`IP_domain.pdf`).  
  - Inserts a **first page** that includes a title and domain name.  
- **Usage**:  
  - Typically run **after** the individual scripts have generated their PDFs.  
  - Outputs consolidated PDFs in the `full_reports` folder.

### **master_script.py**
- **Purpose**:  
  - Provides an **interactive** prompt to the user to:  
    1. Choose whether to load domains from `domains_test.txt` or enter them manually.  
    2. Select which tools to run (`shodan, sucuri, zap`, in any combination).  
  - Automatically invokes the selected scripts and then performs the merge step if reports exist.  
  - Generates final merged PDFs in `full_reports`.

---

## 2. Requirements

1. **Python 3.7+**  
2. **Python Packages** (installed via `pip install ...`):
   - [playwright](https://pypi.org/project/playwright/) (for **shodan.py** and **sucuri.py**)
   - [reportlab](https://pypi.org/project/reportlab/) (PDF generation)
   - [PyPDF2](https://pypi.org/project/PyPDF2/) (PDF merging)
   - [pdfkit](https://pypi.org/project/pdfkit/) & [pdfplumber](https://pypi.org/project/pdfplumber/) (for **zap.py**)
   - [python-zapv2](https://pypi.org/project/python-owasp-zap-v2.4/) (for **zap.py**)
   - Optionally, `python-is-python3` on Ubuntu systems to ensure `python` maps to `python3`
3. **OWASP ZAP** installed locally (e.g., `/opt/zaproxy/zap.sh`) for **zap.py**  
4. **A valid Shodan account** if you intend to do multiple queries or advanced usage (in some regions Shodan gating might apply).  
5. **A stable internet connection** for all scripts that fetch external data.  

**Additional**:  
- `first_page.jpg` should exist in the same directory for the **merge_script** or **master_script** to include a first page image.  

---

## 3. Installation

1. **Clone** this repository:
   ```bash
   git clone https://github.com/<your_username>/<repository_name>.git
   cd <repository_name>
