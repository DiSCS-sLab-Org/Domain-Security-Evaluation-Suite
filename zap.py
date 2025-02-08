import os
import re
import subprocess
import time
import pdfkit
import pdfplumber
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from zapv2 import ZAPv2

def prompt_for_input():
    """
    Prompt the user to decide how to obtain 'IP : domain' lines:
      1) Use existing domains_test.txt
      2) Manually input the pairs.
    If manual is chosen, we overwrite domains_test.txt with the user's entries.

    This step ensures the rest of the script (main) remains unchanged,
    yet users can choose their preferred input method.
    """
    print("ZAP: Choose domain input method:")
    print("1) Use existing domains_test.txt")
    print("2) Enter domain(s) manually (e.g. 1.2.3.4: example.com)")
    choice = input("Enter 1 or 2: ").strip()

    if choice == "2":
        lines = []
        print("Enter 'IP : domain' pairs, one per line. Leave blank to finish:")
        while True:
            entry = input("> ").strip()
            if not entry:
                break
            lines.append(entry)

        # Overwrite the file so the script's original 'main' function
        # will read these new entries automatically.
        with open("domains_test.txt", "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")

# Paths
ZAP_PATH = "/opt/zaproxy/zap.sh"  # Adjust this path to the location of your ZAP tool
INPUT_FILE = 'domains_test.txt'
OUTPUT_DIR = 'zap_reports'
ZAP_API_KEY = 'p2a0v4oknbivsgep9pm36jt70v'
ZAP_API_URL = 'http://127.0.0.1:8080'

# Ensure output directories exist
os.makedirs(OUTPUT_DIR, exist_ok=True)

def start_zap():
    """Start the ZAP application in headless mode."""
    print("Starting OWASP ZAP in headless mode...")
    zap_process = subprocess.Popen([ZAP_PATH, '-daemon', '-config', f'api.key={ZAP_API_KEY}'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(10)  # Give ZAP time to start
    print("OWASP ZAP is running.")
    return zap_process

def stop_zap(zap_process):
    """Stop the ZAP application."""
    if zap_process:
        print("Stopping OWASP ZAP...")
        zap_process.terminate()
        zap_process.wait()
        print("OWASP ZAP stopped.")

def extract_content_up_to_last_alert_table(pdf_file):
    """
    Extract headers, summary of alerts, and alert tables up to the end of
    the second table in the "Alerts" section. Stop processing immediately
    after the second table in the "Alerts" section.
    Explicitly skip any "Alert Detail" or similar sections.
    """
    content = []
    tables_started = False
    alerts_label_added = False
    table_count = 0

    with pdfplumber.open(pdf_file) as pdf:
        first_page = pdf.pages[0]  # Only process the first page
        text = first_page.extract_text()
        if text:
            lines = text.splitlines()
            for line in lines:
                # Stop processing if "Alert Detail" is encountered
                if "Alert Detail" in line:
                    return content

                # Capture headers and stop when tables are encountered
                if "Summary of Alerts" in line:
                    content.append(("<b>Summary of Alerts:</b>", "bold"))
                    tables_started = True
                    break
                if not tables_started:
                    if "Sites:" in line:
                        content.append(("<b>" + line + "</b>", "bold"))
                    else:
                        content.append((line, "normal"))

        # Extract tables in the "Alerts" section
        if tables_started:
            tables = first_page.extract_tables()
            for table in tables:
                if table_count < 2:  # Only include up to 2 tables
                    if not alerts_label_added:
                        content.append(("<b>Alerts:</b>", "bold"))
                        alerts_label_added = True
                    content.append(table)
                    table_count += 1
                else:
                    return content

    return content

def generate_final_pdf_report(raw_pdf_file, ip, domain):
    """
    Generate formatted and summarized PDF report from raw PDF.
    """

    def highlight_severity_words(text):
        """
        Wrap 'high', 'medium', 'low', 'informational' (case-insensitive)
        with a font tag that colors them appropriately.
        """
        severity_colors = {
            'high': 'red',
            'medium': 'orange',
            'low': 'green',
            'informational': 'blue'
        }
        for severity, color in severity_colors.items():
            text = re.sub(
                rf'(?i)\b({severity})\b',
                rf'<font color="{color}">\1</font>',
                text
            )
        return text

    final_pdf_file = os.path.join(OUTPUT_DIR, f"{ip}_{domain.replace('.', '_')}.pdf")
    content = extract_content_up_to_last_alert_table(raw_pdf_file)

    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter

    doc = SimpleDocTemplate(final_pdf_file, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph(f"ZAP Report for {ip} ({domain})", styles['Title']))
    story.append(Spacer(1, 12))

    # Add extracted content
    for item in content:
        if isinstance(item, tuple):  # Text with style
            text, style = item
            colored_text = highlight_severity_words(text)
            if style == "bold":
                story.append(Paragraph(colored_text, styles['Heading2']))
            else:
                story.append(Paragraph(colored_text, styles['BodyText']))
            story.append(Spacer(1, 12))
        elif isinstance(item, list):  # Table data
            table_data = [[Paragraph(highlight_severity_words(cell or ''), styles['BodyText'])
                           for cell in row] for row in item]
            report_table = Table(table_data)
            report_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(report_table)
            story.append(Spacer(1, 12))

    doc.build(story)
    print(f"Final report saved: {final_pdf_file}")

def generate_raw_pdf_report(ip, domain, zap_api):
    """
    Generate raw PDF from ZAP tool results by:
      1) Creating a new session
      2) Spider scanning the target
      3) Active scanning the target
      4) Retrieving an HTML report from ZAP
      5) Converting that HTML to a PDF (raw) using pdfkit
    """
    zap_api.core.new_session(name=f"session_{ip}_{domain}", overwrite=True)
    target_url = f"http://{domain}"
    print(f"Starting ZAP scan for: {target_url}")

    # Perform Spider scan
    zap_api.spider.scan(target_url)
    while int(zap_api.spider.status()) < 100:
        pass  # Wait for the scan to complete

    # Perform Active scan
    zap_api.ascan.scan(target_url)
    while int(zap_api.ascan.status()) < 100:
        pass  # Wait for the scan to complete

    # Get raw HTML report
    html_report = zap_api.core.htmlreport()
    raw_pdf_file = os.path.join(OUTPUT_DIR, f"raw_{ip}_{domain.replace('.', '_')}.pdf")

    # Convert HTML to PDF
    pdfkit.from_string(html_report, raw_pdf_file)
    print(f"Raw report saved: {raw_pdf_file}")
    return raw_pdf_file

def main():
    """
    Original main function that:
      1) Starts ZAP
      2) Initializes ZAP API
      3) Reads lines from INPUT_FILE (domains_test.txt)
      4) For each IP:domain, it runs ZAP scans and generates PDFs
      5) Finally stops ZAP
    This function's logic remains exactly as before.
    """
    zap_process = None
    try:
        zap_process = start_zap()
        zap_api = ZAPv2(apikey=ZAP_API_KEY)

        with open(INPUT_FILE, 'r') as file:
            for line in file:
                if not line.strip():
                    continue

                ip, domain = map(str.strip, line.split(':'))
                print(f"Processing {ip} : {domain}")

                raw_pdf = generate_raw_pdf_report(ip, domain, zap_api)
                generate_final_pdf_report(raw_pdf, ip, domain)

    finally:
        stop_zap(zap_process)

# ----------------------------------------------------
# Run the new prompt first, then run the original main
# ----------------------------------------------------
if __name__ == "__main__":
    prompt_for_input()
    main()
