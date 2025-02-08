#!/usr/bin/env python3

import os
import sys
import subprocess
import time
from PyPDF2 import PdfMerger
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

SHODAN_FOLDER = "shodan_reports"
SUCURI_FOLDER = "sucuri_reports"
ZAP_FOLDER = "zap_reports"
OUTPUT_FOLDER = "full_reports"

def create_domain_test_file(domains):
    """
    Overwrites 'domains_test.txt' with the given list of 'ip:domain' lines.
    """
    with open("domains_test.txt", "w", encoding="utf-8") as f:
        for line in domains:
            f.write(line + "\n")

def read_domains_from_file(file_path="domains_test.txt"):
    """
    Reads the 'domains_test.txt' file and returns a list of lines like 'ip:domain'.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def create_first_page_pdf(domain_line, output_path, title_image="first_page.jpg"):
    """
    Creates a single-page PDF that includes:
      - The provided 'title_image' stretched to page size
      - A line of text identifying the domain
    """
    try:
        ip, domain = map(str.strip, domain_line.split(":"))
        text_to_display = f"Security Evaluation of: {domain}"
    except:
        text_to_display = f"Security Evaluation of: {domain_line}"

    c = canvas.Canvas(output_path, pagesize=letter)
    c.drawImage(title_image, 0, 0, width=letter[0], height=letter[1])
    c.setFont("Helvetica-Bold", 20)
    text_width = c.stringWidth(text_to_display, "Helvetica-Bold", 20)
    text_x = (letter[0] - text_width) / 2
    text_y = letter[1] - 255
    c.drawString(text_x, text_y, text_to_display)
    c.save()

def standardized_pdf_name(ip, domain):
    """
    Matches how PDFs are named in the existing scripts: ip_domain.pdf
    Replaces '.' in domain with '_' so it aligns with the naming in shodan.py.
    """
    domain_sanitized = domain.replace(".", "_")
    return f"{ip}_{domain_sanitized}.pdf"

def merge_reports_for_domain(domain_line, tools_ran, first_page_image="first_page.jpg"):
    try:
        ip, domain = map(str.strip, domain_line.split(":"))
    except:
        return

    # Create the temporary front page
    tmp_first_page_pdf = f"tmp_{ip}_{domain.replace('.', '_')}.pdf"
    create_first_page_pdf(domain_line, tmp_first_page_pdf, first_page_image)

    pdfs_to_merge = []

    # Shodan uses underscores in place of dots
    if "shodan" in tools_ran:
        shodan_filename = f"{ip}_{domain.replace('.', '_')}.pdf"
        shodan_pdf_path = os.path.join(SHODAN_FOLDER, shodan_filename)
        if os.path.exists(shodan_pdf_path):
            pdfs_to_merge.append(shodan_pdf_path)

    # Sucuri uses the domain as is (preserves the dot in 'red-book.eu')
    if "sucuri" in tools_ran:
        sucuri_filename = f"{ip}_{domain}.pdf"  # <-- no replace('.','_')
        sucuri_pdf_path = os.path.join(SUCURI_FOLDER, sucuri_filename)
        if os.path.exists(sucuri_pdf_path):
            pdfs_to_merge.append(sucuri_pdf_path)

    # ZAP also uses underscores
    if "zap" in tools_ran:
        zap_filename = f"{ip}_{domain.replace('.', '_')}.pdf"
        zap_pdf_path = os.path.join(ZAP_FOLDER, zap_filename)
        if os.path.exists(zap_pdf_path):
            pdfs_to_merge.append(zap_pdf_path)

    # If none were found, skip
    if not pdfs_to_merge:
        print(f"[WARNING] No reports to merge for {domain_line}")
        if os.path.exists(tmp_first_page_pdf):
            os.remove(tmp_first_page_pdf)
        return

    # Final PDF will also use underscores
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    merged_output = os.path.join(OUTPUT_FOLDER, f"{ip}_{domain.replace('.', '_')}.pdf")

    merger = PdfMerger()
    merger.append(tmp_first_page_pdf)
    for pdf_path in pdfs_to_merge:
        merger.append(pdf_path)
    with open(merged_output, "wb") as f:
        merger.write(f)
    merger.close()

    if os.path.exists(tmp_first_page_pdf):
        os.remove(tmp_first_page_pdf)

    print(f"[INFO] Final merged PDF saved to {merged_output}")


def run_tool(tool_name):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    python_exe = sys.executable  # Points to the current Python interpreter

    if tool_name == "shodan":
        print("[INFO] Running Shodan script...")
        subprocess.call([python_exe, os.path.join(current_dir, "shodan.py"), "--no-prompt"])
    elif tool_name == "sucuri":
        print("[INFO] Running Sucuri script...")
        subprocess.call([python_exe, os.path.join(current_dir, "sucuri.py"), "--no-prompt"])
    elif tool_name == "zap":
        print("[INFO] Running ZAP script...")
        subprocess.call([python_exe, os.path.join(current_dir, "zap.py"), "--no-prompt"])
    else:
        print(f"[WARNING] Unknown tool requested: {tool_name}")


def main():
    print("Select domain input method:")
    print("1) Use existing domains_test.txt")
    print("2) Enter domain(s) manually (e.g. 1.2.3.4: example.com)")
    choice_input = input("Enter 1 or 2: ").strip()

    if choice_input == "1":
        domain_lines = read_domains_from_file("domains_test.txt")
    else:
        domain_lines = []
        print("Enter domain(s) in the format 'IP : domain', one per line.")
        print("Enter an empty line when done.")
        while True:
            ln = input("> ").strip()
            if not ln:
                break
            domain_lines.append(ln)
        create_domain_test_file(domain_lines)

    print("Which tools would you like to run?")
    print("Enter any combination of: shodan, sucuri, zap. (e.g. 'shodan,sucuri')")
    chosen = input("Tools: ").strip().lower()
    if not chosen:
        print("No tools selected. Exiting.")
        return

    chosen_tools = [x.strip() for x in chosen.replace(";", ",").split(",") if x.strip()]

    for tool in chosen_tools:
        run_tool(tool)

    for line in domain_lines:
        merge_reports_for_domain(line, chosen_tools)

    print("[INFO] All done.")

if __name__ == "__main__":
    main()
