#!/usr/bin/env python3

"""
Shodan scanning script
(Original logic unchanged, only input handling is added)
"""

from playwright.sync_api import sync_playwright
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
import json
import os
import sys


###################################
# New function to handle user input
###################################
def prompt_for_input():
    """
    Prompt the user to decide how to get 'IP : domain' pairs:
      1) From existing domains_test.txt
      2) Enter them manually (one per line)
    If manual is chosen, this overwrites domains_test.txt accordingly.
    """
    print("Shodan: Choose domain input method:")
    print("1) Use existing domains_test.txt")
    print("2) Enter domain(s) manually (e.g. 1.2.3.4: example.com)")
    choice = input("Enter 1 or 2: ").strip()
    
    if choice == "2":
        # Overwrite domains_test.txt with manually entered lines
        lines = []
        print("Enter 'IP : domain' pairs, one per line. Leave blank to finish:")
        while True:
            entry = input("> ").strip()
            if not entry:
                break
            lines.append(entry)
        
        with open("domains_test.txt", "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")


def scrape_shodan_page(ip, domain):
    # -- Original function unchanged --
    result = {
        "IP Address": ip,
        "Domain": domain,
        "General Information": {
            "Hostnames": "N/A",
            "Domains": "N/A",
            "Country": "N/A",
            "City": "N/A",
            "ISP": "N/A",
            "ASN": "N/A"
        },
        "Ports": {}
    }
    shodan_url = f"https://www.shodan.io/host/{ip}"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(shodan_url, timeout=60000)
            try:
                hostnames = page.locator("text=Hostnames").locator("xpath=following-sibling::td").inner_text()
                result["General Information"]["Hostnames"] = hostnames.replace("\n", ", ")
                domains = page.locator("text=Domains").locator("xpath=following-sibling::td").inner_text()
                result["General Information"]["Domains"] = domains.replace("\u00a0", " ")
                country = page.locator("text=Country").locator("xpath=following-sibling::td").inner_text()
                result["General Information"]["Country"] = country
                city = page.locator("text=City").locator("xpath=following-sibling::td").inner_text()
                result["General Information"]["City"] = city
                isp = page.locator("text=ISP").locator("xpath=following-sibling::td").inner_text()
                result["General Information"]["ISP"] = isp
                asn = page.locator("text=ASN").locator("xpath=following-sibling::td").inner_text()
                result["General Information"]["ASN"] = asn
            except Exception as e:
                print(f"Error extracting General Information: {e}")
            try:
                port_elements = page.locator("#ports a")
                for port_element in port_elements.element_handles():
                    port = port_element.inner_text().strip()
                    port_locator = f"h6[id='{port}']"
                    technology_locator = page.locator(f"{port_locator} ~ div .banner-title")
                    if technology_locator.count() > 0:
                        technology = technology_locator.nth(0).inner_text().strip()
                    else:
                        technology = "Unknown"
                    vulnerabilities = []
                    cve_elements = page.locator(f"{port_locator} ~ div .cve-list a.cve-tag")
                    for cve in cve_elements.element_handles():
                        cve_id = cve.inner_text().strip()
                        if "more" in cve_id:
                            continue
                        class_attribute = cve.get_attribute("class")
                        if "bg-danger" in class_attribute:
                            color = "red"
                        elif "bg-warning" in class_attribute:
                            color = "orange"
                        elif "bg-info" in class_attribute:
                            color = "blue"
                        else:
                            color = "gray"
                        vulnerabilities.append({"cve_id": cve_id, "color": color})
                    unique_vulnerabilities = []
                    seen_cves = set()
                    for vuln in vulnerabilities:
                        if vuln["cve_id"] not in seen_cves:
                            seen_cves.add(vuln["cve_id"])
                            unique_vulnerabilities.append(vuln)
                    sorted_vulnerabilities = sorted(
                        unique_vulnerabilities,
                        key=lambda x: ["red", "orange", "blue", "gray"].index(x["color"])
                    )
                    result["Ports"][port] = {
                        "Technology": technology,
                        "Vulnerabilities": sorted_vulnerabilities
                    }
            except Exception as e:
                print(f"Error extracting Ports: {e}")
            browser.close()
    except Exception as e:
        print(f"Error accessing Shodan page for {ip}: {e}")
    return result

def generate_pdf_report(data, output_file):
    # -- Original function unchanged --
    doc = SimpleDocTemplate(output_file, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    title = Paragraph(f"Shodan Report for {data['IP Address']} ({data['Domain']})", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))
    elements.append(Paragraph("<b>General Information:</b>", styles['Heading2']))
    general_info_table = Table(
        [[key, value] for key, value in data["General Information"].items()],
        colWidths=[100, 300]
    )
    general_info_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
    ]))
    elements.append(general_info_table)
    elements.append(Spacer(1, 12))
    if data["Ports"]:
        for idx, (port, details) in enumerate(data["Ports"].items()):
            if idx > 0:
                elements.append(PageBreak())
            elements.append(Paragraph(f"<b>Port {port}:</b>", styles['Heading3']))
            elements.append(Paragraph(f"Technology: {details['Technology']}", styles['BodyText']))
            elements.append(Spacer(1, 6))
            elements.append(Paragraph("<b>Vulnerabilities:</b>", styles['Heading3']))
            if details["Vulnerabilities"]:
                rows = []
                current_row = []
                for i, vulnerability in enumerate(details["Vulnerabilities"]):
                    cve_id = vulnerability["cve_id"]
                    color = vulnerability["color"]
                    current_row.append(Paragraph(f'<font color="{color}">{cve_id}</font>', styles['BodyText']))
                    if (i + 1) % 3 == 0:
                        rows.append(current_row)
                        current_row = []
                if current_row:
                    rows.append(current_row)
                vulnerabilities_table = Table(rows, colWidths=[150, 150, 150])
                vulnerabilities_table.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ]))
                elements.append(vulnerabilities_table)
            else:
                elements.append(Paragraph("No vulnerabilities found.", styles['BodyText']))
            elements.append(Spacer(1, 12))
    else:
        elements.append(Paragraph("No open ports found.", styles['BodyText']))
        elements.append(Spacer(1, 12))
    doc.build(elements)

def main():
    # -- Original main function, unchanged --
    input_file = "domains_test.txt"
    output_dir = "shodan_reports"
    os.makedirs(output_dir, exist_ok=True)
    with open(input_file, "r", encoding="utf-8") as f:
        domain_list = [line.strip() for line in f if line.strip()]
    for entry in domain_list:
        try:
            ip, domain = map(str.strip, entry.split(":"))
            print(f"Processing: {ip} : {domain}")
            report = scrape_shodan_page(ip, domain)
            json_output_file = os.path.join(output_dir, f"{ip}_{domain.replace('.', '_')}.json")
            with open(json_output_file, "w", encoding="utf-8") as json_file:
                json.dump(report, json_file, ensure_ascii=False, indent=4)
            pdf_output_file = os.path.join(output_dir, f"{ip}_{domain.replace('.', '_')}.pdf")
            generate_pdf_report(report, pdf_output_file)
            print(f"Reports saved: {json_output_file}, {pdf_output_file}")
        except Exception as e:
            print(f"Error processing {entry}: {e}")

##########################################
# Call the new prompt, then run main()
##########################################

if __name__ == "__main__":
    # Only prompt the user if they haven't passed --no-prompt
    if "--no-prompt" not in sys.argv:
        prompt_for_input()
    main()
