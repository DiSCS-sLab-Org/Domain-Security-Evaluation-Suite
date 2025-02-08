#!/usr/bin/env python3

"""
Sucuri scanning script
"""

import os
import sys
import time
from playwright.sync_api import sync_playwright

###################################
# Function to handle user input
###################################
def prompt_for_input():
    """
    Prompt the user to decide how to get 'IP : domain' pairs:
      1) From existing domains_test.txt
      2) Enter them manually (one per line)
    If manual is chosen, overwrites domains_test.txt.
    """
    print("Sucuri: Choose domain input method:")
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
        
        with open("domains_test.txt", "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")


def remove_all_after_heading(page, heading_text):
    locator = page.locator(f"h2:has-text('{heading_text}')").first
    if locator.count() == 0:
        return
    locator.evaluate("""
    (heading) => {
      const doc = heading.ownerDocument;
      const body = doc.body;
      const allElems = Array.from(body.querySelectorAll('*'));
      let startRemoving = false;
      for (const el of allElems) {
        if (el === heading) {
          startRemoving = true;
          el.remove();
        } else if (startRemoving) {
          el.remove();
        }
      }
    }
    """)

def main():
    input_file = "domains_test.txt"
    folder = "sucuri_reports"
    os.makedirs(folder, exist_ok=True)
    with open(input_file, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        for line in lines:
            ip, domain = map(str.strip, line.split(":"))
            url = f"https://sitecheck.sucuri.net/results/{domain}"
            out_pdf = os.path.join(folder, f"{ip}_{domain}.pdf")
            print(f"[INFO] Navigating to {url} ...")
            page = context.new_page()
            page.goto(url, timeout=60000)
            try:
                page.locator("button:has-text('Accept')").click(timeout=3000)
            except:
                pass
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            time.sleep(2)
            remove_all_after_heading(page, "Hacked? Get help now.")
            page.pdf(
                path=out_pdf,
                format="A4",
                print_background=True,
                margin={"top": "0.5in", "bottom": "0.5in",
                        "left": "0.5in", "right": "0.5in"},
                scale=0.95
            )
            print(f"[DONE] PDF saved to {out_pdf}")
            page.close()
        browser.close()

###################################################
# Prompt user for input, then call original main()
###################################################
if __name__ == "__main__":
    prompt_for_input()
    main()
