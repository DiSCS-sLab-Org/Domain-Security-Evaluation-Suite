import os
from PyPDF2 import PdfMerger
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

# Define folder paths
shodan_folder = "shodan_reports"
sucuri_folder = "sucuri_reports"
zap_folder = "zap_reports"
output_folder = "full_reports"

# Ensure the output folder exists
os.makedirs(output_folder, exist_ok=True)

def create_pdf_with_text(image_path, output_path, domain_name):
    """Convert a JPG image to a single-page PDF and add text."""
    c = canvas.Canvas(output_path, pagesize=letter)
    
    # Draw the image
    c.drawImage(image_path, 0, 0, width=letter[0], height=letter[1])
    
    # Set font for the text
    c.setFont("Helvetica-Bold", 20)
    
    # Add the text, centered horizontally, and vertically adjusted
    text_width = c.stringWidth(f"Security Evaluation of: {domain_name}", "Helvetica-Bold", 20)
    text_x = (letter[0] - text_width) / 2  # Center horizontally
    text_y = letter[1] - 255  # Lower the text to avoid overlapping the logo
    
    c.drawString(text_x, text_y, f"Security Evaluation of: {domain_name}")
    
    # Save the canvas
    c.save()

    
def extract_domain_name(base_name):
    """Extract the domain name from the base name."""
    # Split by `_` and take the last part after the IP
    try:
        parts = base_name.split('_')
        # Assume the domain name starts after the IP (the last segments)
        domain_name = '.'.join(parts[4:])  # Adjust index if needed
        return domain_name
    except IndexError:
        # If the structure doesn't match, return the full base name
        return base_name
    
def get_pdf_files(folder):
    """Get a dictionary of standardized PDF filenames and their actual paths."""
    files = {}
    try:
        for file in os.listdir(folder):
            if file.lower().endswith('.pdf'):
                base_name, _ = os.path.splitext(file)
                # Standardize the base name (replace special characters for consistency)
                standardized_name = base_name.replace('.', '_').replace('-', '_')
                files[standardized_name] = os.path.join(folder, file)
        print(f"PDF files in {folder}: {list(files.keys())}")  # Debug print
        return files
    except FileNotFoundError:
        print(f"Folder not found: {folder}")
        return {}

def merge_pdfs(base_name, file_paths, first_page_path):
    """Merge PDFs with the same base name in the specified order."""
    merger = PdfMerger()

    # Add the first page (from the image converted to PDF)
    if os.path.exists(first_page_path):
        merger.append(first_page_path)

    # Add all found PDFs to the merger
    for path in file_paths:
        merger.append(path)

    # Save the merged PDF to the output folder
    output_path = os.path.join(output_folder, f"{base_name}.pdf")
    merger.write(output_path)
    merger.close()
    print(f"Merged PDF saved as: {output_path}")

def main():
    # Path to the first page image
    first_page_image = "first_page.jpg"

    # Get the standardized filenames and their paths from each folder
    shodan_files = get_pdf_files(shodan_folder)
    sucuri_files = get_pdf_files(sucuri_folder)
    zap_files = get_pdf_files(zap_folder)

    # Find common standardized filenames across all folders
    common_files = set(shodan_files.keys()).intersection(sucuri_files.keys(), zap_files.keys())

    print(f"Common PDF files: {common_files}")  # Debug print

    if not common_files:
        print("No common PDF files found across the folders.")
        return

    # Merge PDFs for each common file in the specified order
    for base_name in common_files:
        # Extract the domain name
        domain_name = extract_domain_name(base_name)

        # Create the first page PDF with the domain name
        first_page_pdf = f"{domain_name}_first_page.pdf"
        create_pdf_with_text(first_page_image, first_page_pdf, domain_name)

        # Ensure the order is Shodan, Sucuri, Zap
        file_paths = [
            shodan_files[base_name],
            sucuri_files[base_name],
            zap_files[base_name]
        ]
        merge_pdfs(base_name, file_paths, first_page_pdf)

        # Clean up the first page PDF
        os.remove(first_page_pdf)

if __name__ == "__main__":
    main()
