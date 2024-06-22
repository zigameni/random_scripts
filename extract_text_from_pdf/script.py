import sys
from PyPDF2 import PdfReader

def pdf_to_markdown(pdf_file, md_file):
    with open(pdf_file, 'rb') as f:
        reader = PdfReader(f)
        num_pages = len(reader.pages)

        with open(md_file, 'w', encoding='utf-8') as md:
            for page_num in range(num_pages):
                page = reader.pages[page_num]
                text = page.extract_text()

                # Write page content with Markdown syntax
                md.write(f"# Page {page_num + 1}\n\n")  # Heading for each page
                md.write(text + "\n\n")  # Content of the page followed by new line

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <input_pdf_file> <output_markdown_file>")
        sys.exit(1)

    pdf_file = sys.argv[1]  # PDF file path passed as first argument
    md_file = sys.argv[2]   # Markdown file path passed as second argument

    pdf_to_markdown(pdf_file, md_file)
    print(f"Text extracted from {pdf_file} and saved to {md_file}")

