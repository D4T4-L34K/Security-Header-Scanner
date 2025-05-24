import argparse
import logging

from scanner.protocol_scanner import scan_all_protocols
from report.terminal import print_table
from report.text_exporter import export_to_text
from report.csv_exporter import export_to_csv
from report.html_exporter import export_to_html

logging.basicConfig(level=logging.INFO, format="%(message)s")

def main():
    parser = argparse.ArgumentParser(
        prog="BitSight Security Header Detector",
        description="Scan HTTP & HTTPS security headers."
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--csv", help="Output CSV filename")
    parser.add_argument("--text", help="Output Text filename")
    parser.add_argument("--html", help="Output HTML file name")
    parser.add_argument("--internal", action="store_true", help="Flag to identify internal systems")
    args = parser.parse_args()

    results = scan_all_protocols(args.url, args.internal)

    print_table(results)

    if args.csv:
        export_to_csv(results, args.csv)
    if args.text:
        export_to_text(results, args.text)
    if args.html:
        export_to_html(results, args.html)

if __name__ == "__main__":
    main()
