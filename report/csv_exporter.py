import csv

from scanner.detector import REQUIRED_HEADERS

def export_to_csv(results, filename):
    headers = sorted({
        h
        for proto in results.values()
        for ver in proto.values()
        if ver
        for h in ver["headers"]
    })

    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Header", "HTTPS 1.1", "HTTPS 1.0", "HTTP 1.1", "HTTP 1.0"])

        for header in headers:
            row = [header]
            for scheme in ["HTTPS", "HTTP"]:
                for ver in ["1.1", "1.0"]:
                    result = results[scheme].get(ver)
                    if result:
                        is_required = header in REQUIRED_HEADERS.get(scheme, {}).get(ver, [])
                        val = result["headers"].get(header, False)
                        if is_required:
                            row.append("✓" if val else "✗")
                        else:
                            row.append(" ")
                    else:
                        row.append("N/A")
            writer.writerow(row)

        # Notes
        writer.writerow([])
        writer.writerow(["Notes"])
        for scheme in ["HTTPS", "HTTP"]:
            for ver in ["1.1", "1.0"]:
                result = results[scheme].get(ver)
                if result and result["notes"]:
                    writer.writerow([f"{scheme} {ver} Notes"])
                    for note in result["notes"]:
                        plain_note = note.replace("[yellow]", "").replace("[blue]", "").replace("[/yellow]", "").replace("[/blue]", "")
                        writer.writerow([plain_note])
