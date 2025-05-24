from scanner.detector import REQUIRED_HEADERS

def export_to_text(results, filename):
    with open(filename, "w") as f:
        headers = sorted({
            h
            for proto in results.values()
            for ver in proto.values()
            if ver
            for h in ver["headers"]
        })

        f.write("Header\tHTTPS/1.1\tHTTPS/1.0\tHTTP/1.1\tHTTP/1.0\n")

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
            f.write("\t".join(row) + "\n")

        for scheme in ["HTTPS", "HTTP"]:
            for ver in ["1.1", "1.0"]:
                result = results[scheme].get(ver)
                if result and result["notes"]:
                    f.write(f"\n[{scheme} {ver} Notes]\n")
                    for note in result["notes"]:
                        # Strip color tags for text output
                        plain_note = note.replace("[yellow]", "").replace("[blue]", "").replace("[/yellow]", "").replace("[/blue]", "")
                        f.write(f"- {plain_note}\n")
