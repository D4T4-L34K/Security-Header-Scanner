from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from scanner.detector import REQUIRED_HEADERS

console = Console()

def print_table(results):
    table = Table(title="Security Header Scan Results", show_lines=True)

    # Build header
    table.add_column("Header")
    table.add_column("HTTPS 1.1", justify="center")
    table.add_column("HTTPS 1.0", justify="center")
    table.add_column("HTTP 1.1", justify="center")
    table.add_column("HTTP 1.0", justify="center")

    # Gather all unique headers
    all_headers = set()
    for protocol in results:
        for version in results[protocol]:
            result = results[protocol][version]
            if result:
                all_headers.update(result["headers"].keys())

    for header in sorted(all_headers):
        row = [header]
        for scheme in ["HTTPS", "HTTP"]:
            for ver in ["1.1", "1.0"]:
                result = results[scheme].get(ver)
                if result:
                    is_required = header in REQUIRED_HEADERS.get(scheme, {}).get(ver, [])
                    value = result["headers"].get(header, False)
                    if is_required:
                        row.append("[green]✓[/green]" if value else "[red]✗[/red]")
                    else:
                        row.append(" ")
                else:
                    row.append("[grey]N/A[/grey]")
        table.add_row(*row)

    console.print(table)

    # Print Notes per scan version
    for scheme in ["HTTPS", "HTTP"]:
        for ver in ["1.1", "1.0"]:
            result = results[scheme].get(ver)
            if result and result["notes"]:
                console.print(Panel.fit(
                    "\n".join(result["notes"]),
                    title=f"{scheme} {ver} Notes",
                    border_style="cyan"
                ))
