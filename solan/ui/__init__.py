from rich.table import Table
from rich.console import Console

from solan.rules import BaseSignature


def renderThreats(threats: list[BaseSignature]):
    table = Table(title="Defender Signatures")
    table.add_column("Threat", style="cyan", no_wrap=True)
    table.add_column("Category", style="cyan")
    table.add_column("# Signatures", style="cyan")

    for threat in threats:
        table.add_row(threat.threat_name, threat.category, str(len(threat.signatures)))
    console = Console()
    console.print(table)
