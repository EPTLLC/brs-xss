#!/usr/bin/env python3

"""
Project: BRS-XSS
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 11 Oct 2025 01:14:00 UTC
Status: Modified
Telegram: https://t.me/easyprotech

CLI: Knowledge Base Command
"""

import typer
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

from brsxss.report.knowledge_base import (
    get_vulnerability_details,
    get_kb_info,
    list_contexts,
    KB_VERSION
)

console = Console()


kb_group = typer.Typer(name="kb", help="Knowledge Base - view vulnerability information")


@kb_group.callback()
def kb_group_callback():
    """Knowledge Base commands - view vulnerability information"""
    return


@kb_group.command(name='info')
def kb_info():
    """Show Knowledge Base information"""
    info = get_kb_info()
    
    console.print(Panel.fit(
        f"[bold cyan]BRS-XSS Knowledge Base[/bold cyan]\n"
        f"Version: [yellow]{info['version']}[/yellow]\n"
        f"Build: {info['build']}\n"
        f"Revision: [green]{info['revision']}[/green]\n"
        f"Total Contexts: [bold]{info['total_contexts']}[/bold]",
        title="Knowledge Base Info"
    ))


@kb_group.command(name='list', context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
def list_kb_contexts(ctx: typer.Context):
    """List all available contexts"""
    # Manual parse of --format/-f to avoid Click flag auto-detection quirks
    fmt = 'table'
    args = list(ctx.args or [])
    i = 0
    while i < len(args):
        token = args[i]
        if token in ('--format', '-f') and i + 1 < len(args):
            fmt = args[i + 1]
            i += 2
            continue
        i += 1

    contexts = list_contexts()
    if fmt == 'json':
        console.print_json(data=contexts)
        return
    if fmt == 'simple':
        for ctx_name in contexts:
            console.print(ctx_name)
        return
    # table (default)
    table = Table(title="Available Knowledge Base Contexts")
    table.add_column("Context", style="cyan")
    table.add_column("Title", style="white")
    for ctx_name in contexts:
        details = get_vulnerability_details(ctx_name)
        table.add_row(ctx_name, details.get('title', 'N/A')[:60])
    console.print(table)


@kb_group.command(name='show', context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
def show_context(ctx: typer.Context):
    """Show detailed information for a specific context"""
    # Manual parse: <context> [--format text|json|markdown] [--section all|description|attack_vector|remediation]
    args = list(ctx.args or [])
    context = None
    fmt = 'text'
    section = 'all'
    i = 0
    while i < len(args):
        token = args[i]
        if token in ('--format', '-f') and i + 1 < len(args):
            fmt = args[i + 1]
            i += 2
            continue
        if token in ('--section', '-s') and i + 1 < len(args):
            section = args[i + 1]
            i += 2
            continue
        if not token.startswith('-') and context is None:
            context = token
            i += 1
            continue
        i += 1

    if not context:
        console.print("[red]Error:[/red] Context name is required", style="bold")
        raise typer.Exit(2)

    # Validate context exists explicitly; fallback default should not mask unknown contexts
    contexts = list_contexts()
    if context.lower() not in [c.lower() for c in contexts]:
        console.print(f"[red]Error:[/red] Context '{context}' not found", style="bold")
        raise typer.Exit(2)

    details = get_vulnerability_details(context)

    if fmt == 'json':
        if section == 'all':
            console.print_json(data=details)
        else:
            console.print_json(data={section: details.get(section, '')})
        return

    # Text/Markdown output
    if section == 'all' or section == 'description':
        console.print(Panel(
            details.get('title', 'N/A'),
            title="[bold cyan]Vulnerability[/bold cyan]",
            style="bold"
        ))

        metadata = []
        if 'severity' in details:
            severity_color = {
                'low': 'green',
                'medium': 'yellow',
                'high': 'orange1',
                'critical': 'red'
            }.get(details['severity'], 'white')
            metadata.append(f"Severity: [{severity_color}]{details['severity'].upper()}[/{severity_color}]")

        if 'cvss_score' in details:
            metadata.append(f"CVSS: [yellow]{details['cvss_score']}[/yellow]")

        if 'cwe' in details:
            metadata.append(f"CWE: {', '.join(details['cwe'])}")

        if metadata:
            console.print("  ".join(metadata))
            console.print()

        console.print("[bold]Description:[/bold]")
        console.print(details.get('description', 'N/A'))
        console.print()

    if section == 'all' or section == 'attack_vector':
        console.print("[bold red]Attack Vectors:[/bold red]")
        console.print(details.get('attack_vector', 'N/A'))
        console.print()

    if section == 'all' or section == 'remediation':
        console.print("[bold green]Remediation:[/bold green]")
        console.print(details.get('remediation', 'N/A'))
        console.print()


@kb_group.command(name='search')
def search_kb(keyword: str = typer.Argument(..., help='Keyword to search')):
    """Search for contexts containing keyword"""
    contexts = list_contexts()
    matches = []
    
    keyword_lower = keyword.lower()
    
    for ctx in contexts:
        details = get_vulnerability_details(ctx)
        
        # Search in title and description
        if (keyword_lower in details.get('title', '').lower() or
            keyword_lower in details.get('description', '').lower() or
            keyword_lower in ctx.lower()):
            matches.append((ctx, details.get('title', 'N/A')))
    
    if not matches:
        console.print(f"[yellow]No contexts found matching '[bold]{keyword}[/bold]'[/yellow]")
        return
    
    table = Table(title=f"Search Results for '{keyword}'")
    table.add_column("Context", style="cyan")
    table.add_column("Title", style="white")
    
    for ctx, title in matches:
        table.add_row(ctx, title[:60])
    
    console.print(table)


@kb_group.command(name='export', context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
def export_context(ctx: typer.Context):
    """Export context details to file"""
    # Parse args: <context> <output_file> [--format json|yaml|markdown]
    args = list(ctx.args or [])
    context = None
    output_file = None
    fmt = 'json'
    i = 0
    while i < len(args):
        token = args[i]
        if token == '--format' and i + 1 < len(args):
            fmt = args[i + 1]
            i += 2
            continue
        if not token.startswith('-') and context is None:
            context = token
            i += 1
            continue
        if not token.startswith('-') and context is not None and output_file is None:
            output_file = token
            i += 1
            continue
        i += 1

    if not context or not output_file:
        console.print("[red]Error:[/red] Usage: kb export <context> <output_file> [--format json|yaml|markdown]")
        raise typer.Exit(2)

    # Validate context exists explicitly; do not rely on default fallback
    contexts = list_contexts()
    if context.lower() not in [c.lower() for c in contexts]:
        console.print(f"[red]Error:[/red] Context '{context}' not found", style="bold")
        return

    details = get_vulnerability_details(context)

    try:
        # Ensure parent directory exists
        from pathlib import Path
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)

        if fmt == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(details, f, indent=2, ensure_ascii=False)
        elif fmt == 'yaml':
            import yaml
            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump(details, f, default_flow_style=False, allow_unicode=True)
        elif fmt == 'markdown':
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"# {details.get('title', 'N/A')}\n\n")
                f.write(f"## Description\n\n{details.get('description', 'N/A')}\n\n")
                f.write(f"## Attack Vectors\n\n{details.get('attack_vector', 'N/A')}\n\n")
                f.write(f"## Remediation\n\n{details.get('remediation', 'N/A')}\n\n")
        else:
            console.print(f"[yellow]Unknown format '{fmt}', fallback to JSON[/yellow]")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(details, f, indent=2, ensure_ascii=False)

        console.print(f"[green]✓[/green] Exported context '[cyan]{context}[/cyan]' to {output_file}")
    except Exception as e:
        console.print(f"[red]Error:[/red] Failed to export: {e}", style="bold")


# For integration with main CLI
def register_kb_commands(cli):
    """Register KB commands with main CLI"""
    cli.add_typer(kb_group, name='kb')

