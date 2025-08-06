#!/usr/bin/env python3

"""
BRS-XSS CLI Main

Command line interface for the BRS-XSS vulnerability scanner.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: Sat 02 Aug 2025 09:35:54 MSK
Telegram: @easyprotech
"""

import typer
import asyncio
import time
from typing import Optional
from rich.console import Console
from rich.text import Text

from .commands import simple_scan, crawl, fuzz

app = typer.Typer(
    name="brs-xss",
    help="BRS-XSS - XSS vulnerability scanner with advanced detection capabilities",
    no_args_is_help=False,
    rich_markup_mode="rich"
)

console = Console()

# Add subcommands
app.command(name="scan", help="Scan domain or IP for XSS vulnerabilities")(simple_scan.simple_scan_wrapper)
app.add_typer(crawl.app, name="crawl", help="Crawl website and extract forms")
app.add_typer(fuzz.app, name="fuzz", help="Fuzzing mode for parameter discovery")
# GUI removed - terminal-only mode


@app.command()
def version():
    """Show version information"""
    version_text = Text()
    version_text.append("BRS-XSS v1.0.0\n", style="bold green")
    version_text.append("XSS vulnerability scanner\n", style="dim")
    version_text.append("Company: EasyProTech LLC (www.easypro.tech)\n", style="dim")
    version_text.append("Developer: Brabus\n", style="dim")
    console.print(version_text)


@app.command()
def config(
    show: bool = typer.Option(False, "--show", help="Show current configuration"),
    set_option: Optional[str] = typer.Option(None, "--set", help="Set configuration option (key=value)"),
    config_file: Optional[str] = typer.Option(None, "--config", help="Configuration file path")
):
    """Manage configuration settings"""
    from brsxss.core.config_manager import ConfigManager
    
    config_manager = ConfigManager(config_file)
    
    if show:
        console.print("[bold]Configuration:[/bold]")
        summary = config_manager.get_config_summary()
        for key, value in summary.items():
            console.print(f"  {key}: {value}")
    
    if set_option:
        try:
            key, value = set_option.split('=', 1)
            config_manager.set(key, value)
            config_manager.save()
            console.print(f"[green]Configuration updated: {key} = {value}[/green]")
        except ValueError:
            console.print("[red]Invalid format. Use: key=value[/red]")
            raise typer.Exit(1)


def interactive_mode():
    """Interactive terminal mode - simple and user-friendly"""
    from rich.prompt import Prompt, Confirm
    from rich.panel import Panel
    from rich.table import Table
    
    console.print(Panel.fit(
        "[bold green]BRS-XSS v1.0.0[/bold green]\n"
        "[dim]Professional XSS Terminal Scanner[/dim]\n" 
        "[dim]EasyProTech LLC - @easyprotech[/dim]",
        title="Security Scanner"
    ))
    # Get target
    target = Prompt.ask("\n[bold]Enter domain or IP address to scan[/bold]", default="")
    if not target.strip():
        console.print("[red]No target specified. Exiting.[/red]")
        raise typer.Exit(1)
    
    # Scan options
    console.print("\n[bold]Scan Options:[/bold]")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Option", style="cyan")
    table.add_column("Description", style="dim")
    
    table.add_row("1", "Quick Scan (basic parameters)")
    table.add_row("2", "Deep Scan (crawling + forms)")
    table.add_row("3", "Full Scan (everything)")
    table.add_row("4", "Custom Settings")
    
    console.print(table)
    
    choice = Prompt.ask("\n[bold]Select scan type[/bold]", choices=["1", "2", "3", "4"], default="1")
    
    # Set parameters based on choice
    if choice == "1":
        deep = False
        threads = 10
        timeout = 15
    elif choice == "2":
        deep = True
        threads = 15
        timeout = 20
    elif choice == "3":
        deep = True
        threads = 20
        timeout = 30
    else:  # Custom
        deep = Confirm.ask("Enable deep scanning (forms + crawling)?", default=False)
        threads = int(Prompt.ask("Number of threads", default="10"))
        timeout = int(Prompt.ask("Request timeout (seconds)", default="15"))
    
    # Ask for report
    save_report = Confirm.ask("\nSave detailed report?", default=True)
    output_file = None
    if save_report:
        # Create filename with timestamp
        timestamp = int(time.time())
        clean_target = target.replace('.', '_').replace(':', '_')
        filename = f"scan_report_{clean_target}_{timestamp}.json"
        
        # Save to proper results directory
        import os
        os.makedirs("results/json", exist_ok=True)
        output_file = f"results/json/{filename}"
    
    console.print(f"\n[bold green]Starting scan of {target}...[/bold green]")
    
    # Run scan
    try:
        asyncio.run(simple_scan.simple_scan(target, threads, timeout, output_file, deep, verbose=False, ml_mode=True, blind_xss_webhook=None, no_ssl_verify=False))
    except Exception as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        raise typer.Exit(1)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode"),
    log_file: Optional[str] = typer.Option(None, "--log-file", help="Log file path")
):
    """BRS-XSS - XSS vulnerability scanner with advanced detection capabilities"""
    
    # Setup logging
    from brsxss.utils.logger import Logger
    
    if quiet:
        log_level = "ERROR"
    elif verbose:
        log_level = "DEBUG"
    else:
        log_level = "INFO"
    
    Logger.setup_global_logging(log_level, log_file)
    
    # If no command specified, start interactive mode
    if ctx.invoked_subcommand is None:
        interactive_mode()


if __name__ == "__main__":
    app()