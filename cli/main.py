#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sun 10 Aug 2025 21:38:09 MSK
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import typer
from typing import Optional
from rich.console import Console
from rich.text import Text

from .commands import simple_scan
from brsxss import __version__

app = typer.Typer(
    name="brs-xss",
    help="BRS-XSS - XSS vulnerability scanner with advanced detection capabilities",
    no_args_is_help=True,
    rich_markup_mode="rich"
)

console = Console()

# Single authoritative command: serious scanning by default
app.command(name="scan", help="Scan domain or IP for XSS vulnerabilities")(simple_scan.simple_scan_wrapper)


@app.command()
def version():
    """Show version information"""
    version_text = Text()
    version_text.append(f"BRS-XSS v{__version__}\n", style="bold green")
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
    
    # If no command specified, Typer shows help (no_args_is_help=True)


if __name__ == "__main__":
    app()