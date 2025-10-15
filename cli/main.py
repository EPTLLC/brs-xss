#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Mon 13 Oct 2025 00:00:00 UTC
Status: Modified
Telegram: https://t.me/EasyProTech
"""

import typer
from typing import Optional
from rich.console import Console
from rich.text import Text

from .commands import simple_scan
from .commands.kb import kb_group
from brsxss import __version__
from brsxss.report.knowledge_base import KB_VERSION

app = typer.Typer(
    name="brs-xss",
    help="BRS-XSS - XSS vulnerability scanner",
    no_args_is_help=True,
    rich_markup_mode="rich"
)

console = Console()

# Scan command with explicit options to avoid Typer secondary flags
@app.command(name="scan", help="Scan domain or IP for XSS vulnerabilities", context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
def scan(
    target: str = typer.Argument(..., help="Target domain or IP (or URL)"),
    threads: int = typer.Option(10, "--threads", help="Max concurrent requests"),
    timeout: int = typer.Option(15, "--timeout", help="Request timeout (seconds)"),
    output: Optional[str] = typer.Option(None, "--output", help="Path to save JSON report"),
    deep: bool = typer.Option(False, "--deep", is_flag=True, help="Enable deep discovery (crawl forms)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", is_flag=True, help="Verbose output"),
    ml_mode: bool = typer.Option(False, "--ml-mode", is_flag=True, help="Enable ML classification"),
    blind_xss_webhook: Optional[str] = typer.Option(None, "--blind-xss-webhook", help="Webhook for blind XSS"),
    no_ssl_verify: bool = typer.Option(False, "--no-ssl-verify", is_flag=True, help="Disable SSL verification"),
    safe_mode: bool = typer.Option(True, "--safe-mode", is_flag=True, help="Restrict dangerous payloads"),
    pool_cap: int = typer.Option(10000, "--pool-cap", help="Max payload pool size"),
    max_payloads: int = typer.Option(500, "--max-payloads", help="Max payloads per entry point"),
):
    simple_scan.simple_scan_wrapper(
        target,
        threads,
        timeout,
        output,
        deep,
        verbose,
        ml_mode,
        blind_xss_webhook,
        no_ssl_verify,
        safe_mode,
        pool_cap,
        max_payloads,
    )

# Knowledge Base commands
app.add_typer(kb_group, name="kb", help="Knowledge Base - view vulnerability information")


@app.command()
def version():
    """Show version information"""
    version_text = Text()
    version_text.append(f"BRS-XSS v{__version__}\n", style="bold green")
    version_text.append(f"Knowledge Base v{KB_VERSION}\n", style="bold cyan")
    version_text.append("XSS vulnerability scanner\n", style="dim")
    version_text.append("Company: EasyProTech LLC (www.easypro.tech)\n", style="dim")
    version_text.append("Developer: Brabus\n", style="dim")
    console.print(version_text)

@app.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
def config(ctx: typer.Context):
    """Manage configuration settings"""
    from brsxss.core.config_manager import ConfigManager
    
    # Manual parse of flags and options due to parsing quirks
    args = list(ctx.args or [])
    show = False
    set_option = None
    config_file = None
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--show":
            show = True
            i += 1
            continue
        if token == "--set" and i + 1 < len(args):
            set_option = args[i + 1]
            i += 2
            continue
        if token in ("--config", "--config-file") and i + 1 < len(args):
            config_file = args[i + 1]
            i += 2
            continue
        i += 1

    config_manager = ConfigManager(config_file)
    
    shown = False
    if show:
        console.print("[bold]Configuration:[/bold]")
        summary = config_manager.get_config_summary()
        for key, value in summary.items():
            console.print(f"  {key}: {value}")
        shown = True
    
    if set_option:
        try:
            key, value = set_option.split('=', 1)
            config_manager.set(key, value)
            config_manager.save()
            console.print(f"[green]Configuration updated: {key} = {value}[/green]")
        except ValueError:
            console.print("[red]Invalid format. Use: key=value[/red]")
            raise typer.Exit(1)

    if not shown and not set_option:
        # Show brief help if no flags provided, exit 0
        console.print("Use 'brs-xss config --show' to display configuration or '--set key=value' to update.")
        raise typer.Exit(0)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode"),
    log_file: Optional[str] = typer.Option(None, "--log-file", help="Log file path")
):
    """BRS-XSS - XSS vulnerability scanner with detection capabilities"""
    
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