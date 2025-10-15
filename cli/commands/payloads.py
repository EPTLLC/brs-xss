#!/usr/bin/env python3

"""
Project: BRS-XSS (XSS Detection Suite)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 15 Oct 2025 12:00:00 MSK
Status: Created
Telegram: https://t.me/EasyProTech

CLI: Payloads Command
"""

import typer
from typing import Optional
from rich.console import Console
from rich.table import Table

from brsxss.payloads.payload_manager import PayloadManager
from brsxss.payloads.context_matrix import ContextMatrix, Context

console = Console()

payloads_group = typer.Typer(name="payloads", help="List available XSS payloads")


@payloads_group.callback()
def payloads_callback():
    """Payloads commands - list available XSS payloads"""
    return


@payloads_group.command(name='list')
def list_payloads(
    context: Optional[str] = typer.Option(None, "--context", help="Filter by context (html, javascript, css, etc.)")
):
    """List available XSS payloads"""
    
    console.print("[bold]Available XSS Payloads[/bold]\n")
    
    manager = PayloadManager()
    matrix = ContextMatrix()
    
    if context:
        # Show payloads for specific context
        context_lower = context.lower()
        
        # Map context names to Context enum
        context_map = {
            'html': Context.HTML,
            'attribute': Context.ATTRIBUTE,
            'javascript': Context.JAVASCRIPT,
            'js': Context.JAVASCRIPT,
            'css': Context.CSS,
            'uri': Context.URI,
            'url': Context.URI,
            'svg': Context.SVG
        }
        
        if context_lower in context_map:
            ctx_enum = context_map[context_lower]
            payloads = list(matrix.get_context_payloads(ctx_enum))
            
            console.print(f"[cyan]Context:[/cyan] {context}")
            console.print(f"[cyan]Count:[/cyan] {len(payloads)}\n")
            
            # Show first 20 payloads
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("#", width=4)
            table.add_column("Payload", width=80)
            
            for i, payload in enumerate(payloads[:20], 1):
                table.add_row(str(i), str(payload)[:78])
            
            console.print(table)
            
            if len(payloads) > 20:
                console.print(f"\n[dim]... and {len(payloads) - 20} more payloads[/dim]")
        else:
            console.print(f"[red]Unknown context:[/red] {context}")
            console.print("\nAvailable contexts: html, attribute, javascript, css, uri, svg")
    else:
        # Show summary of all contexts
        console.print("[bold]Payload Summary by Context[/bold]\n")
        
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Context", width=20)
        table.add_column("Count", justify="right", width=10)
        table.add_column("Sample Payload", width=60)
        
        contexts = {
            'HTML': Context.HTML,
            'Attribute': Context.ATTRIBUTE,
            'JavaScript': Context.JAVASCRIPT,
            'CSS': Context.CSS,
            'URI': Context.URI,
            'SVG': Context.SVG
        }
        
        for name, ctx in contexts.items():
            payloads = list(matrix.get_context_payloads(ctx))
            sample = str(payloads[0])[:58] if payloads else "N/A"
            table.add_row(name, str(len(payloads)), sample)
        
        # Polyglots
        polyglots = matrix.get_polyglot_payloads()
        table.add_row("Polyglot", str(len(polyglots)), str(polyglots[0])[:58] if polyglots else "N/A")
        
        console.print(table)
        
        # Total from manager
        all_payloads = list(manager.get_all_payloads())
        console.print(f"\n[cyan]Total unique payloads:[/cyan] {len(all_payloads)}")
        
        console.print("\n[dim]Use --context <name> to see specific payloads[/dim]")


@payloads_group.command(name='count')
def count_payloads():
    """Show payload counts"""
    
    manager = PayloadManager()
    matrix = ContextMatrix()
    
    stats = matrix.get_total_payload_count()
    
    console.print("[bold]Payload Statistics[/bold]\n")
    console.print(f"Context-specific: {stats['context_specific']}")
    console.print(f"Polyglot: {stats['polyglot']}")
    console.print(f"Total unique: {stats['total_unique']}")
    
    # Manager stats
    all_count = len(list(manager.get_all_payloads()))
    console.print(f"\nPayload Manager: {all_count} payloads")

