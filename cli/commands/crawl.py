#!/usr/bin/env python3

"""
BRS-XSS Crawl Command

Command for crawling entire websites.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Thu 31 Jul 00:17:37 MSK 2025
Telegram: https://t.me/EasyProTech
"""

from typing import Optional
import time
import asyncio

import typer
from rich.console import Console

from brsxss import _
from brsxss.crawler.engine import CrawlerEngine, CrawlConfig
from brsxss.utils.logger import Logger
from brsxss.utils.validators import URLValidator


app = typer.Typer()
@app.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
def crawl_command(ctx: typer.Context):
    """Crawl entire website for XSS vulnerabilities"""
    
    console = Console()
    logger = Logger("cli.crawl")

    # Manual parse of args to avoid Click flag quirks
    url = None
    depth = 3
    threads = 10
    output: Optional[str] = None
    args = list(ctx.args or [])
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--depth" and i + 1 < len(args):
            try:
                depth = int(args[i + 1])
            except Exception:
                pass
            i += 2
            continue
        if token == "--threads" and i + 1 < len(args):
            try:
                threads = int(args[i + 1])
            except Exception:
                pass
            i += 2
            continue
        if token == "--output" and i + 1 < len(args):
            output = args[i + 1]
            i += 2
            continue
        if not token.startswith('-') and url is None:
            url = token
            i += 1
            continue
        i += 1

    if not url:
        console.print("[red]Invalid URL: (missing)[/red]")
        raise typer.Exit(1)

    console.print("[bold blue]Website crawling mode[/bold blue]")
    console.print(_("Target: {url}").format(url=url))
    console.print(_("Depth: {depth}").format(depth=depth))
    console.print(_("Threads: {threads}").format(threads=threads))
    
    # Validate URL
    validation_result = URLValidator.validate_url(url)
    if not validation_result.valid:
        console.print(f"[red]Invalid URL: {url}[/red]")
        for error in validation_result.errors:
            console.print(f"[red]Error: {error}[/red]")
        raise typer.Exit(1)
    
    normalized_url = validation_result.normalized_value or url
    
    try:
        # Initialize crawler
        console.print("Initializing crawler engine...")
        
        crawl_config = CrawlConfig(
            max_depth=depth,
            max_urls=100,
            max_concurrent=threads,
            timeout=30
        )
        
        crawler = CrawlerEngine(crawl_config)
        
        # Start crawling
        console.print("Starting website crawl...")
        start_time = time.time()
        
        # Run crawler asynchronously
        crawl_result = asyncio.run(crawler.crawl(normalized_url))
        
        crawl_duration = time.time() - start_time
        console.print("\nCrawl completed")
        
        # Aggregate results from all crawled pages
        all_discovered_urls = []
        all_forms = []
        all_parameters = set()
        
        for result in crawl_result:
            if hasattr(result, 'discovered_urls') and result.discovered_urls:
                all_discovered_urls.extend(result.discovered_urls)
            if hasattr(result, 'extracted_forms') and result.extracted_forms:
                all_forms.extend(result.extracted_forms)
            if hasattr(result, 'potential_parameters') and result.potential_parameters:
                all_parameters.update(result.potential_parameters)
        
        # Statistics
        stats = {
            _("URLss discovered"): len(all_discovered_urls),
            _("Forms found"): len(all_forms),
            _("Parameters discovered"): len(all_parameters),
            _("Crawl duration"): f"{crawl_duration:.1f} sec",
        }
        
        # Print statistics
        console.print("\n[bold cyan]Crawl Statistics:[/bold cyan]")
        for key, value in stats.items():
            console.print(f"  {key}: {value}")
        
        # Save results if requested
        if output:
            console.print(f"Saving crawl results: {output}")
            import json
            crawl_data = {
                "target_url": normalized_url,
                "discovered_urls": [url.url if hasattr(url, 'url') else str(url) for url in all_discovered_urls],
                "forms": [{"action": str(f.action), "method": f.method} if hasattr(f, 'action') else {"action": str(f), "method": "GET"} for f in all_forms],
                "parameters": list(all_parameters),
                "crawl_duration": crawl_duration,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            with open(output if output.endswith('.json') else f"{output}.json", 'w') as f:
                json.dump(crawl_data, f, indent=2)
            console.print(_("Crawl results saved: {filepath}").format(filepath=output))
        
        console.print(f"\n[green]Crawl successful: {len(all_discovered_urls)} URLs discovered[/green]")
            
    except KeyboardInterrupt:
        console.print("\nCrawl interrupted by user")
        raise typer.Exit(130)
        
    except Exception as e:
        logger.error(f"Crawl error: {str(e)}")
        raise typer.Exit(1)


# Create typer app for this command (already created above)
