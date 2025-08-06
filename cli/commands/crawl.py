#!/usr/bin/env python3

"""
BRS-XSS Crawl Command

Command for crawling entire websites.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Created: Thu 31 Jul 00:17:37 MSK 2025
Telegram: @easyprotech
"""

from typing import Optional
import time
import asyncio

import typer
from rich.console import Console
from rich.progress import Progress

from brsxss import _
from brsxss.crawler.engine import CrawlerEngine, CrawlConfig
from brsxss.utils.logger import Logger
from brsxss.utils.validators import URLValidator


def crawl_command(
    url: str = typer.Argument(
        ...,
        help="Starting URLs for website crawling",
        metavar="URLs"
    ),
    depth: int = typer.Option(
        3,
        "--depth", "-d",
        help=_("cli.option_depth"),
        min=1,
        max=10
    ),
    threads: int = typer.Option(
        10,
        "--threads", "-t",
        help=_("cli.option_threads"), 
        min=1,
        max=50
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help=_("cli.option_output"),
        metavar="FILE"
    ),
):
    """Crawl entire website for XSS vulnerabilities"""
    
    console = Console()
    logger = Logger("cli.crawl")
    
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
        
        # Statistics
        stats = {
            _("URLss discovered"): len(crawl_result.discovered_urls),
            _("Forms found"): len(crawl_result.forms),
            _("Parameters discovered"): len(crawl_result.potential_parameters),
            _("Crawl duration"): f"{crawl_duration:.1f} sec",
        }
        
        logger.print_stats(stats)
        
        # Save results if requested
        if output:
            console.print(f"Saving crawl results: {output}")
            import json
            crawl_data = {
                "target_url": normalized_url,
                "discovered_urls": list(crawl_result.discovered_urls),
                "forms": [{"action": str(f), "method": "GET"} for f in crawl_result.forms],
                "parameters": list(crawl_result.potential_parameters),
                "crawl_duration": crawl_duration,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            with open(output if output.endswith('.json') else f"{output}.json", 'w') as f:
                json.dump(crawl_data, f, indent=2)
            console.print(f"📄 " + _("Crawl results saved: {filepath}").format(filepath=output))
        
        console.print(f"\n[green]Crawl successful: {len(crawl_result.discovered_urls)} URLs discovered[/green]")
            
    except KeyboardInterrupt:
        console.print("\nCrawl interrupted by user")
        raise typer.Exit(130)
        
    except Exception as e:
        logger.error(f"Crawl error: {str(e)}")
        raise typer.Exit(1)


# Create typer app for this command
app = typer.Typer()
app.command()(crawl_command)
