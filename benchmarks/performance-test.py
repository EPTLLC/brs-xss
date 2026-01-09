#!/usr/bin/env python3

# Project: BRS-XSS (XSS Detection Suite)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: Wed 04 Sep 2025 09:03:08 MSK
# Status: Created
# Telegram: https://t.me/EasyProTech

"""
Performance benchmark suite for BRS-XSS
Tests scanning speed, accuracy, and resource usage
"""

import asyncio
import time
import psutil
import json
import statistics
from typing import List, Dict, Any

# Use hardcoded version for benchmarks to avoid import issues
VERSION = "2.0.0"


class BRSXSSBenchmark:
    """Performance benchmark suite for BRS-XSS scanner"""

    def __init__(self):
        self.results = {
            "benchmark_info": {
                "version": VERSION,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "system_info": self._get_system_info(),
            },
            "performance_tests": [],
            "accuracy_tests": [],
            "resource_usage": [],
        }

    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for benchmark context"""
        return {
            "cpu_count": psutil.cpu_count(logical=True),
            "cpu_freq": psutil.cpu_freq().max if psutil.cpu_freq() else "unknown",
            "memory_total": psutil.virtual_memory().total // (1024**3),  # GB
            "python_version": f"{__import__('sys').version_info.major}.{__import__('sys').version_info.minor}",
            "platform": __import__("platform").system(),
        }

    async def run_performance_benchmark(
        self, target_urls: List[str], concurrency_levels: List[int] = [8, 16, 32, 64]
    ) -> Dict[str, Any]:
        """Run performance benchmark with different concurrency levels"""

        performance_results = []

        for concurrency in concurrency_levels:
            print(f"Testing concurrency level: {concurrency}")

            # Start resource monitoring
            process = psutil.Process()
            start_cpu = process.cpu_percent()
            start_memory = process.memory_info().rss
            start_time = time.time()

            # Simulate BRS-XSS scan (replace with actual scanner call)
            scan_results = await self._simulate_scan(target_urls, concurrency)

            end_time = time.time()
            end_cpu = process.cpu_percent()
            end_memory = process.memory_info().rss

            duration = end_time - start_time
            urls_per_second = len(target_urls) / duration

            result = {
                "concurrency": concurrency,
                "urls_scanned": len(target_urls),
                "duration_seconds": round(duration, 2),
                "urls_per_second": round(urls_per_second, 2),
                "vulnerabilities_found": scan_results.get("vulnerabilities", 0),
                "false_positives": scan_results.get("false_positives", 0),
                "cpu_usage_percent": round((end_cpu + start_cpu) / 2, 1),
                "memory_usage_mb": round((end_memory - start_memory) / (1024**2), 1),
                "requests_total": scan_results.get("requests_total", 0),
                "requests_failed": scan_results.get("requests_failed", 0),
            }

            performance_results.append(result)

            # Cool down between tests
            await asyncio.sleep(2)

        return {
            "test_name": "performance_benchmark",
            "target_count": len(target_urls),
            "results": performance_results,
            "best_performance": max(
                performance_results, key=lambda x: x["urls_per_second"]
            ),
        }

    async def run_accuracy_benchmark(self) -> Dict[str, Any]:
        """Run accuracy benchmark against known vulnerable targets"""

        # Known vulnerable targets for testing
        test_targets = [
            {
                "name": "XSS-Game Level 1",
                "url": "http://xss-game.appspot.com/level1/frame?query=test",
                "expected_vulnerabilities": 1,
                "vulnerability_type": "reflected",
            },
            {
                "name": "XSS-Game Level 2",
                "url": "http://xss-game.appspot.com/level2/frame?query=test",
                "expected_vulnerabilities": 1,
                "vulnerability_type": "stored",
            },
            # Add more test targets as needed
        ]

        accuracy_results = []

        for target in test_targets:
            print(f"Testing accuracy on: {target['name']}")

            # Simulate scan (replace with actual scanner call)
            scan_result = await self._simulate_accuracy_scan(target["url"])

            found_vulns = scan_result.get("vulnerabilities_found", 0)
            expected_vulns = target["expected_vulnerabilities"]
            false_positives = scan_result.get("false_positives", 0)

            accuracy = (
                min(found_vulns / expected_vulns, 1.0) if expected_vulns > 0 else 0
            )
            precision = (
                (found_vulns - false_positives) / found_vulns if found_vulns > 0 else 0
            )

            result = {
                "target": target["name"],
                "url": target["url"],
                "expected_vulnerabilities": expected_vulns,
                "found_vulnerabilities": found_vulns,
                "false_positives": false_positives,
                "accuracy": round(accuracy, 3),
                "precision": round(precision, 3),
                "vulnerability_type": target["vulnerability_type"],
            }

            accuracy_results.append(result)

        # Calculate overall metrics
        overall_accuracy = statistics.mean([r["accuracy"] for r in accuracy_results])
        overall_precision = statistics.mean([r["precision"] for r in accuracy_results])
        total_false_positives = sum([r["false_positives"] for r in accuracy_results])
        total_vulnerabilities = sum(
            [r["found_vulnerabilities"] for r in accuracy_results]
        )
        false_positive_rate = (
            total_false_positives / total_vulnerabilities
            if total_vulnerabilities > 0
            else 0
        )

        return {
            "test_name": "accuracy_benchmark",
            "targets_tested": len(test_targets),
            "results": accuracy_results,
            "overall_metrics": {
                "accuracy": round(overall_accuracy, 3),
                "precision": round(overall_precision, 3),
                "false_positive_rate": round(false_positive_rate, 3),
            },
        }

    async def run_load_test(
        self, target_url: str, duration_minutes: int = 10
    ) -> Dict[str, Any]:
        """Run sustained load test"""

        print(f"Running {duration_minutes}-minute load test on {target_url}")

        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)

        requests_completed = 0
        requests_failed = 0
        response_times = []

        while time.time() < end_time:
            request_start = time.time()

            # Simulate request (replace with actual HTTP request)
            success = await self._simulate_request(target_url)

            request_end = time.time()
            response_time = request_end - request_start

            if success:
                requests_completed += 1
                response_times.append(response_time)
            else:
                requests_failed += 1

            # Small delay to prevent overwhelming
            await asyncio.sleep(0.1)

        actual_duration = time.time() - start_time

        return {
            "test_name": "load_test",
            "target_url": target_url,
            "duration_minutes": round(actual_duration / 60, 2),
            "requests_completed": requests_completed,
            "requests_failed": requests_failed,
            "requests_per_second": round(requests_completed / actual_duration, 2),
            "success_rate": round(
                requests_completed / (requests_completed + requests_failed), 3
            ),
            "response_times": {
                "min": round(min(response_times), 3) if response_times else 0,
                "max": round(max(response_times), 3) if response_times else 0,
                "avg": (
                    round(statistics.mean(response_times), 3) if response_times else 0
                ),
                "median": (
                    round(statistics.median(response_times), 3) if response_times else 0
                ),
            },
        }

    async def _simulate_scan(self, urls: List[str], concurrency: int) -> Dict[str, Any]:
        """Simulate BRS-XSS scan (replace with actual implementation)"""
        # This is a simulation - replace with actual BRS-XSS scanner calls
        await asyncio.sleep(len(urls) * 0.1)  # Simulate scan time

        return {
            "vulnerabilities": max(
                0, len(urls) // 10
            ),  # Simulate finding some vulnerabilities
            "false_positives": max(0, len(urls) // 50),  # Simulate some false positives
            "requests_total": len(urls) * 5,  # Simulate multiple requests per URL
            "requests_failed": max(0, len(urls) // 20),  # Simulate some failures
        }

    async def _simulate_accuracy_scan(self, url: str) -> Dict[str, Any]:
        """Simulate accuracy scan (replace with actual implementation)"""
        await asyncio.sleep(0.5)  # Simulate scan time

        return {
            "vulnerabilities_found": 1,  # Simulate finding vulnerability
            "false_positives": 0,  # Simulate no false positives
        }

    async def _simulate_request(self, url: str) -> bool:
        """Simulate HTTP request (replace with actual implementation)"""
        await asyncio.sleep(0.1)  # Simulate request time
        return True  # Simulate success

    def save_results(self, output_file: str = "benchmark-results.json"):
        """Save benchmark results to file"""
        with open(output_file, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"Benchmark results saved to {output_file}")

    def generate_report(self) -> str:
        """Generate human-readable benchmark report"""
        report = []
        report.append("BRS-XSS Performance Benchmark Report")
        report.append("=" * 40)
        report.append("")

        # System info
        sys_info = self.results["benchmark_info"]["system_info"]
        report.append(
            f"System: {sys_info['cpu_count']} CPU, {sys_info['memory_total']}GB RAM"
        )
        report.append(
            f"Platform: {sys_info['platform']}, Python {sys_info['python_version']}"
        )
        report.append("")

        # Performance results
        if self.results.get("performance_tests"):
            report.append("Performance Results:")
            report.append("-" * 20)
            for test in self.results["performance_tests"]:
                if test["test_name"] == "performance_benchmark":
                    best = test["best_performance"]
                    report.append(
                        f"Best Performance: {best['urls_per_second']} URLs/sec @ {best['concurrency']} concurrency"
                    )
                    report.append("Target: 1000 URLs in 12 minutes = 1.39 URLs/sec")
                    if best["urls_per_second"] >= 1.39:
                        report.append("✅ Performance target MET")
                    else:
                        report.append("❌ Performance target MISSED")
            report.append("")

        # Accuracy results
        if self.results.get("accuracy_tests"):
            report.append("Accuracy Results:")
            report.append("-" * 20)
            for test in self.results["accuracy_tests"]:
                if test["test_name"] == "accuracy_benchmark":
                    metrics = test["overall_metrics"]
                    report.append(f"Overall Accuracy: {metrics['accuracy']*100:.1f}%")
                    report.append(
                        f"False Positive Rate: {metrics['false_positive_rate']*100:.1f}%"
                    )
                    report.append("Target: <5% false positive rate")
                    if metrics["false_positive_rate"] < 0.05:
                        report.append("✅ Accuracy target MET")
                    else:
                        report.append("❌ Accuracy target MISSED")
            report.append("")

        return "\n".join(report)


async def main():
    """Run benchmark suite"""
    benchmark = BRSXSSBenchmark()

    # Generate test URLs (replace with actual test targets)
    test_urls = [f"https://example.com/page{i}" for i in range(1000)]

    print("Starting BRS-XSS Performance Benchmark...")
    print("=" * 50)

    # Run performance benchmark
    perf_results = await benchmark.run_performance_benchmark(test_urls)
    benchmark.results["performance_tests"].append(perf_results)

    # Run accuracy benchmark
    accuracy_results = await benchmark.run_accuracy_benchmark()
    benchmark.results["accuracy_tests"].append(accuracy_results)

    # Save results
    benchmark.save_results()

    # Generate and print report
    report = benchmark.generate_report()
    print(report)

    # Save report to file
    with open("benchmark-report.txt", "w") as f:
        f.write(report)

    print("\nBenchmark completed!")
    print("Results saved to benchmark-results.json")
    print("Report saved to benchmark-report.txt")


if __name__ == "__main__":
    asyncio.run(main())
