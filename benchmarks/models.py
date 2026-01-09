#!/usr/bin/env python3

"""
Project: BRS-XSS Benchmark Suite
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Wed 25 Dec 2025 13:00:00 UTC
Status: Created
Telegram: https://t.me/EasyProTech

Data models for benchmark results and history.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
import json
from pathlib import Path


class BenchmarkStatus(Enum):
    """Benchmark execution status"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class VulnerabilityResult:
    """Result for a single vulnerability test"""

    test_id: str
    test_name: str
    expected_vulnerable: bool
    detected_vulnerable: bool
    severity: str = "unknown"
    confidence: float = 0.0
    detection_time_ms: float = 0.0
    payload_used: Optional[str] = None
    context_type: Optional[str] = None
    notes: Optional[str] = None

    @property
    def is_true_positive(self) -> bool:
        return self.expected_vulnerable and self.detected_vulnerable

    @property
    def is_false_positive(self) -> bool:
        return not self.expected_vulnerable and self.detected_vulnerable

    @property
    def is_true_negative(self) -> bool:
        return not self.expected_vulnerable and not self.detected_vulnerable

    @property
    def is_false_negative(self) -> bool:
        return self.expected_vulnerable and not self.detected_vulnerable


@dataclass
class TargetBenchmark:
    """Benchmark results for a specific target"""

    target_name: str
    target_url: str
    target_type: str  # dvwa, webgoat, xss-game, custom
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: BenchmarkStatus = BenchmarkStatus.PENDING
    results: List[VulnerabilityResult] = field(default_factory=list)
    error_message: Optional[str] = None

    @property
    def total_tests(self) -> int:
        return len(self.results)

    @property
    def true_positives(self) -> int:
        return sum(1 for r in self.results if r.is_true_positive)

    @property
    def false_positives(self) -> int:
        return sum(1 for r in self.results if r.is_false_positive)

    @property
    def true_negatives(self) -> int:
        return sum(1 for r in self.results if r.is_true_negative)

    @property
    def false_negatives(self) -> int:
        return sum(1 for r in self.results if r.is_false_negative)

    @property
    def accuracy(self) -> float:
        if not self.results:
            return 0.0
        correct = self.true_positives + self.true_negatives
        return correct / len(self.results)

    @property
    def precision(self) -> float:
        detected = self.true_positives + self.false_positives
        if detected == 0:
            return 0.0
        return self.true_positives / detected

    @property
    def recall(self) -> float:
        actual_vulnerable = self.true_positives + self.false_negatives
        if actual_vulnerable == 0:
            return 0.0
        return self.true_positives / actual_vulnerable

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return 2 * (p * r) / (p + r)

    @property
    def avg_detection_time_ms(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.detection_time_ms for r in self.results) / len(self.results)


@dataclass
class PerformanceMetrics:
    """Performance metrics for a benchmark run"""

    total_urls_scanned: int = 0
    total_payloads_tested: int = 0
    total_time_seconds: float = 0.0
    urls_per_minute: float = 0.0
    payloads_per_second: float = 0.0
    peak_memory_mb: float = 0.0
    avg_response_time_ms: float = 0.0


@dataclass
class BenchmarkResult:
    """Complete benchmark result"""

    benchmark_id: str
    version: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: BenchmarkStatus = BenchmarkStatus.PENDING

    # Target results
    targets: List[TargetBenchmark] = field(default_factory=list)

    # Performance
    performance: PerformanceMetrics = field(default_factory=PerformanceMetrics)

    # Environment
    python_version: str = ""
    os_info: str = ""
    cpu_count: int = 0

    # Notes
    notes: Optional[str] = None

    @property
    def overall_accuracy(self) -> float:
        if not self.targets:
            return 0.0
        return sum(t.accuracy for t in self.targets) / len(self.targets)

    @property
    def overall_precision(self) -> float:
        if not self.targets:
            return 0.0
        return sum(t.precision for t in self.targets) / len(self.targets)

    @property
    def overall_recall(self) -> float:
        if not self.targets:
            return 0.0
        return sum(t.recall for t in self.targets) / len(self.targets)

    @property
    def overall_f1(self) -> float:
        if not self.targets:
            return 0.0
        return sum(t.f1_score for t in self.targets) / len(self.targets)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "benchmark_id": self.benchmark_id,
            "version": self.version,
            "started_at": self.started_at.isoformat(),
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "status": self.status.value,
            "targets": [
                {
                    "target_name": t.target_name,
                    "target_url": t.target_url,
                    "target_type": t.target_type,
                    "started_at": t.started_at.isoformat(),
                    "completed_at": (
                        t.completed_at.isoformat() if t.completed_at else None
                    ),
                    "status": t.status.value,
                    "metrics": {
                        "total_tests": t.total_tests,
                        "true_positives": t.true_positives,
                        "false_positives": t.false_positives,
                        "true_negatives": t.true_negatives,
                        "false_negatives": t.false_negatives,
                        "accuracy": round(t.accuracy, 4),
                        "precision": round(t.precision, 4),
                        "recall": round(t.recall, 4),
                        "f1_score": round(t.f1_score, 4),
                        "avg_detection_time_ms": round(t.avg_detection_time_ms, 2),
                    },
                    "results": [asdict(r) for r in t.results],
                    "error_message": t.error_message,
                }
                for t in self.targets
            ],
            "performance": asdict(self.performance),
            "overall_metrics": {
                "accuracy": round(self.overall_accuracy, 4),
                "precision": round(self.overall_precision, 4),
                "recall": round(self.overall_recall, 4),
                "f1_score": round(self.overall_f1, 4),
            },
            "environment": {
                "python_version": self.python_version,
                "os_info": self.os_info,
                "cpu_count": self.cpu_count,
            },
            "notes": self.notes,
        }

    def save(self, path: str):
        """Save benchmark result to JSON file"""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: str) -> "BenchmarkResult":
        """Load benchmark result from JSON file"""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Reconstruct objects
        result = cls(
            benchmark_id=data["benchmark_id"],
            version=data["version"],
            started_at=datetime.fromisoformat(data["started_at"]),
            completed_at=(
                datetime.fromisoformat(data["completed_at"])
                if data.get("completed_at")
                else None
            ),
            status=BenchmarkStatus(data["status"]),
            python_version=data.get("environment", {}).get("python_version", ""),
            os_info=data.get("environment", {}).get("os_info", ""),
            cpu_count=data.get("environment", {}).get("cpu_count", 0),
            notes=data.get("notes"),
        )

        # Performance
        if "performance" in data:
            result.performance = PerformanceMetrics(**data["performance"])

        # Targets
        for t_data in data.get("targets", []):
            target = TargetBenchmark(
                target_name=t_data["target_name"],
                target_url=t_data["target_url"],
                target_type=t_data["target_type"],
                started_at=datetime.fromisoformat(t_data["started_at"]),
                completed_at=(
                    datetime.fromisoformat(t_data["completed_at"])
                    if t_data.get("completed_at")
                    else None
                ),
                status=BenchmarkStatus(t_data["status"]),
                error_message=t_data.get("error_message"),
            )

            for r_data in t_data.get("results", []):
                target.results.append(VulnerabilityResult(**r_data))

            result.targets.append(target)

        return result


@dataclass
class VersionComparison:
    """Comparison between two benchmark versions"""

    version_a: str
    version_b: str
    result_a: BenchmarkResult
    result_b: BenchmarkResult

    @property
    def accuracy_delta(self) -> float:
        return self.result_b.overall_accuracy - self.result_a.overall_accuracy

    @property
    def precision_delta(self) -> float:
        return self.result_b.overall_precision - self.result_a.overall_precision

    @property
    def recall_delta(self) -> float:
        return self.result_b.overall_recall - self.result_a.overall_recall

    @property
    def f1_delta(self) -> float:
        return self.result_b.overall_f1 - self.result_a.overall_f1

    @property
    def speed_improvement(self) -> float:
        if self.result_a.performance.urls_per_minute == 0:
            return 0.0
        return (
            (
                self.result_b.performance.urls_per_minute
                - self.result_a.performance.urls_per_minute
            )
            / self.result_a.performance.urls_per_minute
        ) * 100

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version_a": self.version_a,
            "version_b": self.version_b,
            "comparison": {
                "accuracy": {
                    "v_a": round(self.result_a.overall_accuracy, 4),
                    "v_b": round(self.result_b.overall_accuracy, 4),
                    "delta": round(self.accuracy_delta, 4),
                    "improved": self.accuracy_delta > 0,
                },
                "precision": {
                    "v_a": round(self.result_a.overall_precision, 4),
                    "v_b": round(self.result_b.overall_precision, 4),
                    "delta": round(self.precision_delta, 4),
                    "improved": self.precision_delta > 0,
                },
                "recall": {
                    "v_a": round(self.result_a.overall_recall, 4),
                    "v_b": round(self.result_b.overall_recall, 4),
                    "delta": round(self.recall_delta, 4),
                    "improved": self.recall_delta > 0,
                },
                "f1_score": {
                    "v_a": round(self.result_a.overall_f1, 4),
                    "v_b": round(self.result_b.overall_f1, 4),
                    "delta": round(self.f1_delta, 4),
                    "improved": self.f1_delta > 0,
                },
                "speed": {
                    "v_a_urls_per_min": round(
                        self.result_a.performance.urls_per_minute, 2
                    ),
                    "v_b_urls_per_min": round(
                        self.result_b.performance.urls_per_minute, 2
                    ),
                    "improvement_percent": round(self.speed_improvement, 2),
                    "improved": self.speed_improvement > 0,
                },
            },
            "summary": self._generate_summary(),
        }

    def _generate_summary(self) -> str:
        improvements = []
        regressions = []

        if self.accuracy_delta > 0.01:
            improvements.append(f"Accuracy +{self.accuracy_delta:.1%}")
        elif self.accuracy_delta < -0.01:
            regressions.append(f"Accuracy {self.accuracy_delta:.1%}")

        if self.precision_delta > 0.01:
            improvements.append(f"Precision +{self.precision_delta:.1%}")
        elif self.precision_delta < -0.01:
            regressions.append(f"Precision {self.precision_delta:.1%}")

        if self.recall_delta > 0.01:
            improvements.append(f"Recall +{self.recall_delta:.1%}")
        elif self.recall_delta < -0.01:
            regressions.append(f"Recall {self.recall_delta:.1%}")

        if self.speed_improvement > 5:
            improvements.append(f"Speed +{self.speed_improvement:.0f}%")
        elif self.speed_improvement < -5:
            regressions.append(f"Speed {self.speed_improvement:.0f}%")

        parts = []
        if improvements:
            parts.append(f"Improvements: {', '.join(improvements)}")
        if regressions:
            parts.append(f"Regressions: {', '.join(regressions)}")

        return "; ".join(parts) if parts else "No significant changes"


class BenchmarkHistory:
    """Manages benchmark history and version comparisons"""

    def __init__(self, history_dir: str = "benchmarks/history"):
        self.history_dir = Path(history_dir)
        self.history_dir.mkdir(parents=True, exist_ok=True)

    def save_result(self, result: BenchmarkResult):
        """Save benchmark result to history"""
        filename = f"{result.version}_{result.benchmark_id}.json"
        result.save(str(self.history_dir / filename))

    def get_results_for_version(self, version: str) -> List[BenchmarkResult]:
        """Get all benchmark results for a version"""
        results = []
        for path in self.history_dir.glob(f"{version}_*.json"):
            results.append(BenchmarkResult.load(str(path)))
        return sorted(results, key=lambda r: r.started_at, reverse=True)

    def get_latest_result(self, version: str) -> Optional[BenchmarkResult]:
        """Get most recent benchmark result for a version"""
        results = self.get_results_for_version(version)
        return results[0] if results else None

    def get_all_versions(self) -> List[str]:
        """Get all versions with benchmark results"""
        versions = set()
        for path in self.history_dir.glob("*.json"):
            version = path.stem.split("_")[0]
            versions.add(version)
        return sorted(versions, reverse=True)

    def compare_versions(
        self, version_a: str, version_b: str
    ) -> Optional[VersionComparison]:
        """Compare two versions"""
        result_a = self.get_latest_result(version_a)
        result_b = self.get_latest_result(version_b)

        if not result_a or not result_b:
            return None

        return VersionComparison(
            version_a=version_a,
            version_b=version_b,
            result_a=result_a,
            result_b=result_b,
        )

    def get_history_summary(self) -> Dict[str, Any]:
        """Get summary of all benchmark history"""
        versions = self.get_all_versions()
        summary = {
            "total_versions": len(versions),
            "versions": [],
        }

        for version in versions:
            results = self.get_results_for_version(version)
            if results:
                latest = results[0]
                summary["versions"].append(
                    {
                        "version": version,
                        "benchmark_count": len(results),
                        "latest_accuracy": round(latest.overall_accuracy, 4),
                        "latest_f1": round(latest.overall_f1, 4),
                        "latest_date": latest.started_at.isoformat(),
                    }
                )

        return summary
