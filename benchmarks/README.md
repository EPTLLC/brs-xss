# BRS-XSS v2.1.0 Benchmarks

**Performance and accuracy benchmarks for BRS-XSS scanner**

## Quick Benchmark

```bash
# Run performance test
cd benchmarks/
python performance-test.py

# View results
cat benchmark-report.txt
```

## Performance Targets

### Speed Benchmark
- **Target**: 1000 URLs in 12 minutes (1.39 URLs/sec)
- **Hardware**: 8 vCPU VPS
- **Configuration**: 32 concurrency, 8 RPS limit
- **Status**: ![Benchmark](https://img.shields.io/badge/benchmark-1k%20URLs%20%2F%2012min-brightgreen)

### Accuracy Benchmark  
- **Target**: <5% false positive rate
- **Test Suite**: DVWA, WebGoat, XSS-Game
- **Contexts**: HTML, JavaScript, Attribute, CSS, URI, SVG
- **Status**: ![Accuracy](https://img.shields.io/badge/accuracy-%3C5%25%20FP-brightgreen)

## Test Environments

### Verified Platforms
| Platform | CPU | RAM | Performance | Status |
|----------|-----|-----|-------------|---------|
| GitHub Actions | 2 vCPU | 7GB | 0.8 URLs/sec | ✅ Pass |
| AWS t3.large | 2 vCPU | 8GB | 1.2 URLs/sec | ✅ Pass |
| DigitalOcean 8vCPU | 8 vCPU | 16GB | 2.1 URLs/sec | ✅ Pass |
| Azure Standard_D4s | 4 vCPU | 16GB | 1.6 URLs/sec | ✅ Pass |

### Docker Performance
```bash
# Test Docker performance
docker run --rm ghcr.io/eptllc/brs-xss:latest \
  python /app/benchmarks/performance-test.py
```

## Benchmark Results

### Latest Results (v1.0.4)
```
BRS-XSS Performance Benchmark Report
========================================

System: 8 CPU, 16GB RAM
Platform: Linux, Python 3.11

Performance Results:
--------------------
Best Performance: 2.1 URLs/sec @ 32 concurrency
Target: 1000 URLs in 12 minutes = 1.39 URLs/sec
✅ Performance target MET

Accuracy Results:
-----------------
Overall Accuracy: 94.2%
False Positive Rate: 3.1%
Target: <5% false positive rate
✅ Accuracy target MET
```

## Running Custom Benchmarks

### Performance Test
```python
import asyncio
from performance_test import BRSXSSBenchmark

async def custom_benchmark():
    benchmark = BRSXSSBenchmark()
    
    # Custom URL list
    urls = ["https://example.com/search?q=test"] * 500
    
    # Run with different concurrency levels
    results = await benchmark.run_performance_benchmark(
        urls, 
        concurrency_levels=[16, 32, 64]
    )
    
    print(f"Best performance: {results['best_performance']['urls_per_second']} URLs/sec")

asyncio.run(custom_benchmark())
```

### Accuracy Test
```python
async def accuracy_test():
    benchmark = BRSXSSBenchmark()
    results = await benchmark.run_accuracy_benchmark()
    
    fp_rate = results['overall_metrics']['false_positive_rate']
    print(f"False positive rate: {fp_rate*100:.1f}%")
```

## Continuous Benchmarking

### GitHub Actions
```yaml
name: Performance Benchmark
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Run Benchmark
      run: |
        pip install -e .
        python benchmarks/performance-test.py
    - name: Upload Results
      uses: actions/upload-artifact@v3
      with:
        name: benchmark-results
        path: benchmark-*.json
```

## Benchmark History

### Version Comparison
| Version | URLs/sec | FP Rate | Memory | Release |
|---------|----------|---------|--------|---------|
| v1.0.4 | 2.1 | 3.1% | 245MB | 2025-09-05 |
| v1.0.3 | 1.4 | 4.8% | 180MB | 2025-08-18 |
| v1.0.0 | 0.9 | 8.2% | 160MB | 2025-08-07 |

### Performance Improvements
- **v1.0.4**: Async HTTP client, connection pooling, payload caching
- **v1.0.3**: Multi-threading, request deduplication
- **v1.0.0**: Sequential processing baseline

## Contributing Benchmarks

### Adding New Tests
1. Create test in `benchmarks/` directory
2. Follow naming convention: `test_<feature>.py`
3. Include performance and accuracy metrics
4. Add documentation to this README

### Test Data
Use these standardized test targets:
- **DVWA**: http://dvwa.local (if available)
- **WebGoat**: http://webgoat.local (if available)  
- **XSS-Game**: http://xss-game.appspot.com
- **Custom**: Create reproducible test environment
