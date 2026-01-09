# Configuration Guide

**Complete configuration reference for BRS-XSS v4.0**

## Configuration Locations

### Web UI Configuration
- `~/.brs-xss/system_profile.json` - Hardware detection cache
- `~/.brs-xss/preferences.json` - Saved settings (performance mode)
- `brsxss_ui.db` - SQLite database (scans, results)

### CLI Configuration
- `config/default.yaml` – repository defaults (always loaded)
- Optional user config (TOML) – load any file by pointing `BRS_XSS_USER_CONFIG_PATH` to it

### Priority Order
1. Web UI runtime settings (when using the UI)
2. CLI arguments (`brs-xss scan ...`)
3. Environment variables (`BRSXSS_*`, `BRS_XSS_*`)
4. User config (only if `BRS_XSS_USER_CONFIG_PATH` is set)
5. System defaults (`config/default.yaml`)

## Performance Modes (Web UI)

The Web UI automatically tunes scanner parameters based on real hardware metrics (CPU threads, frequency, RAM, GPU, NIC speed).

### Mode selection

Open **Settings → Performance Mode** to:
- view the detected hardware profile (CPU, RAM, GPU, NIC);
- pick one of four profiles (Light / Standard / Turbo / Maximum);
- inspect calculated values (threads, max concurrency, requests-per-second, DOM workers, Playwright instances, HTTP pool size).

Profiles summarize as:

| Mode | Recommended use | Notes |
|------|-----------------|-------|
| Light | background/CI | minimal footprint, DOM workers ≥1 |
| Standard | general scans | recommended automatically when ≤16 threads |
| Turbo | beefy workstations | scales with CPU freq and GPU availability |
| Maximum | dedicated servers | uses ~90% of detected capacity, multi-browser DOM |

### Hardware detection & persistence

- **Detect System** triggers `/api/system/detect` and rewrites `~/.brs-xss/system_profile.json`.
- The selected mode is saved to `~/.brs-xss/preferences.json` for subsequent launches.
- API helpers:

```bash
curl http://localhost:8000/api/system/info             # current profile + modes
curl -X POST http://localhost:8000/api/system/detect   # force re-detect
curl -X POST "http://localhost:8000/api/system/mode?mode=turbo"   # persist choice
```

## Generator Configuration

### Core Parameters

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `max_payloads` | int | 500 | 1-100000 | Maximum payloads per context |
| `effectiveness_threshold` | float | 0.65 | 0.0-1.0 | Minimum effectiveness score |
| `include_evasions` | bool | true | - | Enable evasion technique variants |
| `include_waf_specific` | bool | true | - | Enable WAF-specific bypass payloads |
| `include_blind_xss` | bool | false | - | Enable blind XSS payloads (requires webhook) |
| `safe_mode` | bool | true | - | Production-safe mode (disables blind XSS) |

### Performance Parameters

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `seed` | int | 1337 | - | Random seed for deterministic results |
| `max_manager_payloads` | int | 2000 | 0-200000 | Max payloads from comprehensive manager |
| `max_evasion_bases` | int | 10 | 0-1000 | Max base payloads for evasion techniques |
| `evasion_variants_per_tech` | int | 2 | 0-50 | Max variants per evasion technique |
| `waf_bases` | int | 3 | 0-100 | Max base payloads for WAF bypasses |
| `pool_cap` | int | 10000 | 100-200000 | Maximum pool size before filtering |
| `norm_hash` | bool | false | - | Use SHA256 for deduplication (slower) |

### Payload Weights

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `weights.context_specific` | float | 0.92 | 0.0-1.0 | Context-aware payloads weight |
| `weights.context_matrix` | float | 0.90 | 0.0-1.0 | Matrix-based payloads weight |
| `weights.comprehensive` | float | 0.70 | 0.0-1.0 | Comprehensive manager weight |
| `weights.evasion` | float | 0.75 | 0.0-1.0 | Evasion technique weight |

## Configuration Examples

### High-Speed CI/CD
```toml
[generator]
max_payloads = 100
effectiveness_threshold = 0.8
max_manager_payloads = 500
enable_aggressive = false
safe_mode = true
pool_cap = 1000
```

### Comprehensive Pentest
```toml
[generator]
max_payloads = 1000
effectiveness_threshold = 0.5
max_manager_payloads = 5000
enable_aggressive = true
safe_mode = false
include_blind_xss = true
pool_cap = 20000
```

### Memory-Constrained
```toml
[generator]
max_payloads = 50
max_manager_payloads = 1000
max_evasion_bases = 5
evasion_variants_per_tech = 1
pool_cap = 2000
```

### Custom Weights
```toml
[generator]
max_payloads = 200

[generator.weights]
context_specific = 0.95  # Prioritize context-aware payloads
context_matrix = 0.85    # Matrix payloads second priority
comprehensive = 0.60     # Lower priority for comprehensive
evasion = 0.80          # High priority for evasion variants
```

## CLI Configuration

### Safe Mode
```bash
# Enable safe mode (default)
brs-xss scan url --safe-mode

# Note: --no-safe-mode is not available in CLI
# Use environment variable instead:
export BRS_XSS_SAFE_MODE=false
```

### Pool Control
```bash
# Custom pool cap
brs-xss scan url --pool-cap 5000

# High-performance mode
brs-xss scan url --pool-cap 20000 --max-payloads 1000
```

## Validation Rules

All configuration parameters are validated on startup:

- **Range checks**: All numeric values must be within specified ranges
- **Type validation**: Boolean, integer, and float types enforced
- **Logical validation**: Conflicting settings (e.g., `safe_mode=true` + `include_blind_xss=true`) generate warnings
- **Rollback protection**: Invalid config updates restore previous valid configuration

## Environment Variables

Override config via environment variables:

```bash
export BRS_XSS_SAFE_MODE=true
export BRS_XSS_MAX_PAYLOADS=200
export BRS_XSS_POOL_CAP=5000
export BRS_XSS_EFFECTIVENESS_THRESHOLD=0.75

brs-xss scan example.com
```

## Troubleshooting

### Common Issues

**"Invalid config: max_payloads=-1"**
- Solution: Use positive integers only

**"include_blind_xss ignored due to safe_mode"**
- Solution: Set `safe_mode = false` to enable blind XSS

**"Pool size too large"**
- Solution: Reduce `pool_cap` or `max_manager_payloads`

### Debug Configuration

Configuration is loaded from `config/default.yaml` and can be overridden via environment variables.

```bash
# Check current KB configuration
brs-xss kb info

# List available contexts
brs-xss kb list

# Show payload counts
brs-xss payloads count
```
