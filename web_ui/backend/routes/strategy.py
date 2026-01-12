#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Mon 12 Jan 2026 UTC
Status: Updated - Full CRUD, export/import, A/B testing
Telegram: https://t.me/EasyProTech

API routes for PTT strategy management.
"""

from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from typing import Optional, Any
from pydantic import BaseModel
import json

from ..storage import get_storage

router = APIRouter(prefix="/api/strategy", tags=["strategy"])


class StrategyTreeResponse(BaseModel):
    """Strategy tree response"""
    id: str
    name: str
    description: Optional[str] = None
    version: str = "1.0"
    author: Optional[str] = None
    tags: list[str] = []
    total_uses: int = 0
    total_successes: int = 0
    success_rate: float = 0.0
    is_default: bool = False
    is_active: bool = False
    root: Optional[dict[str, Any]] = None
    tree_data: Optional[dict[str, Any]] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class StrategyTreeCreate(BaseModel):
    """Create strategy tree request"""
    name: str
    description: Optional[str] = None
    version: str = "1.0"
    author: Optional[str] = None
    tags: list[str] = []
    tree_data: dict[str, Any]


class StrategyTreeUpdate(BaseModel):
    """Update strategy tree request"""
    name: Optional[str] = None
    description: Optional[str] = None
    version: Optional[str] = None
    tags: Optional[list[str]] = None
    tree_data: Optional[dict[str, Any]] = None


class StrategyNodeCreate(BaseModel):
    """Create strategy node request"""
    type: str
    name: str
    description: Optional[str] = None
    config: dict[str, Any] = {}
    condition: Optional[str] = None
    priority: int = 0


class RuleResponse(BaseModel):
    """Switching rule response"""
    id: str
    name: str
    description: Optional[str] = None
    rule_type: str
    priority: int = 0
    enabled: bool = True
    conditions: dict[str, Any] = {}
    actions: list[dict[str, Any]] = []


class ABTestCreate(BaseModel):
    """Create A/B test request"""
    name: str
    description: Optional[str] = None
    strategy_a_id: str
    strategy_b_id: str
    target_scans: int = 10


class ABTestResponse(BaseModel):
    """A/B test response"""
    id: str
    name: str
    description: Optional[str] = None
    strategy_a_id: str
    strategy_b_id: str
    strategy_a_name: Optional[str] = None
    strategy_b_name: Optional[str] = None
    status: str
    target_scans: int
    completed_scans_a: int
    completed_scans_b: int
    results_a: dict[str, Any] = {}
    results_b: dict[str, Any] = {}
    winner: Optional[str] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None


@router.get("/tree", response_model=StrategyTreeResponse)
async def get_default_tree():
    """Get the default strategy tree"""
    from brsxss.strategy import create_default_strategy
    
    tree = create_default_strategy()
    return StrategyTreeResponse(**tree.to_dict())


@router.get("/rules", response_model=list[RuleResponse])
async def get_default_rules():
    """Get default switching rules"""
    from brsxss.strategy.rules import get_default_rules
    
    rules = get_default_rules()
    return [RuleResponse(**r.to_dict()) for r in rules]


@router.get("/node-types")
async def get_node_types():
    """Get available node types"""
    from brsxss.strategy.tree import NodeType
    
    return {
        "types": [
            {"id": t.value, "name": t.name, "description": _get_node_type_desc(t)}
            for t in NodeType
        ]
    }


def _get_node_type_desc(node_type) -> str:
    """Get description for node type"""
    from brsxss.strategy.tree import NodeType
    
    descriptions = {
        NodeType.ROOT: "Root node of the strategy tree",
        NodeType.CONTEXT: "Injection context (HTML, JS, URL, etc.)",
        NodeType.PAYLOAD: "Specific XSS payload to test",
        NodeType.ENCODING: "Encoding strategy (URL, HTML entity, etc.)",
        NodeType.WAF_BYPASS: "WAF evasion technique",
        NodeType.MUTATION: "Payload mutation strategy",
        NodeType.CONDITION: "Conditional branch based on scan state",
        NodeType.SUCCESS: "Marks successful attack path",
        NodeType.FAILURE: "Marks failed attack path",
    }
    return descriptions.get(node_type, "")


@router.get("/rule-types")
async def get_rule_types():
    """Get available rule types"""
    from brsxss.strategy.rules import RuleType
    
    return {
        "types": [
            {"id": t.value, "name": t.name}
            for t in RuleType
        ]
    }


@router.post("/simulate")
async def simulate_strategy(
    context_type: str = "html",
    waf_detected: bool = False,
    waf_name: Optional[str] = None,
    max_actions: int = 10,
):
    """
    Simulate strategy execution and return planned actions.
    
    This is useful for visualizing what the strategy would do
    without actually running a scan.
    """
    from brsxss.strategy import StrategyEngine
    
    engine = StrategyEngine()
    engine.initialize(
        url="https://example.com/test",
        parameter="q",
        context_type=context_type,
        waf_detected=waf_detected,
        waf_name=waf_name,
    )
    
    actions = []
    for i, action in enumerate(engine.generate_actions()):
        if i >= max_actions:
            break
        
        actions.append({
            "step": i + 1,
            "action_type": action.action_type,
            "payload": action.payload,
            "encoding": action.encoding,
            "context": action.context,
            "node_id": action.node_id,
            "metadata": action.metadata,
        })
        
        # Simulate failure for demo (in real use, scanner provides results)
        engine.record_result(action, success=False)
    
    return {
        "actions": actions,
        "statistics": engine.get_statistics(),
    }


@router.get("/contexts")
async def get_contexts():
    """Get available injection contexts"""
    return {
        "contexts": [
            {
                "id": "html",
                "name": "HTML Body",
                "description": "Payload reflected in HTML body content",
                "example": "<div>USER_INPUT</div>",
            },
            {
                "id": "javascript",
                "name": "JavaScript",
                "description": "Payload reflected in JavaScript code",
                "example": "var x = 'USER_INPUT';",
            },
            {
                "id": "attribute",
                "name": "HTML Attribute",
                "description": "Payload reflected in HTML attribute value",
                "example": '<input value="USER_INPUT">',
            },
            {
                "id": "url",
                "name": "URL/href",
                "description": "Payload reflected in URL or href attribute",
                "example": '<a href="USER_INPUT">',
            },
            {
                "id": "css",
                "name": "CSS",
                "description": "Payload reflected in CSS style",
                "example": "background: url(USER_INPUT);",
            },
        ]
    }


@router.get("/encodings")
async def get_encodings():
    """Get available encoding strategies"""
    return {
        "encodings": [
            {
                "id": "url",
                "name": "URL Encoding",
                "description": "Percent-encode special characters",
                "example": "%3Cscript%3E",
            },
            {
                "id": "html_entity",
                "name": "HTML Entity",
                "description": "Use HTML entities for characters",
                "example": "&lt;script&gt;",
            },
            {
                "id": "unicode",
                "name": "Unicode",
                "description": "Use Unicode escape sequences",
                "example": "\\u003cscript\\u003e",
            },
            {
                "id": "base64",
                "name": "Base64",
                "description": "Base64 encode payload",
                "example": "PHNjcmlwdD4=",
            },
            {
                "id": "double",
                "name": "Double Encoding",
                "description": "Apply encoding twice",
                "example": "%253Cscript%253E",
            },
        ]
    }


class ScanStrategyPathResponse(BaseModel):
    """Response model for scan strategy path"""
    id: str
    scan_id: str
    strategy_tree_id: str
    initial_context: str
    waf_detected: bool
    waf_name: Optional[str] = None
    actions: list[dict[str, Any]]
    visited_nodes: list[str]
    node_statuses: dict[str, str]
    pivots: list[dict[str, Any]]
    statistics: dict[str, Any]
    created_at: str


@router.get("/scan/{scan_id}", response_model=ScanStrategyPathResponse)
async def get_scan_strategy_path(scan_id: str):
    """
    Get the strategy execution path for a specific scan.
    
    This shows exactly which nodes were visited, which payloads were tested,
    where pivots occurred, and the final outcome.
    """
    storage = get_storage()
    
    # First check if scan exists
    scan = storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    # Get strategy path
    path = storage.get_scan_strategy_path(scan_id)
    if not path:
        raise HTTPException(
            status_code=404, 
            detail=f"Strategy path not found for scan {scan_id}. This scan may have been run before strategy tracking was enabled."
        )
    
    return ScanStrategyPathResponse(**path)


@router.get("/scan/{scan_id}/exists")
async def check_scan_strategy_exists(scan_id: str):
    """
    Check if strategy path exists for a scan.
    Useful for UI to determine whether to show strategy visualization.
    """
    storage = get_storage()
    
    # Check if scan exists
    scan = storage.get_scan(scan_id)
    if not scan:
        return {"exists": False, "reason": "scan_not_found"}
    
    # Check if strategy path exists
    path = storage.get_scan_strategy_path(scan_id)
    if not path:
        return {"exists": False, "reason": "no_strategy_data"}
    
    return {
        "exists": True,
        "scan_id": scan_id,
        "actions_count": len(path.get("actions", [])),
        "visited_nodes_count": len(path.get("visited_nodes", [])),
        "pivots_count": len(path.get("pivots", [])),
    }


@router.get("/scan/{scan_id}/summary")
async def get_scan_strategy_summary(scan_id: str):
    """
    Get a summary of strategy execution for a scan.
    Lighter than full path - good for list views.
    """
    storage = get_storage()
    
    path = storage.get_scan_strategy_path(scan_id)
    if not path:
        raise HTTPException(status_code=404, detail=f"Strategy path not found for scan {scan_id}")
    
    stats = path.get("statistics", {})
    
    return {
        "scan_id": scan_id,
        "initial_context": path.get("initial_context"),
        "waf_detected": path.get("waf_detected"),
        "waf_name": path.get("waf_name"),
        "total_actions": stats.get("total_actions", 0),
        "visited_nodes": stats.get("visited_nodes", 0),
        "success_count": stats.get("success_count", 0),
        "failed_count": stats.get("failed_count", 0),
        "pivot_count": stats.get("pivot_count", 0),
    }


# ============ Custom Strategy Trees CRUD ============

@router.get("/trees", response_model=list[StrategyTreeResponse])
async def list_strategy_trees(user_id: Optional[str] = None):
    """Get all strategy trees (custom + default)"""
    storage = get_storage()
    trees = storage.get_strategy_trees(user_id=user_id)
    return [StrategyTreeResponse(**t) for t in trees]


@router.get("/trees/{tree_id}", response_model=StrategyTreeResponse)
async def get_strategy_tree(tree_id: str):
    """Get a specific strategy tree"""
    storage = get_storage()
    tree = storage.get_strategy_tree(tree_id)
    if not tree:
        raise HTTPException(status_code=404, detail=f"Strategy tree {tree_id} not found")
    return StrategyTreeResponse(**tree)


@router.post("/trees", response_model=StrategyTreeResponse)
async def create_strategy_tree(data: StrategyTreeCreate, user_id: Optional[str] = None):
    """Create a new custom strategy tree"""
    storage = get_storage()
    
    tree_id = storage.create_strategy_tree(
        name=data.name,
        tree_data=data.tree_data,
        user_id=user_id,
        description=data.description,
        version=data.version,
        author=data.author,
        tags=data.tags,
    )
    
    tree = storage.get_strategy_tree(tree_id)
    return StrategyTreeResponse(**tree)


@router.put("/trees/{tree_id}", response_model=StrategyTreeResponse)
async def update_strategy_tree(tree_id: str, data: StrategyTreeUpdate):
    """Update a custom strategy tree"""
    storage = get_storage()
    
    existing = storage.get_strategy_tree(tree_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Strategy tree {tree_id} not found")
    
    if existing.get("is_default"):
        raise HTTPException(status_code=403, detail="Cannot modify default strategy trees")
    
    updated = storage.update_strategy_tree(
        tree_id=tree_id,
        name=data.name,
        description=data.description,
        tree_data=data.tree_data,
        version=data.version,
        tags=data.tags,
    )
    
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update strategy tree")
    
    tree = storage.get_strategy_tree(tree_id)
    return StrategyTreeResponse(**tree)


@router.delete("/trees/{tree_id}")
async def delete_strategy_tree(tree_id: str, user_id: Optional[str] = None):
    """Delete a custom strategy tree"""
    storage = get_storage()
    
    existing = storage.get_strategy_tree(tree_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Strategy tree {tree_id} not found")
    
    if existing.get("is_default"):
        raise HTTPException(status_code=403, detail="Cannot delete default strategy trees")
    
    deleted = storage.delete_strategy_tree(tree_id, user_id)
    if not deleted:
        raise HTTPException(status_code=500, detail="Failed to delete strategy tree")
    
    return {"deleted": True, "id": tree_id}


@router.post("/trees/{tree_id}/clone", response_model=StrategyTreeResponse)
async def clone_strategy_tree(tree_id: str, new_name: str, user_id: Optional[str] = None):
    """Clone an existing strategy tree"""
    storage = get_storage()
    
    new_id = storage.clone_strategy_tree(tree_id, new_name, user_id)
    if not new_id:
        raise HTTPException(status_code=404, detail=f"Source strategy tree {tree_id} not found")
    
    tree = storage.get_strategy_tree(new_id)
    return StrategyTreeResponse(**tree)


@router.post("/trees/{tree_id}/activate")
async def activate_strategy_tree(tree_id: str, user_id: Optional[str] = None):
    """Set a strategy tree as active for scanning"""
    storage = get_storage()
    
    existing = storage.get_strategy_tree(tree_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Strategy tree {tree_id} not found")
    
    storage.set_active_strategy_tree(tree_id, user_id)
    return {"activated": True, "id": tree_id}


@router.get("/trees/active/current", response_model=Optional[StrategyTreeResponse])
async def get_active_strategy_tree(user_id: Optional[str] = None):
    """Get currently active strategy tree"""
    storage = get_storage()
    tree = storage.get_active_strategy_tree(user_id)
    if tree:
        return StrategyTreeResponse(**tree)
    return None


# ============ Export/Import ============

@router.get("/trees/{tree_id}/export")
async def export_strategy_tree(tree_id: str):
    """Export a strategy tree as JSON"""
    storage = get_storage()
    
    tree = storage.get_strategy_tree(tree_id)
    if not tree:
        raise HTTPException(status_code=404, detail=f"Strategy tree {tree_id} not found")
    
    export_data = {
        "format": "brs-xss-strategy",
        "version": "1.0",
        "exported_at": __import__("datetime").datetime.utcnow().isoformat(),
        "strategy": {
            "name": tree["name"],
            "description": tree["description"],
            "version": tree["version"],
            "author": tree["author"],
            "tags": tree["tags"],
            "tree_data": tree["tree_data"],
        }
    }
    
    return JSONResponse(
        content=export_data,
        headers={
            "Content-Disposition": f'attachment; filename="strategy_{tree_id}.json"'
        }
    )


@router.post("/trees/import", response_model=StrategyTreeResponse)
async def import_strategy_tree(
    file: UploadFile = File(...),
    user_id: Optional[str] = None,
):
    """Import a strategy tree from JSON file"""
    storage = get_storage()
    
    try:
        content = await file.read()
        data = json.loads(content.decode("utf-8"))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")
    
    # Validate format
    if data.get("format") != "brs-xss-strategy":
        raise HTTPException(status_code=400, detail="Invalid strategy file format")
    
    strategy = data.get("strategy", {})
    if not strategy.get("name") or not strategy.get("tree_data"):
        raise HTTPException(status_code=400, detail="Missing required fields: name, tree_data")
    
    tree_id = storage.create_strategy_tree(
        name=f"{strategy['name']} (imported)",
        tree_data=strategy["tree_data"],
        user_id=user_id,
        description=strategy.get("description"),
        version=strategy.get("version", "1.0"),
        author=strategy.get("author"),
        tags=strategy.get("tags", []),
    )
    
    tree = storage.get_strategy_tree(tree_id)
    return StrategyTreeResponse(**tree)


@router.post("/trees/import/json", response_model=StrategyTreeResponse)
async def import_strategy_tree_json(
    data: dict[str, Any],
    user_id: Optional[str] = None,
):
    """Import a strategy tree from JSON body (alternative to file upload)"""
    storage = get_storage()
    
    # Validate format
    if data.get("format") != "brs-xss-strategy":
        raise HTTPException(status_code=400, detail="Invalid strategy file format")
    
    strategy = data.get("strategy", {})
    if not strategy.get("name") or not strategy.get("tree_data"):
        raise HTTPException(status_code=400, detail="Missing required fields: name, tree_data")
    
    tree_id = storage.create_strategy_tree(
        name=f"{strategy['name']} (imported)",
        tree_data=strategy["tree_data"],
        user_id=user_id,
        description=strategy.get("description"),
        version=strategy.get("version", "1.0"),
        author=strategy.get("author"),
        tags=strategy.get("tags", []),
    )
    
    tree = storage.get_strategy_tree(tree_id)
    return StrategyTreeResponse(**tree)


# ============ A/B Testing ============

@router.get("/ab-tests", response_model=list[ABTestResponse])
async def list_ab_tests(user_id: Optional[str] = None, status: Optional[str] = None):
    """Get all A/B tests"""
    storage = get_storage()
    tests = storage.get_ab_tests(user_id=user_id, status=status)
    return [ABTestResponse(**t) for t in tests]


@router.get("/ab-tests/{test_id}", response_model=ABTestResponse)
async def get_ab_test(test_id: str):
    """Get a specific A/B test"""
    storage = get_storage()
    test = storage.get_ab_test(test_id)
    if not test:
        raise HTTPException(status_code=404, detail=f"A/B test {test_id} not found")
    return ABTestResponse(**test)


@router.post("/ab-tests", response_model=ABTestResponse)
async def create_ab_test(data: ABTestCreate, user_id: Optional[str] = None):
    """Create a new A/B test"""
    storage = get_storage()
    
    # Validate strategies exist
    strategy_a = storage.get_strategy_tree(data.strategy_a_id)
    if not strategy_a:
        raise HTTPException(status_code=404, detail=f"Strategy A ({data.strategy_a_id}) not found")
    
    strategy_b = storage.get_strategy_tree(data.strategy_b_id)
    if not strategy_b:
        raise HTTPException(status_code=404, detail=f"Strategy B ({data.strategy_b_id}) not found")
    
    if data.strategy_a_id == data.strategy_b_id:
        raise HTTPException(status_code=400, detail="Strategy A and B must be different")
    
    test_id = storage.create_ab_test(
        name=data.name,
        strategy_a_id=data.strategy_a_id,
        strategy_b_id=data.strategy_b_id,
        user_id=user_id,
        description=data.description,
        target_scans=data.target_scans,
    )
    
    test = storage.get_ab_test(test_id)
    return ABTestResponse(**test)


@router.post("/ab-tests/{test_id}/start")
async def start_ab_test(test_id: str):
    """Start an A/B test"""
    storage = get_storage()
    
    test = storage.get_ab_test(test_id)
    if not test:
        raise HTTPException(status_code=404, detail=f"A/B test {test_id} not found")
    
    if test["status"] != "pending":
        raise HTTPException(status_code=400, detail=f"Test is already {test['status']}")
    
    started = storage.start_ab_test(test_id)
    if not started:
        raise HTTPException(status_code=500, detail="Failed to start test")
    
    return {"started": True, "id": test_id}


@router.post("/ab-tests/{test_id}/cancel")
async def cancel_ab_test(test_id: str):
    """Cancel an A/B test"""
    storage = get_storage()
    
    cancelled = storage.cancel_ab_test(test_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail=f"A/B test {test_id} not found or not running")
    
    return {"cancelled": True, "id": test_id}


@router.delete("/ab-tests/{test_id}")
async def delete_ab_test(test_id: str, user_id: Optional[str] = None):
    """Delete an A/B test"""
    storage = get_storage()
    
    deleted = storage.delete_ab_test(test_id, user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"A/B test {test_id} not found")
    
    return {"deleted": True, "id": test_id}


@router.get("/ab-tests/running/current", response_model=Optional[ABTestResponse])
async def get_running_ab_test(user_id: Optional[str] = None):
    """Get currently running A/B test"""
    storage = get_storage()
    test = storage.get_running_ab_test(user_id)
    if test:
        return ABTestResponse(**test)
    return None


@router.get("/ab-tests/{test_id}/comparison")
async def get_ab_test_comparison(test_id: str):
    """Get detailed comparison of A/B test results"""
    storage = get_storage()
    
    test = storage.get_ab_test(test_id)
    if not test:
        raise HTTPException(status_code=404, detail=f"A/B test {test_id} not found")
    
    results_a = test.get("results_a", {})
    results_b = test.get("results_b", {})
    
    # Calculate metrics
    scans_a = test.get("completed_scans_a", 0)
    scans_b = test.get("completed_scans_b", 0)
    
    avg_vulns_a = results_a.get("vulns", 0) / max(scans_a, 1)
    avg_vulns_b = results_b.get("vulns", 0) / max(scans_b, 1)
    
    success_rate_a = results_a.get("success", 0) / max(scans_a, 1)
    success_rate_b = results_b.get("success", 0) / max(scans_b, 1)
    
    avg_duration_a = results_a.get("duration", 0) / max(scans_a, 1)
    avg_duration_b = results_b.get("duration", 0) / max(scans_b, 1)
    
    return {
        "test_id": test_id,
        "status": test["status"],
        "strategy_a": {
            "id": test["strategy_a_id"],
            "name": test.get("strategy_a_name"),
            "scans_completed": scans_a,
            "total_vulns": results_a.get("vulns", 0),
            "avg_vulns_per_scan": round(avg_vulns_a, 2),
            "success_rate": round(success_rate_a * 100, 1),
            "avg_duration": round(avg_duration_a, 2),
        },
        "strategy_b": {
            "id": test["strategy_b_id"],
            "name": test.get("strategy_b_name"),
            "scans_completed": scans_b,
            "total_vulns": results_b.get("vulns", 0),
            "avg_vulns_per_scan": round(avg_vulns_b, 2),
            "success_rate": round(success_rate_b * 100, 1),
            "avg_duration": round(avg_duration_b, 2),
        },
        "winner": test.get("winner"),
        "progress": {
            "target": test.get("target_scans", 10),
            "completed_a": scans_a,
            "completed_b": scans_b,
            "percent_complete": round(
                (min(scans_a, test.get("target_scans", 10)) + 
                 min(scans_b, test.get("target_scans", 10))) / 
                (test.get("target_scans", 10) * 2) * 100, 1
            ),
        }
    }


# ============ Default Strategy Initialization ============

@router.post("/init-defaults")
async def init_default_strategies():
    """Initialize default strategy trees in database"""
    storage = get_storage()
    
    # Check if defaults already exist
    existing = storage.get_strategy_trees(include_default=True)
    defaults = [t for t in existing if t.get("is_default")]
    
    if defaults:
        return {"initialized": False, "message": "Default strategies already exist", "count": len(defaults)}
    
    # Create default strategy from brsxss.strategy module
    from brsxss.strategy import create_default_strategy
    
    default_tree = create_default_strategy()
    tree_dict = default_tree.to_dict()
    
    tree_id = storage.create_strategy_tree(
        name="Default PTT Strategy",
        tree_data=tree_dict,
        description="Default Pentesting Task Tree strategy with context-aware payload selection",
        version="1.0",
        author="BRS-XSS",
        tags=["default", "ptt", "context-aware"],
        is_default=True,
    )
    
    # Set as active
    storage.set_active_strategy_tree(tree_id)
    
    return {"initialized": True, "id": tree_id}
