#!/usr/bin/env python3

"""
Project: BRS-XSS Web UI Backend
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: Sat 10 Jan 2026 UTC
Status: New - Workflow management API
Telegram: https://t.me/EasyProTech

API routes for scan workflow management.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Optional, Any
from pydantic import BaseModel

from ..storage import get_storage
from .auth import get_current_user_optional

router = APIRouter(prefix="/api/workflows", tags=["workflows"])


class WorkflowStep(BaseModel):
    """Single workflow step"""
    type: str  # crawl, scan, report
    context: Optional[str] = None
    target: Optional[str] = None
    mode: Optional[str] = None
    depth: Optional[int] = None
    blind: Optional[bool] = None
    format: Optional[str] = None


class WorkflowCreate(BaseModel):
    """Create workflow request"""
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    steps: list[dict[str, Any]]
    settings: Optional[dict[str, Any]] = None
    tags: Optional[list[str]] = None


class WorkflowUpdate(BaseModel):
    """Update workflow request"""
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    steps: Optional[list[dict[str, Any]]] = None
    settings: Optional[dict[str, Any]] = None
    tags: Optional[list[str]] = None


class WorkflowResponse(BaseModel):
    """Workflow response model"""
    id: str
    user_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    is_preset: bool = False
    steps: list[dict[str, Any]]
    settings: Optional[dict[str, Any]] = None
    tags: list[str] = []
    use_count: int = 0
    last_used: Optional[str] = None
    created_at: Optional[str] = None


@router.get("", response_model=list[WorkflowResponse])
async def get_workflows(
    category: Optional[str] = None,
    user_id: Optional[str] = Depends(get_current_user_optional),
):
    """Get all workflows (presets + user custom)"""
    storage = get_storage()
    
    # Initialize presets if needed
    storage.init_preset_workflows()
    
    workflows = storage.get_workflows(user_id=user_id, category=category)
    return [WorkflowResponse(**w) for w in workflows]


@router.get("/categories")
async def get_workflow_categories():
    """Get available workflow categories"""
    return {
        "categories": [
            {"id": "ecommerce", "name": "E-commerce", "icon": "ShoppingCart"},
            {"id": "blog", "name": "Blog/CMS", "icon": "FileText"},
            {"id": "spa", "name": "SPA/React", "icon": "Code"},
            {"id": "api", "name": "API", "icon": "Server"},
            {"id": "recon", "name": "Reconnaissance", "icon": "Search"},
            {"id": "custom", "name": "Custom", "icon": "Settings"},
        ]
    }


@router.get("/{workflow_id}", response_model=WorkflowResponse)
async def get_workflow(workflow_id: str):
    """Get single workflow by ID"""
    storage = get_storage()
    workflow = storage.get_workflow(workflow_id)
    
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")
    
    return WorkflowResponse(**workflow)


@router.post("", response_model=WorkflowResponse)
async def create_workflow(
    data: WorkflowCreate,
    user_id: Optional[str] = Depends(get_current_user_optional),
):
    """Create a new custom workflow"""
    storage = get_storage()
    
    workflow_id = storage.create_workflow(
        name=data.name,
        steps=data.steps,
        user_id=user_id,
        description=data.description,
        category=data.category or "custom",
        settings=data.settings,
        tags=data.tags,
    )
    
    workflow = storage.get_workflow(workflow_id)
    return WorkflowResponse(**workflow)


@router.put("/{workflow_id}", response_model=WorkflowResponse)
async def update_workflow(
    workflow_id: str,
    data: WorkflowUpdate,
    user_id: Optional[str] = Depends(get_current_user_optional),
):
    """Update a custom workflow (presets cannot be modified)"""
    storage = get_storage()
    
    # Check if workflow exists
    existing = storage.get_workflow(workflow_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Workflow not found")
    
    if existing["is_preset"]:
        raise HTTPException(status_code=403, detail="Cannot modify preset workflows")
    
    updated = storage.update_workflow(
        workflow_id=workflow_id,
        name=data.name,
        description=data.description,
        steps=data.steps,
        settings=data.settings,
        tags=data.tags,
        category=data.category,
    )
    
    if not updated:
        raise HTTPException(status_code=400, detail="Failed to update workflow")
    
    workflow = storage.get_workflow(workflow_id)
    return WorkflowResponse(**workflow)


@router.delete("/{workflow_id}")
async def delete_workflow(
    workflow_id: str,
    user_id: Optional[str] = Depends(get_current_user_optional),
):
    """Delete a custom workflow (presets cannot be deleted)"""
    storage = get_storage()
    
    # Check if workflow exists
    existing = storage.get_workflow(workflow_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Workflow not found")
    
    if existing["is_preset"]:
        raise HTTPException(status_code=403, detail="Cannot delete preset workflows")
    
    deleted = storage.delete_workflow(workflow_id, user_id=user_id)
    
    if not deleted:
        raise HTTPException(status_code=400, detail="Failed to delete workflow")
    
    return {"deleted": True, "id": workflow_id}


@router.post("/{workflow_id}/use")
async def use_workflow(workflow_id: str):
    """Mark workflow as used (increment counter)"""
    storage = get_storage()
    
    workflow = storage.get_workflow(workflow_id)
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")
    
    storage.increment_workflow_usage(workflow_id)
    
    return {"success": True, "use_count": workflow["use_count"] + 1}


@router.post("/{workflow_id}/clone", response_model=WorkflowResponse)
async def clone_workflow(
    workflow_id: str,
    user_id: Optional[str] = Depends(get_current_user_optional),
):
    """Clone a workflow (useful for customizing presets)"""
    storage = get_storage()
    
    original = storage.get_workflow(workflow_id)
    if not original:
        raise HTTPException(status_code=404, detail="Workflow not found")
    
    new_id = storage.create_workflow(
        name=f"{original['name']} (Copy)",
        steps=original["steps"],
        user_id=user_id,
        description=original["description"],
        category="custom",
        settings=original.get("settings"),
        tags=original.get("tags"),
    )
    
    workflow = storage.get_workflow(new_id)
    return WorkflowResponse(**workflow)
