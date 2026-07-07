import re
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import List, Dict, Any

# Initialize the router
router = APIRouter(
    prefix="/api/v1/scan",
    tags=["IaC Misconfiguration Linter"]
)

# ==========================================
# Pydantic Models
# ==========================================
class LinterScanRequest(BaseModel):
    file_type: str = Field(..., description="E.g., 'Dockerfile'")
    file_content: str = Field(..., description="Raw text content of the configuration file")

# ==========================================
# Dockerfile Linter Engine
# ==========================================
def lint_dockerfile(content: str) -> List[Dict[str, Any]]:
    findings = []
    
    # Split content into lines and strip whitespace
    lines = [line.strip() for line in content.splitlines()]
    
    # State tracking variables
    has_user_instruction = False
    last_user_is_root = False
    
    # Sensitive ports lookup table
    SENSITIVE_PORTS = {
        "22": "SSH (Secure Shell)",
        "3306": "MySQL Database",
        "5432": "PostgreSQL Database",
        "27017": "MongoDB Database",
        "6379": "Redis Cache"
    }

    # Process line-by-line
    for line_no, line in enumerate(lines, 1):
        # Ignore comments and empty lines
        if not line or line.startswith("#"):
            continue

        # 1. Check FROM instructions for missing or 'latest' tags
        if line.upper().startswith("FROM"):
            # Extract the image part (handle multi-stage builds 'FROM image AS stage')
            parts = line.split()
            if len(parts) > 1:
                base_image = parts[1]
                
                # Flag if latest tag is explicitly used or tag is entirely missing
                if ":latest" in base_image.lower():
                    findings.append({
                        "line": line_no,
                        "rule": "Explicit Latest Tag Used",
                        "severity": "Medium",
                        "description": f"The base image '{base_image}' explicitly requests the mutable ':latest' tag.",
                        "remediation": "Pin the base image to a specific semantic version version or a sha256 cryptographic digest."
                    })
                elif ":" not in base_image and "@" not in base_image:
                    findings.append({
                        "line": line_no,
                        "rule": "Missing Base Image Tag",
                        "severity": "Medium",
                        "description": f"The base image '{base_image}' does not specify a version tag, defaulting to ':latest'.",
                        "remediation": "Append a specific image version tag (e.g., python:3.11-slim) or digest to guarantee build reproducibility."
                    })

        # 2. Track USER instructions
        if line.upper().startswith("USER"):
            has_user_instruction = True
            parts = line.split()
            if len(parts) > 1 and parts[1].lower() == "root":
                last_user_is_root = True
            else:
                last_user_is_root = False

        # 3. Check EXPOSE instructions for sensitive infrastructure ports
        if line.upper().startswith("EXPOSE"):
            # Extract all potential port matches from the instruction line
            ports = re.findall(r"\b\d+\b", line)
            for port in ports:
                if port in SENSITIVE_PORTS:
                    findings.append({
                        "line": line_no,
                        "rule": "Sensitive Port Exposed",
                        "severity": "High",
                        "description": f"Port {port} ({SENSITIVE_PORTS[port]}) is exposed in the container specification.",
                        "remediation": "Remove the EXPOSE instruction for production database or administrative utilities. Use runtime port mapping instead."
                    })

    # Evaluate the final state of the runtime user context
    if not has_user_instruction:
        findings.append({
            "line": None,
            "rule": "Implicit Root User Privileges",
            "severity": "High",
            "description": "No USER directive declared. Containers run as root by default.",
            "remediation": "Create a dedicated non-root application user/group profile and switch to it using the 'USER' directive before the entry point."
        })
    elif last_user_is_root:
        findings.append({
            "line": None,
            "rule": "Explicit Root User Privileges",
            "severity": "High",
            "description": "The container execution context is explicitly set to running under 'USER root'.",
            "remediation": "Switch execution context to a non-privileged system user profile to minimize container breakout risks."
        })

    return findings

# ==========================================
# Endpoints
# ==========================================
@router.post("/iac")
async def scan_iac_configuration(payload: LinterScanRequest):
    try:
        if payload.file_type.lower() != "dockerfile":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported configuration file profile. Currently supporting 'Dockerfile'."
            )
            
        # Run internal parsing rules
        issues = lint_dockerfile(payload.file_content)
        
        if issues:
            return {
                "status": "vulnerable",
                "misconfigurations_found": len(issues),
                "details": issues
            }
            
        return {
            "status": "secure",
            "misconfigurations_found": 0,
            "details": []
        }
        
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred within the static configuration linter engine: {str(e)}"
        )
