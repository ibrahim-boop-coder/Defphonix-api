import re
import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import List, Dict, Any

# Initialize the router
router = APIRouter(
    prefix="/api/v1/scan",
    tags=["Vulnerability Scanner"]
)

# ==========================================
# Pydantic Models
# ==========================================
class DependencyScanRequest(BaseModel):
    file_type: str = Field(..., description="E.g., 'requirements.txt' or 'package.json'")
    file_content: str = Field(..., description="Raw text content of the file")

# ==========================================
# Parsing & Scanning Engine
# ==========================================
def parse_requirements(content: str) -> List[Dict[str, str]]:
    """
    Extracts package names and exact versions from a requirements.txt file.
    Currently specifically targets strictly pinned versions (e.g., package==1.2.3).
    """
    packages = []
    # Regex to match 'package_name==version' ignoring comments or empty lines
    pattern = re.compile(r"^([a-zA-Z0-9\-_\.]+)\s*==\s*([0-9a-zA-Z\.\-_]+)", re.MULTILINE)
    
    for match in pattern.finditer(content):
        packages.append({
            "name": match.group(1),
            "version": match.group(2)
        })
    return packages

async def query_osv_api(packages: List[Dict[str, str]], ecosystem: str = "PyPI") -> List[Dict[str, Any]]:
    """
    Makes asynchronous POST requests to the OSV API for each parsed package.
    """
    vulnerabilities = []
    
    # Use an async client context manager to reuse connections
    async with httpx.AsyncClient(timeout=10.0) as client:
        for pkg in packages:
            payload = {
                "version": pkg["version"],
                "package": {
                    "name": pkg["name"],
                    "ecosystem": ecosystem
                }
            }
            
            try:
                response = await client.post("https://api.osv.dev/v1/query", json=payload)
                response.raise_for_status()
                data = response.json()
                
                # OSV returns a "vulns" array if vulnerabilities are found
                if "vulns" in data:
                    vulnerabilities.append({
                        "package": pkg["name"],
                        "version": pkg["version"],
                        "issue_count": len(data["vulns"]),
                        "cves": [v.get("id") for v in data["vulns"]]
                    })
            except httpx.HTTPError as exc:
                # In a production environment, you would log this error.
                # We skip failing packages to ensure the rest of the scan completes.
                print(f"Error querying OSV for {pkg['name']}: {exc}")
                continue
                
    return vulnerabilities

# ==========================================
# Endpoints
# ==========================================
@router.post("/dependencies")
async def scan_dependencies(payload: DependencyScanRequest):
    # 1. Validate File Type & Parse Content
    if payload.file_type.lower() == "requirements.txt":
        packages = parse_requirements(payload.file_content)
        ecosystem = "PyPI"
    elif payload.file_type.lower() == "package.json":
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="NPM package.json scanning is scheduled for Phase 3."
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file_type. Currently supporting 'requirements.txt'."
        )

    # If no valid packages were found after parsing
    if not packages:
        return {
            "status": "secure",
            "vulnerabilities_found": 0,
            "message": "No pinned dependencies found to scan.",
            "details": []
        }

    # 2. Query OSV API Asynchronously
    vulnerabilities = await query_osv_api(packages, ecosystem)

    # 3. Format Response
    if vulnerabilities:
        total_vulns = sum(v["issue_count"] for v in vulnerabilities)
        return {
            "status": "vulnerable",
            "vulnerabilities_found": total_vulns,
            "details": vulnerabilities
        }
        
    return {
        "status": "secure",
        "vulnerabilities_found": 0,
        "details": []
    }
