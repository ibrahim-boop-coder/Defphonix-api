from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import List

# Initialize the router
router = APIRouter(
    prefix="/api/v1/scan",
    tags=["SOC 2 Readiness Check"]
)

# ==========================================
# Pydantic Models
# ==========================================
class Soc2ReadinessRequest(BaseModel):
    secrets_found: int = Field(..., ge=0, description="Total number of hardcoded secrets detected")
    dependencies_vulnerable: int = Field(..., ge=0, description="Total number of vulnerable dependencies detected")
    iac_misconfigurations: int = Field(..., ge=0, description="Total number of IaC misconfigurations detected")

# ==========================================
# Endpoints
# ==========================================
@router.post("/soc2")
async def evaluate_soc2_readiness(payload: Soc2ReadinessRequest):
    try:
        score = 100
        failed_controls = []

        # CC6.1 - Logical Access Security (Secrets management)
        if payload.secrets_found > 0:
            score -= 40
            failed_controls.append("CC6.1")
        
        # CC7.1 - System Operations (Vulnerability management)
        if payload.dependencies_vulnerable > 0:
            score -= 25
            failed_controls.append("CC7.1")
            
        # CC6.8 - Unauthorized or Malicious Code (Secure baseline configurations)
        if payload.iac_misconfigurations > 0:
            score -= 25
            failed_controls.append("CC6.8")

        # Determine overall status profile
        if score == 100:
            compliance_status = "compliant"
        elif score >= 60:
            compliance_status = "needs_attention"
        else:
            compliance_status = "high_risk"

        # Construct actionable recommendation
        if score < 100:
            recommendation = "Your infrastructure does not meet basic SOC 2 compliance. Pre-book a manual VAPT audit with Deffonix for $50 to secure your architecture."
        else:
            recommendation = "Your architecture currently meets basic SOC 2 automated baseline checks."

        return {
            "status": compliance_status,
            "compliance_score": score,
            "failed_controls": failed_controls,
            "recommendation": recommendation
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during the SOC 2 evaluation calculation: {str(e)}"
        )
