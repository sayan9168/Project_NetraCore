#!/bin/bash
# Project Netra-Core - GitHub Topics & Metadata Application
# Version: Production Release

set -e

cd ~/Project_NetraCore

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}   PROJECT NETRA-CORE - GitHub Metadata Configuration    ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Check if gh is authenticated
if ! gh auth status > /dev/null 2>&1; then
    echo -e "${RED}✗ GitHub CLI not authenticated${NC}"
    echo "Run: gh auth login"
    exit 1
fi

echo -e "${GREEN}✓ GitHub CLI authenticated${NC}"

# Get repository details
REPO_OWNER=$(gh repo view --json owner -q .owner.login)
REPO_NAME=$(gh repo view --json name -q .name)
FULL_REPO="${REPO_OWNER}/${REPO_NAME}"

echo -e "${GREEN}✓ Repository: ${FULL_REPO}${NC}"
echo ""

# ─── Strategic Topic List (30 Topics) ─────────────────────────────────────
TOPICS=(
    # Core Domain
    "cybersecurity"
    "digital-forensics"
    "forensic-analysis"
    "incident-response"
    "cyber-defense"
    "threat-intelligence"
    
    # Technology Stack
    "python"
    "python3"
    "fastapi"
    "async"
    "asyncio"
    "pydantic"
    "uvicorn"
    
    # Security & Compliance
    "zero-trust"
    "security-audit"
    "hmac"
    "chain-of-custody"
    "tamper-evident"
    "iso27001"
    "nis2"
    
    # AI / ML
    "nlp"
    "machine-learning"
    "steganalysis"
    "deep-learning"
    "sentence-transformers"
    
    # Infrastructure
    "docker"
    "kubernetes"
    "helm"
    "opentelemetry"
    "aws"
    "boto3"
    
    # Domain-Specific
    "law-enforcement"
    "government"
    "court-admissible"
    "evidence-management"
    
    # Indian Legal Context
    "bns2023"
    "it-act"
    "indian-cyber-law"
)

echo -e "${YELLOW}📋 Applying ${#TOPICS[@]} strategic topics...${NC}"
echo ""

# Convert array to comma-separated string
TOPIC_STRING=$(IFS=,; echo "${TOPICS[*]}")

# Apply topics using GitHub API
echo -e "${CYAN}Sending topics to GitHub API...${NC}"
gh api \
    --method PUT \
    -H "Accept: application/vnd.github+json" \
    "/repos/${FULL_REPO}/topics" \
    -f "names=${TOPIC_STRING}" > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Successfully applied ${#TOPICS[@]} topics${NC}"
else
    echo -e "${RED}✗ Failed to apply topics${NC}"
    echo "Trying alternative method..."
    
    # Alternative: one-by-one application
    for topic in "${TOPICS[@]}"; do
        echo -n "  Adding: $topic ... "
        if gh repo edit "$FULL_REPO" --add-topic "$topic" > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC}"
        else
            echo -e "${YELLOW}⚠${NC}"
        fi
    done
fi

echo ""

# ─── Update Repository Description ────────────────────────────────────────
echo -e "${YELLOW}📝 Updating repository description...${NC}"

DESCRIPTION="🛡️ Enterprise-Grade Government Cyber-Defense & Forensic Engine | Zero-Trust | HMAC-SHA256 Evidence Ledger | AI-Powered Legal NLP (BNS/IT Act) | Court-Admissible Reports"

gh repo edit "$FULL_REPO" --description "$DESCRIPTION" > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Description updated${NC}"
else
    echo -e "${YELLOW}⚠ Description update failed${NC}"
fi

echo ""

# ─── Enable Repository Features ───────────────────────────────────────────
echo -e "${YELLOW}⚙ Enabling repository features...${NC}"

# Enable issues
gh repo edit "$FULL_REPO" --enable-issues > /dev/null 2>&1 && \
    echo -e "${GREEN}✓ Issues enabled${NC}" || \
    echo -e "${YELLOW}⚠ Issues already enabled${NC}"

# Enable discussions
gh repo edit "$FULL_REPO" --enable-discussions > /dev/null 2>&1 && \
    echo -e "${GREEN}✓ Discussions enabled${NC}" || \
    echo -e "${YELLOW}⚠ Discussions feature unavailable${NC}"

# Enable wiki
gh repo edit "$FULL_REPO" --enable-wiki > /dev/null 2>&1 && \
    echo -e "${GREEN}✓ Wiki enabled${NC}" || \
    echo -e "${YELLOW}⚠ Wiki already enabled${NC}"

# Enable security alerts
gh api \
    --method PUT \
    "/repos/${FULL_REPO}/vulnerability-alerts" \
    -H "Accept: application/vnd.github+json" > /dev/null 2>&1 && \
    echo -e "${GREEN}✓ Vulnerability alerts enabled${NC}" || \
    echo -e "${YELLOW}⚠ Vulnerability alerts already enabled${NC}"

echo ""

# ─── Verification ─────────────────────────────────────────────────────────
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}   VERIFICATION                                            ${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

echo -e "${GREEN}Current Repository Topics:${NC}"
gh api "/repos/${FULL_REPO}/topics" -H "Accept: application/vnd.github+json" | \
    python3 -c "import sys, json; topics = json.load(sys.stdin)['names']; [print(f'  • {t}') for t in topics]" 2>/dev/null || \
    echo "  (Unable to fetch topics)"

echo ""
echo -e "${GREEN}Repository URL:${NC}"
echo -e "  ${CYAN}https://github.com/${FULL_REPO}${NC}"

echo ""
echo -e "${GREEN}Repository Description:${NC}"
gh repo view --json description -q .description | sed 's/^/  /'

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ GitHub Metadata Configuration Complete${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
