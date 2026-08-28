#!/bin/bash
# Update README.md with professional GitHub badges

cd ~/Project_NetraCore

# Get repository info
REPO_OWNER=$(gh repo view --json owner -q .owner.login)
REPO_NAME=$(gh repo view --json name -q .name)

# Create badge header
BADGE_HEADER="<!-- Professional Badges -->
<p align=\"center\">
  <img src=\"https://img.shields.io/badge/Version-6.1.2--Production-blue?style=for-the-badge\" alt=\"Version\">
  <img src=\"https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white\" alt=\"Python\">
  <img src=\"https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi&logoColor=white\" alt=\"FastAPI\">
  <img src=\"https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white\" alt=\"Docker\">
  <img src=\"https://img.shields.io/badge/Kubernetes-Helm-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white\" alt=\"Kubernetes\">
  <img src=\"https://img.shields.io/badge/Security-Tamper--Evident-red?style=for-the-badge\" alt=\"Security\">
  <img src=\"https://img.shields.io/github/license/${REPO_OWNER}/${REPO_NAME}?style=for-the-badge\" alt=\"License\">
  <img src=\"https://img.shields.io/github/stars/${REPO_OWNER}/${REPO_NAME}?style=for-the-badge&color=gold\" alt=\"Stars\">
  <img src=\"https://img.shields.io/github/last-commit/${REPO_OWNER}/${REPO_NAME}?style=for-the-badge\" alt=\"Last Commit\">
</p>

<p align=\"center\">
  <img src=\"https://img.shields.io/badge/ISO-27001%20Compliant-4CAF50?style=flat-square\" alt=\"ISO 27001\">
  <img src=\"https://img.shields.io/badge/NIS2-Compliant-2196F3?style=flat-square\" alt=\"NIS2\">
  <img src=\"https://img.shields.io/badge/Court-Admissible-FF5722?style=flat-square\" alt=\"Court Admissible\">
  <img src=\"https://img.shields.io/badge/Zero-Trust-9C27B0?style=flat-square\" alt=\"Zero Trust\">
</p>
"

# Check if badges already exist
if grep -q "<!-- Professional Badges -->" README.md; then
    echo "Badges already exist in README.md"
else
    # Insert badges after the title
    python3 << PYEOF
import re

with open("README.md", "r") as f:
    content = f.read()

badges = """$BADGE_HEADER"""

# Find the first header (#) and insert badges after the first paragraph
lines = content.split('\n')
insert_at = 0
for i, line in enumerate(lines):
    if line.startswith('# '):
        # Find the next blank line or next header
        for j in range(i+1, len(lines)):
            if lines[j].strip() == '' or lines[j].startswith('#'):
                insert_at = j
                break
        break

if insert_at > 0:
    lines.insert(insert_at, badges)
    with open("README.md", "w") as f:
        f.write('\n'.join(lines))
    print("✓ Badges added to README.md")
else:
    print("✗ Could not find insertion point")
PYEOF
fi

echo "README.md badge update complete"
