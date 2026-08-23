import boto3
import asyncio
import logging
from botocore.exceptions import NoCredentialsError, ClientError
from typing import List
from src.core.models import CaseIntakeRequest, Finding

logger = logging.getLogger("netra.module_c")

class CloudAuditModule:
    """
    Zero-Trust Cloud Configuration Auditor.
    Scans AWS EC2 Security Groups for public exposure (0.0.0.0/0) on sensitive ports.
    Falls back to High-Fidelity Simulation if no credentials are found.
    """
    
    SENSITIVE_PORTS = {
        22: "SSH", 
        3389: "RDP", 
        3306: "MySQL", 
        5432: "PostgreSQL", 
        27017: "MongoDB",
        9200: "Elasticsearch"
    }

    async def run(self, request: CaseIntakeRequest) -> List[Finding]:
        logger.info(f"Module C: Initiating Cloud Audit for {request.case_id}...")
        
        # Attempt Real AWS Scan
        findings = await self._scan_real_aws()
        
        # Fallback to Tactical Simulation (For Demo/Training without Creds)
        if findings is None:
            logger.warning("No AWS Credentials found. Engaging Tactical Simulation Mode.")
            findings = self._simulate_compromised_cloud()
            
        return findings

    async def _scan_real_aws(self) -> List[Finding]:
        try:
            # Initialize Boto3 Client (Uses ~/.aws/credentials or Env Vars)
            client = boto3.client('ec2', region_name='us-east-1')
            response = client.describe_security_groups()
            
            findings = []
            for sg in response.get('SecurityGroups', []):
                sg_id = sg['GroupId']
                sg_name = sg.get('GroupName', 'Unknown')
                
                for rule in sg.get('IpPermissions', []):
                    # Check for Public IPv4 (0.0.0.0/0)
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            self._add_violation(findings, sg_id, sg_name, rule, "IPv4")
                            
                    # Check for Public IPv6 (::/0)
                    for ipv6_range in rule.get('Ipv6Ranges', []):
                        if ipv6_range.get('CidrIpv6') == '::/0':
                            self._add_violation(findings, sg_id, sg_name, rule, "IPv6")
                            
            return findings
            
        except NoCredentialsError:
            return None # Trigger Simulation
        except ClientError as e:
            logger.error(f"AWS API Error: {e}")
            return []

    def _add_violation(self, findings: list, sg_id: str, sg_name: str, rule: dict, ip_type: str):
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 0)
        
        # Check if any sensitive port is in the exposed range
        for port, service in self.SENSITIVE_PORTS.items():
            if from_port <= port <= to_port:
                findings.append(Finding(
                    module="MODULE_C",
                    severity="CRITICAL",
                    title=f"Public {service} Exposure ({ip_type})",
                    description=f"Security Group {sg_id} allows public access to port {port}.",
                    confidence=1.0,
                    raw_data={
                        "sg_id": sg_id,
                        "sg_name": sg_name,
                        "port": port,
                        "service": service,
                        "cidr": "0.0.0.0/0" if ip_type == "IPv4" else "::/0"
                    }
                ))

    def _simulate_compromised_cloud(self) -> List[Finding]:
        """
        High-Fidelity Simulation of a misconfigured AWS environment.
        Used when real credentials are not available.
        """
        return [
            Finding(
                module="MODULE_C",
                severity="CRITICAL",
                title="Public SSH Exposure (Simulated)",
                description="Security Group 'sg-dev-web-01' allows SSH (22) from 0.0.0.0/0.",
                confidence=1.0,
                raw_data={"sg_id": "sg-0a1b2c3d4e5f6g7h8", "port": 22, "service": "SSH"}
            ),
            Finding(
                module="MODULE_C",
                severity="HIGH",
                title="Public Database Exposure (Simulated)",
                description="Security Group 'sg-db-prod' allows MySQL (3306) from 0.0.0.0/0.",
                confidence=1.0,
                raw_data={"sg_id": "sg-9h8g7f6e5d4c3b2a1", "port": 3306, "service": "MySQL"}
            )
        ]
