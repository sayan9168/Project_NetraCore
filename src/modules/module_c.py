import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import asyncio
import logging
import os
from typing import List, Optional
from src.core.models import CaseIntakeRequest, Finding

logger = logging.getLogger("netra.module_c")


class CloudAuditModule:
    """
    Production AWS Cloud Auditor.
    Uses STS AssumeRole with read-only SecurityAudit policy.
    Supports cross-account scanning for government multi-tenant environments.
    """

    SENSITIVE_PORTS = {
        22: "SSH", 3389: "RDP", 3306: "MySQL",
        5432: "PostgreSQL", 27017: "MongoDB",
        9200: "Elasticsearch", 6379: "Redis",
        11211: "Memcached", 5601: "Kibana"
    }

    PUBLIC_CIDRS = ("0.0.0.0/0", "::/0")

    def __init__(self):
        self.role_arn = os.getenv("AWS_AUDIT_ROLE_ARN")
        self.external_id = os.getenv("AWS_EXTERNAL_ID")
        self.regions = os.getenv("AWS_SCAN_REGIONS", "us-east-1,ap-south-1").split(",")

    async def run(self, request: CaseIntakeRequest) -> List[Finding]:
        logger.info(f"Module C: Production AWS Audit for case {request.case_id}")

        if not self.role_arn:
            logger.warning("AWS_AUDIT_ROLE_ARN not set. Falling back to simulation.")
            return self._simulate()

        try:
            findings = await asyncio.to_thread(self._scan_all_regions)
            logger.info(f"Module C: Found {len(findings)} violations across {len(self.regions)} regions")
            return findings
        except NoCredentialsError:
            logger.error("AWS credentials missing")
            return []
        except ClientError as e:
            logger.error(f"AWS API error: {e}")
            return [Finding(
                module="MODULE_C", severity="HIGH",
                title="AWS Access Error",
                description=f"Failed to scan: {e.response['Error']['Message']}",
                confidence=1.0, raw_data={"error_code": e.response["Error"]["Code"]}
            )]

    def _assume_role(self, region: str) -> Optional[boto3.Session]:
        """Cross-account role assumption with ExternalID protection."""
        try:
            sts = boto3.client("sts", region_name=region)
            kwargs = {
                "RoleArn": self.role_arn,
                "RoleSessionName": f"netra-audit-{region}",
                "DurationSeconds": 900
            }
            if self.external_id:
                kwargs["ExternalId"] = self.external_id

            response = sts.assume_role(**kwargs)
            creds = response["Credentials"]
            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region
            )
        except ClientError as e:
            logger.error(f"AssumeRole failed for {region}: {e}")
            return None

    def _scan_all_regions(self) -> List[Finding]:
        all_findings = []
        for region in self.regions:
            session = self._assume_role(region)
            if not session:
                continue

            all_findings.extend(self._audit_security_groups(session, region))
            all_findings.extend(self._audit_s3_buckets(session, region))
            all_findings.extend(self._audit_iam_policies(session, region))
            all_findings.extend(self._audit_cloudtrail(session, region))
        return all_findings

    def _audit_security_groups(self, session: boto3.Session, region: str) -> List[Finding]:
        findings = []
        ec2 = session.client("ec2")
        paginator = ec2.get_paginator("describe_security_groups")

        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort") or 0
                    to_port = perm.get("ToPort") or 65535

                    for cidr in perm.get("IpRanges", []) + perm.get("Ipv6Ranges", []):
                        cidr_value = cidr.get("CidrIp") or cidr.get("CidrIpv6")
                        if cidr_value in self.PUBLIC_CIDRS:
                            for port, service in self.SENSITIVE_PORTS.items():
                                if from_port <= port <= to_port:
                                    findings.append(Finding(
                                        module="MODULE_C",
                                        severity="CRITICAL",
                                        title=f"Public {service} Exposure",
                                        description=f"SG {sg['GroupId']} in {region} exposes port {port} to {cidr_value}",
                                        confidence=1.0,
                                        raw_data={
                                            "sg_id": sg["GroupId"],
                                            "sg_name": sg.get("GroupName"),
                                            "region": region,
                                            "port": port,
                                            "service": service,
                                            "cidr": cidr_value
                                        }
                                    ))
        return findings

    def _audit_s3_buckets(self, session: boto3.Session, region: str) -> List[Finding]:
        findings = []
        s3 = session.client("s3")
        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except ClientError:
            return findings

        for bucket in buckets:
            name = bucket["Name"]
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    uri = grant.get("Grantee", {}).get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        findings.append(Finding(
                            module="MODULE_C",
                            severity="CRITICAL",
                            title=f"Public S3 Bucket: {name}",
                            description=f"Bucket grants public access via ACL",
                            confidence=1.0,
                            raw_data={"bucket": name, "region": region, "grant": uri}
                        ))
                        break
            except ClientError:
                pass
        return findings

    def _audit_iam_policies(self, session: boto3.Session, region: str) -> List[Finding]:
        findings = []
        iam = session.client("iam")
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    uname = user["UserName"]
                    try:
                        keys = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
                        for key in keys:
                            if key["Status"] == "Active":
                                last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                                last_date = last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                                if not last_date:
                                    findings.append(Finding(
                                        module="MODULE_C",
                                        severity="HIGH",
                                        title=f"Unused IAM Access Key: {uname}",
                                        description="Active access key has never been used",
                                        confidence=0.9,
                                        raw_data={"user": uname, "key_id": key["AccessKeyId"]}
                                    ))
                    except ClientError:
                        pass
        except ClientError:
            pass
        return findings

    def _audit_cloudtrail(self, session: boto3.Session, region: str) -> List[Finding]:
        findings = []
        ct = session.client("cloudtrail")
        try:
            trails = ct.describe_trails().get("trailList", [])
            if not trails:
                findings.append(Finding(
                    module="MODULE_C", severity="HIGH",
                    title="No CloudTrail in Region",
                    description=f"No CloudTrail configured in {region}",
                    confidence=1.0, raw_data={"region": region}
                ))
            else:
                for trail in trails:
                    if not trail.get("IsMultiRegionTrail"):
                        findings.append(Finding(
                            module="MODULE_C", severity="MEDIUM",
                            title=f"CloudTrail Not Multi-Region: {trail['Name']}",
                            description="Trail only logs in single region",
                            confidence=1.0, raw_data={"trail": trail["Name"]}
                        ))
        except ClientError:
            pass
        return findings

    def _simulate(self) -> List[Finding]:
        return [Finding(
            module="MODULE_C", severity="CRITICAL",
            title="Public SSH Exposure (Simulation Mode)",
            description="Set AWS_AUDIT_ROLE_ARN env var for live scanning",
            confidence=1.0, raw_data={"mode": "simulation"}
        )]
