import json
import boto3
import uuid
import os
from datetime import datetime
from boto3.dynamodb.conditions import Attr

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
}

dynamodb = boto3.resource("dynamodb")
table    = dynamodb.Table(os.environ["FINDINGS_TABLE"])

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def get_client(service, target_account, own_account):
    """
    Returns a boto3 client.
    - No target / same account → use own credentials
    - Different account → assume CrossAccountComplianceRole via STS
    """
    if not target_account or target_account == own_account:
        return boto3.client(service)

    sts = boto3.client("sts")
    try:
        creds = sts.assume_role(
            RoleArn=f"arn:aws:iam::{target_account}:role/CrossAccountComplianceRole",
            RoleSessionName="ComplianceAuditSession"
        )["Credentials"]
        return boto3.client(
            service,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
    except Exception as e:
        raise Exception(f"Failed to assume role in {target_account}: {str(e)}")


def pick_worst(current, severity, risk, title, remediation, frameworks):
    if current is None or SEVERITY_RANK[severity] > SEVERITY_RANK[current["severity"]]:
        return {
            "severity": severity,
            "riskScore": risk,
            "title": title,
            "remediation": remediation,
            "complianceFramework": frameworks,
        }
    return current


def lambda_handler(event, context):

    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    own_account    = context.invoked_function_arn.split(":")[4]
    target_account = event.get("accountId", "").strip()
    scan_account   = target_account if target_account and target_account != own_account else own_account

    print(f"S3 Scanner — scanning account: {scan_account}")

    try:
        s3 = get_client("s3", target_account, own_account)

        # Delete old S3 findings for this account
        old_items = table.scan(
            FilterExpression=Attr("scanner").eq("S3") & Attr("accountId").eq(scan_account)
        ).get("Items", [])
        for item in old_items:
            table.delete_item(Key={"findingId": item["findingId"]})
        print(f"Deleted {len(old_items)} old S3 findings")

        buckets = s3.list_buckets().get("Buckets", [])
        print(f"Found {len(buckets)} buckets")

        findings_added = 0

        for bucket in buckets:
            name  = bucket["Name"]
            worst = None

            # ── CHECK 1: Public access block ──────────────────────────────
            try:
                pab = s3.get_public_access_block(Bucket=name)
                config = pab["PublicAccessBlockConfiguration"]
                if not all([
                    config.get("BlockPublicAcls"),
                    config.get("BlockPublicPolicy"),
                    config.get("RestrictPublicBuckets"),
                    config.get("IgnorePublicAcls"),
                ]):
                    worst = pick_worst(worst, "HIGH", "9.0",
                        "S3 bucket public access block is not fully enabled",
                        "Enable all four public access block settings on the bucket.",
                        ["CIS-AWS-2.1.5", "NIST-SC-7", "ISO27001-A.13.1"])
            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                worst = pick_worst(worst, "HIGH", "9.0",
                    "S3 bucket has no public access block configuration",
                    "Configure public access block to prevent accidental public exposure.",
                    ["CIS-AWS-2.1.5", "NIST-SC-7", "ISO27001-A.13.1"])
            except Exception as e:
                print(f"  Public access check error for {name}: {e}")

            # ── CHECK 2: Default encryption ───────────────────────────────
            try:
                s3.get_bucket_encryption(Bucket=name)
            except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                worst = pick_worst(worst, "MEDIUM", "6.5",
                    "S3 bucket does not have default encryption enabled",
                    "Enable AES256 or AWS KMS default encryption on the bucket.",
                    ["CIS-AWS-2.1.1", "NIST-SC-28", "ISO27001-A.10.1"])
            except Exception as e:
                print(f"  Encryption check error for {name}: {e}")

            # ── CHECK 3: Versioning ───────────────────────────────────────
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                if ver.get("Status") != "Enabled":
                    worst = pick_worst(worst, "LOW", "3.5",
                        "S3 bucket versioning is not enabled",
                        "Enable versioning to protect against accidental deletion.",
                        ["CIS-AWS-2.1.3", "NIST-CP-9", "ISO27001-A.12.3"])
            except Exception as e:
                print(f"  Versioning check error for {name}: {e}")

            # ── CHECK 4: Access logging ───────────────────────────────────
            try:
                log = s3.get_bucket_logging(Bucket=name)
                if "LoggingEnabled" not in log:
                    worst = pick_worst(worst, "LOW", "2.5",
                        "S3 bucket access logging is not enabled",
                        "Enable server access logging for audit trail purposes.",
                        ["CIS-AWS-2.1.4", "NIST-AU-2", "ISO27001-A.12.4"])
            except Exception as e:
                print(f"  Logging check error for {name}: {e}")

            # Fallback
            if worst is None:
                worst = {
                    "severity": "LOW", "riskScore": "1.0",
                    "title": "S3 bucket review — no critical issues found",
                    "remediation": "Continue regular review of bucket configurations.",
                    "complianceFramework": ["CIS-AWS-2.1", "NIST-SI-2"],
                }

            table.put_item(Item={
                "findingId":          str(uuid.uuid4()),
                "accountId":          scan_account,
                "resourceType":       "S3 Bucket",
                "resourceId":         f"arn:aws:s3:::{name}",
                "severity":           worst["severity"],
                "riskScore":          worst["riskScore"],
                "title":              worst["title"],
                "status":             "OPEN",
                "timestamp":          datetime.utcnow().isoformat() + "Z",
                "scanner":            "S3",
                "remediation":        worst["remediation"],
                "complianceFramework": worst["complianceFramework"],
            })
            findings_added += 1
            print(f"  {name}: {worst['severity']} — {worst['title']}")

        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message": "S3 scan complete",
                "accountId": scan_account,
                "bucketsScanned": len(buckets),
                "findingsAdded": findings_added,
            }),
        }

    except Exception as e:
        print(f"S3 scan error: {str(e)}")
        import traceback; traceback.print_exc()
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"message": "S3 scan failed", "error": str(e)}),
        }