import json
import boto3
import uuid
from datetime import datetime
import os
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
}

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["FINDINGS_TABLE"])
s3 = boto3.client("s3")

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def lambda_handler(event, context):

    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    account_id = context.invoked_function_arn.split(":")[4]

    try:
        # Delete old S3 findings
        old_items = table.scan(FilterExpression=Attr("scanner").eq("S3")).get("Items", [])
        for item in old_items:
            table.delete_item(Key={"findingId": item["findingId"]})

        buckets = s3.list_buckets().get("Buckets", [])
        print(f"Scanning {len(buckets)} buckets in account {account_id}")

        for b in buckets:
            bucket_name = b["Name"]

            # Evaluate all checks and pick the worst one
            worst = None  # {"severity", "riskScore", "title", "remediation", "complianceFramework"}

            def update_worst(severity, risk, title, remediation, frameworks):
                nonlocal worst
                if worst is None or SEVERITY_RANK[severity] > SEVERITY_RANK[worst["severity"]]:
                    worst = {
                        "severity": severity,
                        "riskScore": risk,
                        "title": title,
                        "remediation": remediation,
                        "complianceFramework": frameworks,
                    }

            # CHECK 1: Public access block → HIGH
            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)
                cfg = pab["PublicAccessBlockConfiguration"]
                if not (
                    cfg.get("BlockPublicAcls", True) and
                    cfg.get("IgnorePublicAcls", True) and
                    cfg.get("BlockPublicPolicy", True) and
                    cfg.get("RestrictPublicBuckets", True)
                ):
                    update_worst("HIGH", "9.0",
                        "S3 bucket allows public access",
                        "Enable all four Block Public Access settings for the bucket",
                        ["CIS-AWS-3.1", "ISO27001-A.13.1", "NIST-SC-7"])
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "NoSuchPublicAccessBlockConfiguration":
                    update_worst("HIGH", "9.0",
                        "S3 bucket allows public access",
                        "Enable all four Block Public Access settings for the bucket",
                        ["CIS-AWS-3.1", "ISO27001-A.13.1", "NIST-SC-7"])
                else:
                    print(f"Skipping public access check for {bucket_name}: {code}")

            # CHECK 2: No encryption → MEDIUM
            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
            except ClientError as e:
                if e.response["Error"]["Code"] in (
                    "ServerSideEncryptionConfigurationNotFoundError",
                    "NoSuchEncryptionConfiguration"
                ):
                    update_worst("MEDIUM", "6.5",
                        "S3 bucket does not have default encryption enabled",
                        "Enable AES-256 or AWS KMS default encryption on the bucket",
                        ["CIS-AWS-3.7", "NIST-SC-28", "ISO27001-A.10.1"])

            # CHECK 3: Versioning disabled → LOW
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get("Status") != "Enabled":
                    update_worst("LOW", "3.5",
                        "S3 bucket versioning is not enabled",
                        "Enable versioning to protect against accidental deletion or overwrites",
                        ["CIS-AWS-3.8", "NIST-CP-9", "ISO27001-A.12.3"])
            except ClientError as e:
                print(f"Versioning check failed for {bucket_name}: {e.response['Error']['Code']}")

            # CHECK 4: Logging disabled → LOW
            try:
                logging_cfg = s3.get_bucket_logging(Bucket=bucket_name)
                if "LoggingEnabled" not in logging_cfg:
                    update_worst("LOW", "2.5",
                        "S3 bucket access logging is not enabled",
                        "Enable S3 server access logging for audit and forensic purposes",
                        ["CIS-AWS-3.6", "NIST-AU-2", "ISO27001-A.12.4"])
            except ClientError as e:
                print(f"Logging check failed for {bucket_name}: {e.response['Error']['Code']}")

            # Save only the single worst finding for this bucket
            if worst:
                table.put_item(Item={
                    "findingId": str(uuid.uuid4()),
                    "accountId": account_id,
                    "resourceType": "S3 Bucket",
                    "resourceId": f"arn:aws:s3:::{bucket_name}",
                    "severity": worst["severity"],
                    "riskScore": worst["riskScore"],
                    "title": worst["title"],
                    "status": "OPEN",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "scanner": "S3",
                    "remediation": worst["remediation"],
                    "complianceFramework": worst["complianceFramework"],
                })
                print(f"{bucket_name} → {worst['severity']}: {worst['title']}")

        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message": "S3 scan completed",
                "accountId": account_id,
                "bucketsScanned": len(buckets)
            })
        }

    except Exception as e:
        print("S3 scan error:", str(e))
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"message": "S3 scan failed", "error": str(e)})
        }