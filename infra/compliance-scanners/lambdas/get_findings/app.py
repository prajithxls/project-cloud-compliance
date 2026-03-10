import json
import boto3
import os
import csv
import io
from datetime import datetime
from decimal import Decimal

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
}

dynamodb = boto3.resource("dynamodb")
s3 = boto3.client("s3")

TABLE_NAME = os.environ["FINDINGS_TABLE"]
CSV_BUCKET = os.environ.get("CSV_BUCKET", "")

table = dynamodb.Table(TABLE_NAME)


def decimal_to_native(obj):
    if isinstance(obj, list):
        return [decimal_to_native(i) for i in obj]
    if isinstance(obj, dict):
        return {k: decimal_to_native(v) for k, v in obj.items()}
    if isinstance(obj, Decimal):
        return float(obj)
    return obj


def generate_csv(findings):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "FindingID", "AccountId", "ResourceType", "ResourceID",
        "Scanner", "Severity", "RiskScore", "Title", "Status",
        "Timestamp", "ComplianceFramework", "Remediation"
    ])
    for f in findings:
        writer.writerow([
            f.get("findingId", ""),
            f.get("accountId", ""),
            f.get("resourceType", ""),
            f.get("resourceId", ""),
            f.get("scanner", ""),
            f.get("severity", ""),
            f.get("riskScore", ""),
            f.get("title", ""),
            f.get("status", ""),
            f.get("timestamp", ""),
            ",".join(f.get("complianceFramework", [])),
            f.get("remediation", ""),
        ])
    return output.getvalue()


def delete_old_csvs():
    """Delete all existing CSV files from the bucket before uploading new one."""
    try:
        response = s3.list_objects_v2(Bucket=CSV_BUCKET)
        objects = response.get("Contents", [])
        if objects:
            s3.delete_objects(
                Bucket=CSV_BUCKET,
                Delete={
                    "Objects": [{"Key": obj["Key"]} for obj in objects],
                    "Quiet": True
                }
            )
            print(f"Deleted {len(objects)} old CSV(s) from {CSV_BUCKET}")
    except Exception as e:
        print(f"Could not delete old CSVs: {str(e)}")


def fetch_all_findings():
    """Scan DynamoDB with pagination."""
    response = table.scan()
    findings = response.get("Items", [])
    while "LastEvaluatedKey" in response:
        response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
        findings.extend(response.get("Items", []))
    return decimal_to_native(findings)


def lambda_handler(event, context):

    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    # Detect whether this is a /refresh call or a /findings call
    path = event.get("path", "")
    is_refresh = path.endswith("/refresh")

    try:
        findings = fetch_all_findings()

        if is_refresh:
            # /refresh → delete old CSVs, generate fresh one, return summary
            if not CSV_BUCKET:
                return {
                    "statusCode": 500,
                    "headers": CORS_HEADERS,
                    "body": json.dumps({"message": "CSV_BUCKET env var not set"})
                }

            # 1. Delete all old CSVs
            delete_old_csvs()

            # 2. Generate new CSV
            csv_data = generate_csv(findings)
            file_name = f"compliance_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"

            # 3. Upload to S3
            s3.put_object(
                Bucket=CSV_BUCKET,
                Key=file_name,
                Body=csv_data,
                ContentType="text/csv"
            )
            print(f"Uploaded new CSV: {file_name} to {CSV_BUCKET}")

            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({
                    "message": "Report generated successfully",
                    "csvFile": file_name,
                    "totalFindings": len(findings),
                    "bucket": CSV_BUCKET
                })
            }

        else:
            # /findings → just return findings, also upload CSV silently
            if CSV_BUCKET:
                try:
                    csv_data = generate_csv(findings)
                    file_name = f"compliance_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
                    s3.put_object(
                        Bucket=CSV_BUCKET,
                        Key=file_name,
                        Body=csv_data,
                        ContentType="text/csv"
                    )
                except Exception as e:
                    print("Silent CSV upload failed:", str(e))

            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({
                    "findings": findings,
                    "total": len(findings),
                })
            }

    except Exception as e:
        print("get_findings error:", str(e))
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"message": "Failed", "error": str(e)})
        }