import json
import boto3
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from boto3.dynamodb.conditions import Key

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
}

lambda_client = boto3.client("lambda")
sts_client = boto3.client("sts")
dynamodb = boto3.resource("dynamodb")

# Environment Variables
S3_FN          = os.environ.get("S3_SCANNER_FUNCTION",     "compliance-scanners-dev-s3Scanner")
EC2_FN         = os.environ.get("EC2_SCANNER_FUNCTION",    "compliance-scanners-dev-ec2Scanner")
IAM_FN         = os.environ.get("IAM_SCANNER_FUNCTION",    "compliance-scanners-dev-iamScanner")
LAMBDA_FN      = os.environ.get("LAMBDA_SCANNER_FUNCTION", "compliance-scanners-dev-lambdaScanner")
FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE",          "ComplianceFindings") # <-- Make sure this matches your DynamoDB table!

def purge_old_findings(account_id):
    """Deletes all existing findings for this account before running a new scan."""
    table = dynamodb.Table(FINDINGS_TABLE)
    try:
        # 1. Find all old records
        response = table.query(
            KeyConditionExpression=Key('accountId').eq(account_id)
        )
        items = response.get('Items', [])

        # 2. Delete them in batches
        if items:
            with table.batch_writer() as batch:
                for item in items:
                    batch.delete_item(
                        Key={
                            'accountId': item['accountId'],
                            'findingId': item['findingId']
                        }
                    )
            print(f"Purged {len(items)} old findings for account {account_id}")
    except Exception as e:
        print(f"Error purging findings: {str(e)}")

def invoke_scanner(name, fn, target_account):
    try:
        payload = {}
        if target_account:
            payload["accountId"] = target_account

        response = lambda_client.invoke(
            FunctionName=fn,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload),
        )
        result = json.loads(response["Payload"].read())
        body = result.get("body", "{}")
        return name, json.loads(body) if isinstance(body, str) else body, None
    except Exception as e:
        print(f"{name} invocation error: {str(e)}")
        return name, None, str(e)


def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    # Get own account ID from Lambda execution context
    own_account = context.invoked_function_arn.split(":")[4]

    # Check if a target account was passed as query parameter
    target_account = (event.get("queryStringParameters") or {}).get("accountId", "").strip()

    # Validate if provided
    if target_account:
        if len(target_account) != 12 or not target_account.isdigit():
            return {
                "statusCode": 400,
                "headers": CORS_HEADERS,
                "body": json.dumps({"message": "accountId must be exactly 12 digits"})
            }
        # If same as own account treat as own-account scan
        if target_account == own_account:
            target_account = ""

    is_cross_account = bool(target_account)
    scan_account = target_account if is_cross_account else own_account

    print(f"Scanning account: {scan_account} | Cross-account: {is_cross_account}")

    # ── 1. FAIL FAST: Check STS AssumeRole BEFORE scanning ──
    if is_cross_account:
        try:
            sts_client.assume_role(
                RoleArn=f"arn:aws:iam::{target_account}:role/CrossAccountComplianceRole",
                RoleSessionName="ComplianceScanCheck"
            )
        except Exception as e:
            print(f"Failed to assume role: {str(e)}")
            
            # Wipe old data anyway so the frontend doesn't show ghost data
            purge_old_findings(scan_account) 
            
            # Send the 403 Forbidden Error back to React
            return {
                "statusCode": 403,
                "headers": CORS_HEADERS,
                "body": json.dumps({
                    "message": f"Access Denied: Could not assume CrossAccountComplianceRole in account {target_account}. The role may have been deleted or modified."
                })
            }

    # ── 2. PURGE OLD DATA (If STS succeeds, clear out the last scan) ──
    purge_old_findings(scan_account)

    scanners = [
        ("s3",     S3_FN),
        ("ec2",    EC2_FN),
        ("iam",    IAM_FN),
        ("lambda", LAMBDA_FN),
    ]

    results = {}
    errors  = {}

    # Run all 4 scanners in parallel
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(invoke_scanner, name, fn, target_account): name
            for name, fn in scanners
        }
        for future in as_completed(futures):
            name, result, error = future.result()
            if error:
                errors[name] = error
            else:
                results[name] = result

    print(f"Scan complete. Results: {list(results.keys())}, Errors: {list(errors.keys())}")

    return {
        "statusCode": 200 if not errors else 207,
        "headers": CORS_HEADERS,
        "body": json.dumps({
            "message": "Scan complete" if not errors else "Scan completed with errors",
            "accountId": scan_account,
            "crossAccount": is_cross_account,
            "results": results,
            "errors": errors,
        }),
    }