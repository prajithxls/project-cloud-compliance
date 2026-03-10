import json
import boto3
import uuid
from datetime import datetime
import os
from boto3.dynamodb.conditions import Attr

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
}

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["FINDINGS_TABLE"])

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# Runtimes that are deprecated / end-of-life
DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7",
    "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10", "nodejs10.x", "nodejs12.x",
    "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1",
    "ruby2.5", "java8",
}

# Runtimes approaching EOL (warn as MEDIUM)
AGING_RUNTIMES = {
    "python3.8", "nodejs14.x", "nodejs16.x", "java11", "ruby2.7",
}


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

    account_id = context.invoked_function_arn.split(":")[4]
    lmb = boto3.client("lambda")
    iam = boto3.client("iam")

    try:
        # Delete old Lambda findings
        old_items = table.scan(FilterExpression=Attr("scanner").eq("LAMBDA")).get("Items", [])
        for item in old_items:
            table.delete_item(Key={"findingId": item["findingId"]})
        print(f"Deleted {len(old_items)} old Lambda findings")

        # List all Lambda functions (paginated)
        functions = []
        paginator = lmb.get_paginator("list_functions")
        for page in paginator.paginate():
            functions.extend(page.get("Functions", []))

        print(f"Found {len(functions)} Lambda functions in account {account_id}")

        if not functions:
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({
                    "message": "Lambda scan completed — no functions found",
                    "accountId": account_id,
                    "functionsScanned": 0
                })
            }

        findings_added = 0

        for fn in functions:
            fn_name    = fn["FunctionName"]
            fn_arn     = fn["FunctionArn"]
            runtime    = fn.get("Runtime", "")
            role_arn   = fn.get("Role", "")
            timeout    = fn.get("Timeout", 3)
            memory     = fn.get("MemorySize", 128)
            worst      = None

            print(f"\n--- Scanning function: {fn_name} ---")
            print(f"  Runtime: {runtime}, Timeout: {timeout}s, Memory: {memory}MB")

            # ── CHECK 1: Deprecated runtime (HIGH) ───────────────────────────
            if runtime in DEPRECATED_RUNTIMES:
                worst = pick_worst(worst, "HIGH", "8.0",
                    f"Lambda function uses deprecated runtime: {runtime}",
                    f"Upgrade to a supported runtime. {runtime} is end-of-life and receives no security patches.",
                    ["CIS-AWS-L1.1", "NIST-SA-22", "ISO27001-A.12.6"])

            # ── CHECK 2: Aging runtime (MEDIUM) ──────────────────────────────
            elif runtime in AGING_RUNTIMES:
                worst = pick_worst(worst, "MEDIUM", "5.5",
                    f"Lambda function uses an aging runtime: {runtime}",
                    f"Plan migration to a newer runtime. {runtime} is approaching end-of-life.",
                    ["CIS-AWS-L1.1", "NIST-SA-22", "ISO27001-A.12.6"])

            # ── CHECK 3: Overly permissive execution role (CRITICAL/HIGH) ────
            try:
                role_name = role_arn.split("/")[-1]
                attached  = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                policy_names = [p["PolicyName"] for p in attached]
                print(f"  Role policies: {policy_names}")

                if "AdministratorAccess" in policy_names:
                    worst = pick_worst(worst, "CRITICAL", "9.8",
                        "Lambda execution role has AdministratorAccess — full AWS access",
                        "Replace AdministratorAccess with least-privilege policies scoped to only what this function needs.",
                        ["CIS-AWS-L1.3", "NIST-AC-6", "ISO27001-A.9.2"])
                elif any("FullAccess" in p or "PowerUser" in p for p in policy_names):
                    worst = pick_worst(worst, "HIGH", "8.5",
                        f"Lambda execution role has overly permissive policy: {next(p for p in policy_names if 'FullAccess' in p or 'PowerUser' in p)}",
                        "Scope the execution role down to only the specific AWS actions this function requires.",
                        ["CIS-AWS-L1.3", "NIST-AC-6", "ISO27001-A.9.2"])
            except Exception as e:
                print(f"  Role check error: {e}")

            # ── CHECK 4: No environment variable encryption (MEDIUM) ──────────
            try:
                env_vars = fn.get("Environment", {}).get("Variables", {})
                kms_key  = fn.get("KMSKeyArn", "")
                if env_vars and not kms_key:
                    worst = pick_worst(worst, "MEDIUM", "5.0",
                        "Lambda function has environment variables without KMS encryption",
                        "Add a KMS key to encrypt environment variables, especially if they contain secrets or API keys.",
                        ["CIS-AWS-L1.4", "NIST-SC-28", "ISO27001-A.10.1"])
            except Exception as e:
                print(f"  Env encryption check error: {e}")

            # ── CHECK 5: Very high timeout (LOW) ─────────────────────────────
            if timeout >= 600:
                worst = pick_worst(worst, "LOW", "2.5",
                    f"Lambda function has an unusually high timeout of {timeout} seconds",
                    "Review if a 10-minute timeout is truly necessary. High timeouts can mask errors and inflate costs.",
                    ["NIST-SC-5", "ISO27001-A.12.1"])

            # ── CHECK 6: No reserved concurrency / throttling set (LOW) ──────
            try:
                concurrency = lmb.get_function_concurrency(FunctionName=fn_name)
                reserved = concurrency.get("ReservedConcurrentExecutions")
                print(f"  Reserved concurrency: {reserved}")
                if reserved is None:
                    worst = pick_worst(worst, "LOW", "2.0",
                        "Lambda function has no reserved concurrency limit set",
                        "Set reserved concurrency to prevent this function from consuming all available concurrency and causing DoS for other functions.",
                        ["NIST-SC-5", "ISO27001-A.12.1"])
            except Exception as e:
                print(f"  Concurrency check error: {e}")

            print(f"  WORST → {worst}")

            # Always save one finding per function
            if worst is None:
                worst = {
                    "severity": "LOW",
                    "riskScore": "1.0",
                    "title": "Lambda function review — no critical issues found",
                    "remediation": "Continue regular reviews of Lambda function configurations.",
                    "complianceFramework": ["CIS-AWS-L1.1", "NIST-SI-2"],
                }

            table.put_item(Item={
                "findingId": str(uuid.uuid4()),
                "accountId": account_id,
                "resourceType": "Lambda Function",
                "resourceId": fn_arn,
                "severity": worst["severity"],
                "riskScore": worst["riskScore"],
                "title": worst["title"],
                "status": "OPEN",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "scanner": "LAMBDA",
                "remediation": worst["remediation"],
                "complianceFramework": worst["complianceFramework"],
            })
            findings_added += 1
            print(f"  Saved: {worst['severity']} — {worst['title']}")

        print(f"\nLambda scan complete. {findings_added} findings saved.")

        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message": "Lambda scan completed",
                "accountId": account_id,
                "functionsScanned": len(functions),
                "findingsAdded": findings_added,
            })
        }

    except Exception as e:
        print("Lambda scan error:", str(e))
        import traceback
        traceback.print_exc()
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"message": "Lambda scan failed", "error": str(e)})
        }