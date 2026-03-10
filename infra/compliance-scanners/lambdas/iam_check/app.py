import json
import boto3
import uuid
from datetime import datetime, timezone
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
    iam = boto3.client("iam")

    try:
        # ── Delete old IAM findings ───────────────────────────────────────────
        old_items = table.scan(FilterExpression=Attr("scanner").eq("IAM")).get("Items", [])
        for item in old_items:
            table.delete_item(Key={"findingId": item["findingId"]})
        print(f"Deleted {len(old_items)} old IAM findings")

        users = iam.list_users().get("Users", [])
        print(f"Found {len(users)} IAM users in account {account_id}")

        if not users:
            print("No IAM users found — nothing to scan")
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({"message": "IAM scan completed — no users found", "accountId": account_id, "usersScanned": 0})
            }

        now = datetime.now(timezone.utc)
        findings_added = 0

        for user in users:
            username = user["UserName"]
            user_arn = user["Arn"]
            worst = None
            print(f"\n--- Scanning user: {username} ---")

            # ── CHECK 1: MFA not enabled (HIGH) ──────────────────────────────
            try:
                mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                print(f"  MFA devices: {len(mfa_devices)}")
                if not mfa_devices:
                    worst = pick_worst(worst, "HIGH", "8.5",
                        "IAM user does not have MFA enabled",
                        "Enable MFA for the IAM user immediately",
                        ["CIS-AWS-1.5", "NIST-IA-2", "ISO27001-A.9.4"])
            except Exception as e:
                print(f"  MFA check error: {e}")

            # ── CHECK 2: AdministratorAccess policy attached (CRITICAL) ───────
            try:
                attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
                policy_names = [p["PolicyName"] for p in attached]
                print(f"  Attached policies: {policy_names}")
                admin_policies = [p for p in policy_names if "Admin" in p or "FullAccess" in p or p == "PowerUserAccess"]
                if admin_policies:
                    worst = pick_worst(worst, "CRITICAL", "10.0",
                        f"IAM user has overly permissive policy attached: {admin_policies[0]}",
                        "Follow least-privilege principle — remove AdministratorAccess and grant only required permissions",
                        ["CIS-AWS-1.16", "NIST-AC-6", "ISO27001-A.9.2"])
            except Exception as e:
                print(f"  Attached policies check error: {e}")

            # ── CHECK 3: Access key older than 90 days (MEDIUM) ───────────────
            try:
                access_keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                print(f"  Access keys: {len(access_keys)}")
                for key in access_keys:
                    if key["Status"] == "Active":
                        age_days = (now - key["CreateDate"]).days
                        print(f"  Key {key['AccessKeyId']} age: {age_days} days")
                        if age_days > 90:
                            worst = pick_worst(worst, "MEDIUM", "6.0",
                                f"IAM access key not rotated in {age_days} days",
                                "Rotate access keys every 90 days as per CIS benchmark",
                                ["CIS-AWS-1.14", "NIST-IA-5", "ISO27001-A.9.2"])
            except Exception as e:
                print(f"  Access key check error: {e}")

            # ── CHECK 4: Console access inactive > 90 days or never used (LOW) 
            try:
                iam.get_login_profile(UserName=username)
                last_used = user.get("PasswordLastUsed")
                if last_used:
                    days_since = (now - last_used).days
                    print(f"  Last login: {days_since} days ago")
                    if days_since > 90:
                        worst = pick_worst(worst, "LOW", "3.0",
                            f"IAM user has not logged in for {days_since} days",
                            "Review and disable or remove inactive IAM users",
                            ["CIS-AWS-1.3", "NIST-AC-2", "ISO27001-A.9.2"])
                else:
                    print(f"  Has console access but never logged in")
                    worst = pick_worst(worst, "LOW", "2.5",
                        "IAM user has console access but has never logged in",
                        "Remove console access for unused IAM users",
                        ["CIS-AWS-1.3", "NIST-AC-2", "ISO27001-A.9.2"])
            except iam.exceptions.NoSuchEntityException:
                print(f"  No console/login profile")
            except Exception as e:
                print(f"  Login profile check error: {e}")

            # ── CHECK 5: Inline policies (LOW) ────────────────────────────────
            try:
                inline = iam.list_user_policies(UserName=username).get("PolicyNames", [])
                print(f"  Inline policies: {inline}")
                if inline:
                    worst = pick_worst(worst, "LOW", "2.5",
                        "IAM user has inline policies attached directly",
                        "Replace inline policies with managed policies for easier auditing",
                        ["CIS-AWS-1.16", "NIST-AC-6", "ISO27001-A.9.4"])
            except Exception as e:
                print(f"  Inline policy check error: {e}")

            print(f"  WORST → {worst}")

            # ── Always write at least a LOW finding so every user appears ─────
            # If all checks pass, flag the user as reviewed-clean with LOW
            if worst is None:
                worst = {
                    "severity": "LOW",
                    "riskScore": "1.0",
                    "title": "IAM user review — no critical issues found",
                    "remediation": "Continue regular IAM access reviews",
                    "complianceFramework": ["CIS-AWS-1.1", "NIST-AC-2"],
                }

            table.put_item(Item={
                "findingId": str(uuid.uuid4()),
                "accountId": account_id,
                "resourceType": "IAM User",
                "resourceId": user_arn,
                "severity": worst["severity"],
                "riskScore": worst["riskScore"],
                "title": worst["title"],
                "status": "OPEN",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "scanner": "IAM",
                "remediation": worst["remediation"],
                "complianceFramework": worst["complianceFramework"],
            })
            findings_added += 1
            print(f"  Saved finding: {worst['severity']} — {worst['title']}")

        print(f"\nIAM scan complete. {findings_added} findings saved.")

        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message": "IAM scan completed",
                "accountId": account_id,
                "usersScanned": len(users),
                "findingsAdded": findings_added,
            })
        }

    except Exception as e:
        print("IAM scan error:", str(e))
        import traceback
        traceback.print_exc()
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"message": "IAM scan failed", "error": str(e)})
        }