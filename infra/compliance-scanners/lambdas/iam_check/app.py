import json
import boto3
import uuid
import os
from datetime import datetime, timezone
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
    if not target_account or target_account == own_account:
        return boto3.client(service)
    sts   = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=f"arn:aws:iam::{target_account}:role/CrossAccountComplianceRole",
        RoleSessionName="ComplianceAuditSession"
    )["Credentials"]
    return boto3.client(service,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )


def pick_worst(current, severity, risk, title, remediation, frameworks):
    if current is None or SEVERITY_RANK[severity] > SEVERITY_RANK[current["severity"]]:
        return {"severity": severity, "riskScore": risk, "title": title,
                "remediation": remediation, "complianceFramework": frameworks}
    return current


def lambda_handler(event, context):

    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    own_account    = context.invoked_function_arn.split(":")[4]
    target_account = event.get("accountId", "").strip()
    scan_account   = target_account if target_account and target_account != own_account else own_account

    print(f"IAM Scanner — scanning account: {scan_account}")

    try:
        iam = get_client("iam", target_account, own_account)

        # Delete old IAM findings
        old_items = table.scan(
            FilterExpression=Attr("scanner").eq("IAM") & Attr("accountId").eq(scan_account)
        ).get("Items", [])
        for item in old_items:
            table.delete_item(Key={"findingId": item["findingId"]})
        print(f"Deleted {len(old_items)} old IAM findings")

        # List all users
        users = []
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            users.extend(page["Users"])
        print(f"Found {len(users)} IAM users")

        findings_added = 0

        for user in users:
            username = user["UserName"]
            user_arn = user["Arn"]
            worst    = None

            print(f"\n--- Scanning user: {username} ---")

            # ── CHECK 1: Admin / FullAccess policies ──────────────────────
            try:
                attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
                policy_names = [p["PolicyName"] for p in attached]
                print(f"  Policies: {policy_names}")

                if "AdministratorAccess" in policy_names:
                    worst = pick_worst(worst, "CRITICAL", "10.0",
                        f"IAM user has AdministratorAccess — full AWS account access",
                        "Remove AdministratorAccess and replace with least-privilege policies.",
                        ["CIS-AWS-1.16", "NIST-AC-6", "ISO27001-A.9.2"])
                elif any("FullAccess" in p or "PowerUserAccess" in p for p in policy_names):
                    match = next((p for p in policy_names if "FullAccess" in p or "PowerUserAccess" in p), "")
                    worst = pick_worst(worst, "HIGH", "8.5",
                        f"IAM user has overly permissive policy: {match}",
                        "Replace broad policy with least-privilege permissions scoped to required actions.",
                        ["CIS-AWS-1.16", "NIST-AC-6", "ISO27001-A.9.2"])
            except Exception as e:
                print(f"  Policy check error: {e}")

            # ── CHECK 2: MFA ───────────────────────────────────────────────
            try:
                mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
                has_console = True
                try:
                    iam.get_login_profile(UserName=username)
                except iam.exceptions.NoSuchEntityException:
                    has_console = False

                if has_console and not mfa_devices:
                    worst = pick_worst(worst, "HIGH", "8.5",
                        "IAM user does not have MFA enabled",
                        "Enable MFA for this user to protect against credential compromise.",
                        ["CIS-AWS-1.10", "NIST-IA-5", "ISO27001-A.9.4"])
            except Exception as e:
                print(f"  MFA check error: {e}")

            # ── CHECK 3: Access key rotation ───────────────────────────────
            try:
                keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                now  = datetime.now(timezone.utc)
                for key in keys:
                    if key["Status"] == "Active":
                        age_days = (now - key["CreateDate"]).days
                        print(f"  Key {key['AccessKeyId']} age: {age_days} days")
                        if age_days > 90:
                            worst = pick_worst(worst, "MEDIUM", "6.0",
                                f"IAM user access key has not been rotated in {age_days} days",
                                "Rotate access keys every 90 days to reduce risk of credential exposure.",
                                ["CIS-AWS-1.14", "NIST-IA-5", "ISO27001-A.9.4"])
            except Exception as e:
                print(f"  Key rotation check error: {e}")

            # ── CHECK 4: User inactivity ───────────────────────────────────
            try:
                pwd_last_used = user.get("PasswordLastUsed")
                if pwd_last_used:
                    now      = datetime.now(timezone.utc)
                    inactive = (now - pwd_last_used).days
                    if inactive > 90:
                        worst = pick_worst(worst, "LOW", "3.0",
                            f"IAM user has been inactive for {inactive} days",
                            "Disable or remove inactive users to reduce attack surface.",
                            ["CIS-AWS-1.12", "NIST-AC-2", "ISO27001-A.9.2"])
            except Exception as e:
                print(f"  Inactivity check error: {e}")

            # ── CHECK 5: Inline policies ────────────────────────────────────
            try:
                inline = iam.list_user_policies(UserName=username).get("PolicyNames", [])
                if inline:
                    worst = pick_worst(worst, "LOW", "2.5",
                        f"IAM user has {len(inline)} inline policy/policies attached",
                        "Replace inline policies with managed policies for better governance.",
                        ["CIS-AWS-1.16", "NIST-AC-6", "ISO27001-A.9.2"])
            except Exception as e:
                print(f"  Inline policy check error: {e}")

            # Fallback
            if worst is None:
                worst = {
                    "severity": "LOW", "riskScore": "1.0",
                    "title": "IAM user review — no critical issues found",
                    "remediation": "Continue regular review of IAM user permissions.",
                    "complianceFramework": ["CIS-AWS-1.1", "NIST-SI-2"],
                }

            table.put_item(Item={
                "findingId":          str(uuid.uuid4()),
                "accountId":          scan_account,
                "resourceType":       "IAM User",
                "resourceId":         user_arn,
                "severity":           worst["severity"],
                "riskScore":          worst["riskScore"],
                "title":              worst["title"],
                "status":             "OPEN",
                "timestamp":          datetime.utcnow().isoformat() + "Z",
                "scanner":            "IAM",
                "remediation":        worst["remediation"],
                "complianceFramework": worst["complianceFramework"],
            })
            findings_added += 1
            print(f"  WORST → {worst['severity']} — {worst['title']}")

        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message": "IAM scan complete",
                "accountId": scan_account,
                "usersScanned": len(users),
                "findingsAdded": findings_added,
            }),
        }

    except Exception as e:
        print(f"IAM scan error: {str(e)}")
        import traceback; traceback.print_exc()
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"message": "IAM scan failed", "error": str(e)}),
        }