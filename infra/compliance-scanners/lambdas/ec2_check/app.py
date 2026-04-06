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

SEVERITY_RANK    = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SENSITIVE_PORTS  = {22, 23, 3389, 3306, 5432, 1521, 27017, 6379, 9200}


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

    print(f"EC2 Scanner — scanning account: {scan_account}")

    try:
        ec2 = get_client("ec2", target_account, own_account)

        # Delete old EC2 findings
        old_items = table.scan(
            FilterExpression=Attr("scanner").eq("EC2") & Attr("accountId").eq(scan_account)
        ).get("Items", [])
        for item in old_items:
            table.delete_item(Key={"findingId": item["findingId"]})
        print(f"Deleted {len(old_items)} old EC2 findings")

        # Get all running/stopped instances and their security groups
        paginator  = ec2.get_paginator("describe_instances")
        sg_ids_seen = set()
        sg_map      = {}

        for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]):
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    iid = instance["InstanceId"]
                    for sg in instance.get("SecurityGroups", []):
                        sgid = sg["GroupId"]
                        if sgid not in sg_ids_seen:
                            sg_ids_seen.add(sgid)
                            sg_map[sgid] = iid

        print(f"Found {len(sg_ids_seen)} unique security groups")

        # Also check instance-level monitoring
        instance_findings = 0
        for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]):
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    monitoring = instance.get("Monitoring", {}).get("State", "disabled")
                    if monitoring == "disabled":
                        table.put_item(Item={
                            "findingId":   str(uuid.uuid4()),
                            "accountId":   scan_account,
                            "resourceType":"EC2 Instance",
                            "resourceId":  instance["InstanceId"],
                            "severity":    "LOW",
                            "riskScore":   "2.0",
                            "title":       "EC2 instance does not have detailed monitoring enabled",
                            "status":      "OPEN",
                            "timestamp":   datetime.utcnow().isoformat() + "Z",
                            "scanner":     "EC2",
                            "remediation": "Enable detailed monitoring for better visibility into instance metrics.",
                            "complianceFramework": ["CIS-AWS-L1.4", "NIST-AU-2"],
                        })
                        instance_findings += 1

        # Evaluate security groups
        sg_findings = 0
        if sg_ids_seen:
            sg_list = list(sg_ids_seen)
            # Fetch in batches of 200
            all_sgs = []
            for i in range(0, len(sg_list), 200):
                batch = ec2.describe_security_groups(GroupIds=sg_list[i:i+200])
                all_sgs.extend(batch["SecurityGroups"])

            for sg in all_sgs:
                sgid  = sg["GroupId"]
                worst = None

                # ── Inbound rules ─────────────────────────────────────────
                for rule in sg.get("IpPermissions", []):
                    proto      = rule.get("IpProtocol", "")
                    from_port  = rule.get("FromPort", 0)
                    to_port    = rule.get("ToPort", 65535)
                    open_ipv4  = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
                    open_ipv6  = any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []))
                    is_open    = open_ipv4 or open_ipv6

                    if not is_open:
                        continue

                    if proto == "-1":  # all traffic
                        worst = pick_worst(worst, "CRITICAL", "9.5",
                            "Security group allows all inbound traffic from the internet (0.0.0.0/0)",
                            "Remove the unrestricted inbound rule and restrict to specific IPs and ports.",
                            ["CIS-AWS-5.2", "NIST-SC-7", "ISO27001-A.13.1"])
                    else:
                        ports_in_range = set(range(from_port, to_port + 1)) & SENSITIVE_PORTS
                        if ports_in_range:
                            port_str = ", ".join(str(p) for p in sorted(ports_in_range))
                            worst = pick_worst(worst, "CRITICAL", "9.5",
                                f"Security group allows unrestricted internet access on sensitive port(s): {port_str}",
                                f"Restrict inbound access on port(s) {port_str} to specific trusted IP ranges.",
                                ["CIS-AWS-5.2", "NIST-SC-7", "ISO27001-A.13.1"])
                        else:
                            worst = pick_worst(worst, "HIGH", "7.5",
                                f"Security group allows unrestricted internet access on port {from_port}-{to_port}",
                                "Restrict inbound access to specific trusted IP ranges.",
                                ["CIS-AWS-5.3", "NIST-SC-7", "ISO27001-A.13.1"])

                # ── Outbound rules ────────────────────────────────────────
                for rule in sg.get("IpPermissionsEgress", []):
                    proto     = rule.get("IpProtocol", "")
                    open_ipv4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
                    if proto == "-1" and open_ipv4:
                        worst = pick_worst(worst, "MEDIUM", "5.0",
                            "Security group has unrestricted outbound access (0.0.0.0/0)",
                            "Restrict egress rules to only required destinations and ports.",
                            ["CIS-AWS-5.4", "NIST-SC-7", "ISO27001-A.13.1"])

                if worst is None:
                    worst = {
                        "severity": "LOW", "riskScore": "1.0",
                        "title": "EC2 security group review — no critical issues found",
                        "remediation": "Continue regular review of security group rules.",
                        "complianceFramework": ["CIS-AWS-5.1", "NIST-SI-2"],
                    }

                table.put_item(Item={
                    "findingId":          str(uuid.uuid4()),
                    "accountId":          scan_account,
                    "resourceType":       "EC2 Security Group",
                    "resourceId":         sgid,
                    "severity":           worst["severity"],
                    "riskScore":          worst["riskScore"],
                    "title":              worst["title"],
                    "status":             "OPEN",
                    "timestamp":          datetime.utcnow().isoformat() + "Z",
                    "scanner":            "EC2",
                    "remediation":        worst["remediation"],
                    "complianceFramework": worst["complianceFramework"],
                })
                sg_findings += 1

        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message": "EC2 scan complete",
                "accountId": scan_account,
                "securityGroupsScanned": len(sg_ids_seen),
                "findingsAdded": sg_findings + instance_findings,
            }),
        }

    except Exception as e:
        print(f"EC2 scan error: {str(e)}")
        import traceback; traceback.print_exc()
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"message": "EC2 scan failed", "error": str(e)}),
        }