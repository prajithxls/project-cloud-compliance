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


def lambda_handler(event, context):

    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    account_id = context.invoked_function_arn.split(":")[4]
    ec2 = boto3.client("ec2")

    try:
        # Delete old EC2 findings
        old_items = table.scan(FilterExpression=Attr("scanner").eq("EC2")).get("Items", [])
        for item in old_items:
            table.delete_item(Key={"findingId": item["findingId"]})

        # Get active instances and their security groups
        running_sg_ids = set()
        instances = []
        reservations = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
        )["Reservations"]

        for r in reservations:
            for instance in r["Instances"]:
                instances.append(instance)
                for sg in instance.get("SecurityGroups", []):
                    running_sg_ids.add(sg["GroupId"])

        print(f"Found {len(instances)} instances, {len(running_sg_ids)} security groups")

        if not running_sg_ids:
            return {
                "statusCode": 200,
                "headers": CORS_HEADERS,
                "body": json.dumps({"message": "EC2 scan completed — no active instances", "accountId": account_id})
            }

        security_groups = ec2.describe_security_groups(GroupIds=list(running_sg_ids))["SecurityGroups"]

        # ── One finding per security group ────────────────────────────────────
        for sg in security_groups:
            sg_id = sg["GroupId"]
            worst = None

            def update_worst(severity, risk, title, remediation):
                nonlocal worst
                if worst is None or SEVERITY_RANK[severity] > SEVERITY_RANK[worst["severity"]]:
                    worst = {"severity": severity, "riskScore": risk, "title": title, "remediation": remediation}

            sensitive_ports = {22, 23, 3389, 3306, 5432, 27017, 6379, 1433}

            # CHECK 1: Inbound rules
            for perm in sg.get("IpPermissions", []):
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        protocol  = perm.get("IpProtocol", "-1")
                        from_port = perm.get("FromPort", 0)
                        to_port   = perm.get("ToPort", 65535)
                        is_all    = protocol == "-1"
                        is_sensitive = from_port in sensitive_ports or to_port in sensitive_ports

                        if is_all or is_sensitive:
                            port_desc = "all ports" if is_all else f"port {from_port}"
                            update_worst("CRITICAL", "9.5",
                                f"Security group allows unrestricted inbound access on {port_desc}",
                                "Restrict inbound rules to specific trusted IP ranges only")
                        else:
                            update_worst("HIGH", "7.5",
                                f"Security group allows inbound 0.0.0.0/0 on port {from_port}-{to_port}",
                                "Restrict inbound rules to specific trusted IP ranges only")

            # CHECK 2: Unrestricted outbound → MEDIUM
            for perm in sg.get("IpPermissionsEgress", []):
                if perm.get("IpProtocol") == "-1":
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            update_worst("MEDIUM", "5.0",
                                "Security group allows unrestricted outbound traffic",
                                "Restrict outbound rules to only required destinations and ports")

            if worst:
                table.put_item(Item={
                    "findingId": str(uuid.uuid4()),
                    "accountId": account_id,
                    "resourceType": "EC2 Security Group",
                    "resourceId": sg_id,
                    "severity": worst["severity"],
                    "riskScore": worst["riskScore"],
                    "title": worst["title"],
                    "status": "OPEN",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "scanner": "EC2",
                    "remediation": worst["remediation"],
                    "complianceFramework": ["CIS-AWS-4.1", "NIST-AC-4", "ISO27001-A.13.1"]
                })

        # ── One finding per instance ──────────────────────────────────────────
        for instance in instances:
            worst = None

            def update_worst(severity, risk, title, remediation):
                nonlocal worst
                if worst is None or SEVERITY_RANK[severity] > SEVERITY_RANK[worst["severity"]]:
                    worst = {"severity": severity, "riskScore": risk, "title": title, "remediation": remediation}

            # CHECK 3: Detailed monitoring → LOW
            if instance.get("Monitoring", {}).get("State") != "enabled":
                update_worst("LOW", "2.0",
                    "EC2 instance does not have detailed monitoring enabled",
                    "Enable detailed monitoring for better visibility and alerting")

            if worst:
                table.put_item(Item={
                    "findingId": str(uuid.uuid4()),
                    "accountId": account_id,
                    "resourceType": "EC2 Instance",
                    "resourceId": instance["InstanceId"],
                    "severity": worst["severity"],
                    "riskScore": worst["riskScore"],
                    "title": worst["title"],
                    "status": "OPEN",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "scanner": "EC2",
                    "remediation": worst["remediation"],
                    "complianceFramework": ["NIST-AU-2", "ISO27001-A.12.4"]
                })

        return {
            "statusCode": 200,
            "headers": CORS_HEADERS,
            "body": json.dumps({
                "message": "EC2 scan completed",
                "accountId": account_id,
                "instancesChecked": len(instances)
            })
        }

    except Exception as e:
        print("EC2 scan error:", str(e))
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"message": "EC2 scan failed", "error": str(e)})
        }