import json
import boto3
import os

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
}

lambda_client = boto3.client("lambda")

S3_FN     = os.environ.get("S3_SCANNER_FUNCTION",     "compliance-scanners-dev-s3Scanner")
EC2_FN    = os.environ.get("EC2_SCANNER_FUNCTION",    "compliance-scanners-dev-ec2Scanner")
IAM_FN    = os.environ.get("IAM_SCANNER_FUNCTION",    "compliance-scanners-dev-iamScanner")
LAMBDA_FN = os.environ.get("LAMBDA_SCANNER_FUNCTION", "compliance-scanners-dev-lambdaScanner")


def lambda_handler(event, context):

    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    results = {}
    errors  = {}

    for name, fn in [("s3", S3_FN), ("ec2", EC2_FN), ("iam", IAM_FN), ("lambda", LAMBDA_FN)]:
        try:
            response = lambda_client.invoke(
                FunctionName=fn,
                InvocationType="RequestResponse",
                Payload=json.dumps({}),
            )
            result = json.loads(response["Payload"].read())
            body = result.get("body", "{}")
            results[name] = json.loads(body) if isinstance(body, str) else body
        except Exception as e:
            print(f"{name} invocation error: {str(e)}")
            errors[name] = str(e)

    return {
        "statusCode": 200 if not errors else 207,
        "headers": CORS_HEADERS,
        "body": json.dumps({
            "message": "Scan complete" if not errors else "Scan completed with errors",
            "results": results,
            "errors": errors,
        }),
    }