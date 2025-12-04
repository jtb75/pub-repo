# ⚠️ SECURITY ANTI-PATTERNS DEMONSTRATION

**🚨 WARNING: This Terraform configuration is intentionally insecure and demonstrates security anti-patterns. DO NOT deploy this in any production environment or with real AWS credentials that have access to production resources.**

## Purpose

This repository serves as an educational example of **what NOT to do** when deploying AWS infrastructure. It demonstrates common security vulnerabilities and misconfigurations that could lead to:

- Data breaches
- Unauthorized access
- Data exfiltration
- Compliance violations
- Financial losses

## Security Issues Demonstrated

### 1. Network Security Issues

- **Wide-open VPC**: No proper network segmentation
- **Public subnet with auto-assign public IPs**: All instances get public IPs automatically
- **Unrestricted Internet Gateway**: Full internet access without controls
- **No private subnets**: Everything is exposed to the internet

### 2. EC2 Instance Security Issues

- **IMDSv1 enabled**: All 5 instances use IMDSv1 (`http_tokens = "optional"`), which is vulnerable to SSRF attacks
- **Wide-open security group**: Security group allows ALL traffic (0.0.0.0/0) on ALL ports and protocols
- **Public IP addresses**: All instances are directly accessible from the internet (instances are stopped by default but can be started)
- **No encryption**: No mention of encryption at rest or in transit
- **Random naming**: Makes it harder to track and manage resources
- **Instances are stopped**: While instances are configured to be stopped after creation, they remain vulnerable if started
- **Exposed sensitive data**: First 3 instances contain fake sensitive data files including:
  - **12+ fake credit card numbers** with CVV codes stored in `/tmp/data/credit_cards.txt`
  - **10 fake Social Security Numbers** with names and DOBs in `/tmp/data/ssn_data.txt`
  - **10 fake PII records** (names, DOBs, emails, phones, addresses) in `/tmp/data/pii_data.txt`
  - **Fake API keys and secrets** (AWS keys, database passwords, JWT secrets, etc.) in `/home/ec2-user/secrets/api_keys.txt`
  - **Fake database dumps** with hardcoded credentials in `/tmp/data/database_dump.sql`
  - **Hardcoded credentials** in web config files (`/var/www/html/config.php`)
  - **World-readable permissions** (644) on all sensitive files
  - **Sensitive data logged** to syslog

### 3. S3 Bucket Security Issues

- **Public read/write access**: All 10 buckets allow public read and write operations
- **Public access block disabled**: `block_public_acls = false`, `block_public_policy = false`
- **Public ACLs**: Buckets use `public-read-write` ACL
- **Public bucket policies**: Policies allow `*` (anyone) to read, list, and write objects
- **No encryption**: No server-side encryption configured
- **No versioning**: No protection against accidental deletion or overwrites
- **No logging**: No access logging enabled

### 3b. PHI S3 Bucket Security Issues (5 Private Buckets)

- **PHI data storage**: 5 private S3 buckets contain fake Protected Health Information (PHI)
- **Overly permissive IAM roles**: Instances 3 and 4 have IAM roles with full S3 access to all 5 PHI buckets
- **No encryption**: PHI buckets have no server-side encryption (violates HIPAA requirements)
- **No versioning**: No protection against accidental deletion or overwrites of PHI data
- **No access logging**: No CloudTrail or S3 access logging to track who accesses PHI
- **No MFA delete**: No protection against accidental deletion
- **No lifecycle policies**: No data retention or archival policies
- **Broad IAM permissions**: IAM policy allows GetObject, PutObject, DeleteObject, ListBucket on all PHI buckets
- **PHI data includes**: Patient records with SSNs, medical record numbers, diagnoses, medications, lab results, insurance information

### 4. IAM and Access Control Issues

- **Overly permissive IAM roles**: Instances 3 and 4 have IAM roles with full S3 access to PHI buckets
- **No least privilege**: IAM policies grant more permissions than necessary
- **No IAM roles on instances 0-2**: First 3 instances have no IAM roles (use default instance profiles)
- **No condition keys**: IAM policies don't restrict access by IP, time, or other conditions
- **No MFA requirements**: No multi-factor authentication required for sensitive operations

### 5. General Security Issues

- **No monitoring**: No CloudWatch alarms or logging
- **No compliance controls**: No guardrails or policy enforcement
- **No data classification**: No tagging or classification of sensitive data
- **No audit trails**: No comprehensive logging of access to sensitive data

## What This Could Lead To

1. **Data Breaches**: Public S3 buckets and exposed EC2 instances could expose sensitive data
2. **PII/PCI-DSS Violations**: Exposed credit card numbers, SSNs, and PII in world-readable files
3. **HIPAA Violations**: PHI stored in S3 buckets without encryption, proper access controls, or audit logging
4. **Credential Theft**: Hardcoded API keys, passwords, and secrets in accessible files
5. **SSRF Attacks**: IMDSv1 allows attackers to retrieve instance metadata and credentials
6. **DDoS Attacks**: Wide-open security groups make instances vulnerable
7. **Unauthorized Access**: No network segmentation allows lateral movement
8. **Compliance Violations**: GDPR, HIPAA, PCI-DSS violations from exposed sensitive data
9. **Financial Impact**: Unauthorized resource usage, data exfiltration costs, potential fines (HIPAA fines up to $1.5M per violation)
10. **Identity Theft**: Exposed SSNs and PII could be used for identity theft
11. **Account Takeover**: Stolen API keys and credentials could lead to full account compromise
12. **PHI Exposure**: If instances 3-4 are compromised, attackers can access all PHI buckets via IAM role

## How to Use This (For Educational Purposes Only)

1. **Use a sandbox AWS account** with no production resources
2. **Use AWS Free Tier** if possible to minimize costs
3. **Set up billing alerts** to monitor unexpected charges
4. **Destroy immediately** after reviewing the configuration
5. **Never commit real credentials** to this repository

## Deployment

```bash
# Initialize Terraform
terraform init

# Review the plan (DO NOT apply to production!)
terraform plan

# Apply (ONLY in a sandbox environment)
terraform apply

# Destroy immediately after review
terraform destroy
```

## Proper Security Practices (What You SHOULD Do)

### EC2 Instances
- ✅ Use IMDSv2 only (`http_tokens = "required"`)
- ✅ Use least-privilege security groups
- ✅ Place instances in private subnets
- ✅ Use NAT Gateway for outbound internet access
- ✅ Use IAM roles with minimal permissions
- ✅ Enable encryption at rest and in transit
- ✅ Use Systems Manager Session Manager instead of SSH
- ✅ **Never store sensitive data in plain text files**
- ✅ Use AWS Secrets Manager or Parameter Store for secrets
- ✅ Use proper file permissions (600 for sensitive files, never 644)
- ✅ Encrypt sensitive data at rest
- ✅ Don't log sensitive data to syslog or application logs
- ✅ Use environment variables or secure configuration management
- ✅ Implement data loss prevention (DLP) tools

### S3 Buckets
- ✅ Enable public access block by default
- ✅ Use bucket policies with specific principals
- ✅ Enable server-side encryption (SSE-S3 or SSE-KMS) - **REQUIRED for PHI/HIPAA**
- ✅ Enable versioning for critical data
- ✅ Enable access logging (CloudTrail and S3 access logs)
- ✅ Use least-privilege IAM policies
- ✅ Enable MFA delete for critical buckets
- ✅ Use bucket policies with IP restrictions and condition keys
- ✅ Implement lifecycle policies for data retention
- ✅ Use separate buckets for different data classifications
- ✅ Enable S3 Object Lock for compliance requirements
- ✅ For PHI: Implement encryption at rest AND in transit, audit logging, access controls

### Network
- ✅ Use private subnets for compute resources
- ✅ Implement network ACLs
- ✅ Use VPC Flow Logs
- ✅ Implement proper network segmentation
- ✅ Use security groups with specific rules
- ✅ Use WAF for web-facing resources

### IAM and Access Control
- ✅ Use least-privilege IAM policies
- ✅ Implement condition keys (IP restrictions, time-based access)
- ✅ Use separate IAM roles for different workloads
- ✅ Enable MFA for sensitive operations
- ✅ Regularly audit IAM permissions
- ✅ Use IAM Access Analyzer to identify over-permissive policies
- ✅ Implement just-in-time access for sensitive resources

## Disclaimer

This configuration is provided for educational purposes only. The authors and contributors are not responsible for any security incidents, data breaches, or financial losses resulting from the use (intentional or accidental) of this configuration in any environment.

**USE AT YOUR OWN RISK. DO NOT DEPLOY TO PRODUCTION.**

