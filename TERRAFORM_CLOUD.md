# Terraform Cloud Configuration Guide

This guide explains how to configure this repository for use with Terraform Cloud.

## Required Configuration

### 1. Terraform Variables (Workspace Variables)

These can be set in Terraform Cloud under **Workspace Settings → Variables → Terraform Variables**:

| Variable Name | Type | Default | Description | Required |
|--------------|------|---------|------------|----------|
| `aws_region` | string | `us-east-1` | AWS region where resources will be deployed | No (has default) |
| `instance_type` | string | `t2.micro` | EC2 instance type (must be free tier eligible) | No (has default) |

**Note**: Both variables have defaults, so they're optional. However, you may want to set them explicitly in Terraform Cloud.

### 2. AWS Credentials (Environment Variables)

**CRITICAL**: You must configure AWS credentials in Terraform Cloud for the workspace to authenticate with AWS.

Set these in **Workspace Settings → Variables → Environment Variables**:

| Variable Name | Type | Description | Required |
|--------------|------|-------------|----------|
| `AWS_ACCESS_KEY_ID` | Environment | AWS Access Key ID | **Yes** |
| `AWS_SECRET_ACCESS_KEY` | Environment | AWS Secret Access Key | **Yes** |
| `AWS_SESSION_TOKEN` | Environment | AWS Session Token (if using temporary credentials) | No |
| `AWS_DEFAULT_REGION` | Environment | Default AWS region (optional, can use `aws_region` variable) | No |

**Security Best Practices for Credentials:**
- ✅ Mark `AWS_SECRET_ACCESS_KEY` as **Sensitive** (hidden in UI)
- ✅ Mark `AWS_SESSION_TOKEN` as **Sensitive** if used
- ✅ Use IAM user with minimal required permissions (not root account)
- ✅ Enable MFA on the IAM user
- ✅ Rotate credentials regularly
- ✅ Use separate AWS account for testing (sandbox account)

### 3. Terraform Cloud Workspace Settings

#### General Settings
- **Execution Mode**: Remote (recommended) or Local
- **Terraform Version**: `>= 1.0` (latest stable recommended)
- **Working Directory**: Leave empty (root of repository)

#### Version Control
- Connect to your GitHub repository
- **VCS Branch**: `main` (or your default branch)
- **Auto-apply**: **DISABLED** (recommended for security demos)
- **Auto-destroy**: **DISABLED**

#### Run Triggers
- Configure as needed (e.g., trigger on push to main branch)

#### Notifications
- Set up notifications for run failures (optional but recommended)

## Step-by-Step Setup

### 1. Create a New Workspace

1. Log into Terraform Cloud
2. Click **"New workspace"**
3. Select **"Version control workflow"** (if using GitHub/GitLab)
4. Connect to your repository: `jtb75/pub-repo`
5. Configure workspace:
   - **Workspace name**: `insecure-aws-demo` (or your choice)
   - **Description**: "Security anti-patterns demonstration - DO NOT USE IN PRODUCTION"

### 2. Configure AWS Credentials

1. Go to **Workspace Settings → Variables**
2. Click **"+ Add variable"**
3. Add environment variables:
   - **Key**: `AWS_ACCESS_KEY_ID`
   - **Value**: Your AWS Access Key ID
   - **Sensitive**: No
   - **Category**: Environment variable
   
   - **Key**: `AWS_SECRET_ACCESS_KEY`
   - **Value**: Your AWS Secret Access Key
   - **Sensitive**: **Yes** (check this box!)
   - **Category**: Environment variable

### 3. Configure Terraform Variables (Optional)

If you want to override defaults:

1. In the same Variables page, add Terraform variables:
   - **Key**: `aws_region`
   - **Value**: `us-east-1` (or your preferred region)
   - **Sensitive**: No
   - **Category**: Terraform variable
   
   - **Key**: `instance_type`
   - **Value**: `t2.micro`
   - **Sensitive**: No
   - **Category**: Terraform variable

### 4. Configure Workspace Settings

1. Go to **Workspace Settings → General Settings**
2. Set **Terraform Version**: Latest (e.g., `1.6.0`)
3. **Auto-apply**: **OFF** (manual approval required)
4. **Auto-destroy**: **OFF**

### 5. Run Initial Plan

1. Go to **Runs** tab
2. Click **"Queue plan manually"**
3. Review the plan output
4. **DO NOT APPLY** unless you're in a sandbox AWS account

## AWS IAM Permissions Required

The IAM user/role used by Terraform Cloud needs the following permissions:

### Minimum Required Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*",
        "s3:*",
        "iam:*",
        "lambda:*",
        "apigateway:*",
        "logs:*",
        "vpc:*",
        "cloudwatch:*"
      ],
      "Resource": "*"
    }
  ]
}
```

**⚠️ WARNING**: This is overly permissive for demonstration purposes. In production, use least-privilege policies.

### Recommended IAM Policy (More Restrictive)

For better security, create a policy that only allows the specific actions needed:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "ec2:Create*",
        "ec2:Delete*",
        "ec2:Modify*",
        "ec2:StartInstances",
        "ec2:StopInstances",
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:PutBucket*",
        "s3:GetBucket*",
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
        "iam:PutUserPolicy",
        "iam:DeleteUserPolicy",
        "lambda:CreateFunction",
        "lambda:DeleteFunction",
        "lambda:UpdateFunction*",
        "lambda:AddPermission",
        "lambda:RemovePermission",
        "apigateway:*",
        "logs:CreateLogGroup",
        "logs:DeleteLogGroup",
        "logs:PutRetentionPolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

## Cost Considerations

**IMPORTANT**: Even though resources use free tier, monitor costs:

1. Set up **AWS Billing Alerts** in your AWS account
2. Set a budget alert (e.g., $10) to catch unexpected charges
3. Review Terraform Cloud run costs (if on paid plan)
4. Destroy resources immediately after testing

## Security Scanning

Terraform Cloud includes **Sentinel** policy as code and can integrate with security scanning tools:

1. **Sentinel Policies**: Create policies to prevent certain resource types
2. **Cost Estimation**: Review cost estimates before applying
3. **Security Scanning**: Integrate with tools like Checkov, TFLint, or tfsec

## Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify AWS credentials are set correctly
   - Check that credentials have necessary permissions
   - Ensure credentials are not expired

2. **Region Issues**
   - Verify the region supports all services (some services aren't available in all regions)
   - Check that `aws_region` variable matches your AWS account settings

3. **Lambda Deployment Issues**
   - Ensure the Lambda zip file is created (archive provider)
   - Check that Python runtime is available in your region

4. **S3 Bucket Name Conflicts**
   - S3 bucket names must be globally unique
   - If conflicts occur, the random suffix should handle it, but you may need to retry

## Best Practices for This Demo

1. ✅ Use a **sandbox AWS account** (not production)
2. ✅ Set **auto-apply to OFF** (manual approval)
3. ✅ Review plans carefully before applying
4. ✅ **Destroy immediately** after reviewing
5. ✅ Use **separate workspace** for each test run
6. ✅ Monitor AWS billing dashboard
7. ✅ Set up **billing alerts** in AWS

## Next Steps

1. Create workspace in Terraform Cloud
2. Configure AWS credentials
3. Queue a plan to verify configuration
4. Review the plan output
5. Apply only in sandbox environment
6. Review created resources
7. **Destroy immediately** after review

---

**Remember**: This is a security anti-patterns demonstration. Never deploy to production!

