output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "public_subnet_id" {
  description = "Public subnet ID"
  value       = aws_subnet.public.id
}

output "internet_gateway_id" {
  description = "Internet Gateway ID"
  value       = aws_internet_gateway.main.id
}

output "security_group_id" {
  description = "Wide-open security group ID"
  value       = aws_security_group.wide_open.id
}

output "ec2_instances" {
  description = "EC2 instance details (instances are stopped by default)"
  value = {
    for idx, instance in aws_instance.insecure_instances : instance.tags.Name => {
      id                      = instance.id
      public_ip               = instance.public_ip
      private_ip              = instance.private_ip
      state                   = "stopped"
      contains_sensitive_data = idx < 3 ? "YES - Contains fake credit cards, SSNs, PII, and secrets" : "No"
      has_iam_role            = idx >= 3 ? "YES - Has IAM role with S3 access to PHI buckets" : "No"
      iam_role_name           = idx >= 3 ? aws_iam_role.phi_access_role.name : null
    }
  }
}

output "sensitive_data_locations" {
  description = "Locations of fake sensitive data on instances (first 3 instances only)"
  value = {
    note = "The first 3 EC2 instances contain fake sensitive data in the following locations:"
    locations = [
      "/tmp/data/credit_cards.txt - 12+ fake credit card numbers",
      "/tmp/data/ssn_data.txt - 10 fake Social Security Numbers",
      "/tmp/data/pii_data.txt - 10 fake PII records",
      "/tmp/data/database_dump.sql - Fake database dump with credentials",
      "/home/ec2-user/secrets/api_keys.txt - Fake API keys and secrets",
      "/var/www/html/config.php - Hardcoded credentials in config file"
    ]
    warning = "All files have world-readable permissions (644) - DO NOT DO THIS IN PRODUCTION!"
  }
}

output "s3_buckets" {
  description = "Publicly exposed S3 bucket names"
  value = {
    for idx, bucket in aws_s3_bucket.public_buckets : bucket.tags.Name => {
      name = bucket.id
      arn  = bucket.arn
    }
  }
}

output "phi_s3_buckets" {
  description = "Private S3 buckets containing fake PHI data (accessible by instances 3 and 4)"
  value = {
    for idx, bucket in aws_s3_bucket.phi_buckets : bucket.tags.Name => {
      name = bucket.id
      arn  = bucket.arn
      note = "Contains fake PHI data - accessible via IAM role on instances 3 and 4"
    }
  }
}

output "iam_role_info" {
  description = "IAM role information for PHI bucket access"
  value = {
    role_name   = aws_iam_role.phi_access_role.name
    role_arn    = aws_iam_role.phi_access_role.arn
    attached_to = "EC2 instances 3 and 4 (indices 3 and 4)"
    permissions = "Full S3 access (GetObject, PutObject, DeleteObject, ListBucket) on all 5 PHI buckets"
    warning     = "Overly permissive IAM policy - violates least privilege principle"
  }
}

output "iam_users" {
  description = "IAM users with admin access (BAD: Overly permissive)"
  value = {
    for idx, user in aws_iam_user.admin_users : user.name => {
      arn           = user.arn
      access_key_id = aws_iam_access_key.admin_keys[idx].id
      warning       = "User has AdministratorAccess policy attached - VERY BAD!"
    }
  }
}

output "lambda_function" {
  description = "Lambda function with security issues"
  value = {
    function_name = aws_lambda_function.insecure_lambda.function_name
    arn           = aws_lambda_function.insecure_lambda.arn
    role_arn      = aws_iam_role.lambda_role.arn
    warning       = "Lambda has secrets in environment variables and overly permissive IAM role"
  }
}

output "api_gateway" {
  description = "API Gateway with no authentication"
  value = {
    api_id     = aws_api_gateway_rest_api.insecure_api.id
    api_url    = "https://${aws_api_gateway_rest_api.insecure_api.id}.execute-api.${var.aws_region}.amazonaws.com/${aws_api_gateway_stage.insecure_api_stage.stage_name}"
    stage_name = aws_api_gateway_stage.insecure_api_stage.stage_name
    warning    = "API Gateway has NO authentication - anyone can call it!"
  }
}

output "cloudwatch_logs" {
  description = "CloudWatch Log Groups (no encryption, no retention)"
  value = {
    lambda_log_group = aws_cloudwatch_log_group.insecure_logs.name
    api_log_group    = aws_cloudwatch_log_group.api_gateway_logs.name
    warning          = "Log groups have no retention policy and may contain sensitive data"
  }
}

output "missing_security_features" {
  description = "Security features that are NOT enabled (anti-patterns)"
  value = {
    cloudtrail_enabled = "NO - CloudTrail should be enabled for audit logging"
    vpc_flow_logs      = "NO - VPC Flow Logs should be enabled for network monitoring"
    mfa_required       = "NO - MFA should be required for admin users"
    key_rotation       = "NO - Access keys should be rotated regularly"
    waf_enabled        = "NO - WAF should be attached to API Gateway"
    rate_limiting      = "NO - API Gateway should have rate limiting"
  }
}

output "bedrock_agent" {
  description = "Bedrock Agent with security anti-patterns"
  value = {
    agent_id    = aws_bedrockagent_agent.insecure_agent.agent_id
    agent_name  = aws_bedrockagent_agent.insecure_agent.agent_name
    agent_arn   = aws_bedrockagent_agent.insecure_agent.agent_arn
    alias_id    = aws_bedrockagent_agent_alias.insecure_agent_alias.agent_alias_id
    alias_name  = aws_bedrockagent_agent_alias.insecure_agent_alias.agent_alias_name
    model       = "anthropic.claude-3-haiku-20240307-v1:0"
    role_arn    = aws_iam_role.bedrock_agent_role.arn
    action_lambda = aws_lambda_function.bedrock_action_lambda.function_name
    warnings = [
      "No guardrails configured - agent can generate harmful content",
      "Overly permissive IAM role with wildcard permissions",
      "Agent instructions encourage unsafe behavior",
      "Action group Lambda has secrets in environment variables",
      "No input/output validation or filtering"
    ]
  }
}

output "bedrock_training_pipeline" {
  description = "Bedrock training data pipeline with security anti-patterns (infrastructure only - no actual training)"
  value = {
    training_data_bucket = aws_s3_bucket.bedrock_training_data.id
    training_data_arn    = aws_s3_bucket.bedrock_training_data.arn
    model_output_bucket  = aws_s3_bucket.bedrock_model_output.id
    model_output_arn     = aws_s3_bucket.bedrock_model_output.arn
    training_role_arn    = aws_iam_role.bedrock_training_role.arn
    training_data_files = [
      "training-data/customer_interactions.jsonl - Contains fake PII (SSNs, credit cards, emails)",
      "training-data/internal_procedures.jsonl - Contains fake internal system info and credentials"
    ]
    warnings = [
      "Training data bucket has no encryption",
      "Training data contains PII that would be learned by the model",
      "Training data contains internal system information and credentials",
      "Model output bucket allows deletion by any principal in account",
      "Training IAM role has wildcard permissions on all S3 and Bedrock resources",
      "No data classification or governance controls"
    ]
  }
}

output "bedrock_missing_security_features" {
  description = "Security features NOT enabled for Bedrock resources (anti-patterns)"
  value = {
    guardrails           = "NO - Bedrock Guardrails should filter harmful content"
    model_invocation_logging = "NO - Should log all model invocations for audit"
    vpc_endpoint         = "NO - Traffic goes over public internet instead of VPC"
    kms_encryption       = "NO - Training data and model artifacts should be encrypted"
    data_classification  = "NO - Training data should be classified and sanitized"
    pii_detection        = "NO - Should detect and redact PII before training"
    prompt_injection_protection = "NO - Agent vulnerable to prompt injection attacks"
  }
}

output "warning" {
  description = "SECURITY WARNING"
  value       = "⚠️  THIS DEPLOYMENT CONTAINS NUMEROUS SECURITY VULNERABILITIES. DO NOT USE IN PRODUCTION!"
}

