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
  description = "Wide-open security group ID (used by instances 1-3)"
  value       = aws_security_group.wide_open.id
}

output "restricted_security_group_id" {
  description = "Restricted security group ID (used by instances 4-5 - for drift demo)"
  value       = aws_security_group.restricted.id
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
      has_mcp_package         = idx >= 3 ? "YES - Python MCP package (pkg:python/mcp) installed" : "No"
      iam_role_name           = idx >= 3 ? aws_iam_role.phi_access_role.name : null
      security_group          = idx >= 3 ? "restricted (SSH only from 10.0.0.0/8) - drift demo target" : "wide-open (0.0.0.0/0 all ports) - BAD"
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

output "agent_invoker_lambda" {
  description = "Lambda that invokes Bedrock Agent (publicly accessible)"
  value = {
    function_name = aws_lambda_function.agent_invoker.function_name
    function_url  = aws_lambda_function_url.agent_invoker_url.function_url
    arn           = aws_lambda_function.agent_invoker.arn
    role_arn      = aws_iam_role.agent_invoker_role.arn
    agent_id      = aws_bedrockagent_agent.insecure_agent.agent_id
    agent_alias   = aws_bedrockagent_agent_alias.insecure_agent_alias.agent_alias_id
    usage_example = "curl -X POST <function_url> -H 'Content-Type: application/json' -d '{\"input\": \"Hello\", \"session_id\": \"test\"}'"
    warnings = [
      "Lambda function URL is PUBLIC - no authentication",
      "No input validation - vulnerable to prompt injection",
      "User-controlled session_id - session hijacking possible",
      "Debug logging enabled - sensitive data in CloudWatch",
      "Overly permissive IAM role (bedrock:*)",
      "Open CORS policy (Access-Control-Allow-Origin: *)",
      "Exposes agent_id in error responses"
    ]
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

output "bedrock_flow" {
  description = "Bedrock Flow with security anti-patterns"
  value = {
    flow_id        = aws_bedrockagent_flow.insecure_flow.id
    flow_name      = aws_bedrockagent_flow.insecure_flow.name
    flow_arn       = aws_bedrockagent_flow.insecure_flow.arn
    flow_status    = aws_bedrockagent_flow.insecure_flow.status
    flow_version   = aws_bedrockagent_flow.insecure_flow.version
    role_arn       = aws_iam_role.bedrock_flow_role.arn
    nodes = [
      "FlowInputNode - Accepts any input without validation",
      "UnsafePrompt - Prompt with no safety guidelines, encourages bypassing restrictions",
      "FlowOutputNode - Returns output without filtering"
    ]
    warnings = [
      "No guardrails configured - flow can process harmful content",
      "No input validation - vulnerable to prompt injection",
      "Overly permissive IAM role with wildcard permissions",
      "No encryption at rest for flow data",
      "Uses DRAFT version directly - no immutable versioning",
      "Prompt explicitly discourages safety refusals",
      "High temperature (1.0) increases output unpredictability",
      "Can access secrets via IAM role (secretsmanager, ssm)"
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
      "training-data/internal_procedures.jsonl - Contains fake internal system info and credentials",
      "training-data/ssn_records.jsonl - Contains fake SSN records with linked PII",
      "training-data/payment_records.jsonl - Contains fake PCI credit card data with CVVs"
    ]
    warnings = [
      "Training data bucket has no encryption",
      "Training data contains PII that would be learned by the model",
      "Training data contains internal system information and credentials",
      "Training data contains full SSNs linked to personal information",
      "Training data contains full credit card numbers with CVVs (PCI-DSS violation)",
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

output "mcp_server" {
  description = "Insecure MCP Server on EC2 with S3 access and Ollama LLM"
  value = {
    instance_id   = aws_instance.mcp_server.id
    public_ip     = aws_instance.mcp_server.public_ip
    public_dns    = aws_instance.mcp_server.public_dns
    mcp_endpoint  = "http://${aws_instance.mcp_server.public_ip}:8080"
    sse_endpoint  = "http://${aws_instance.mcp_server.public_ip}:8080/sse"
    health_check  = "http://${aws_instance.mcp_server.public_ip}:8080/health"
    ollama_endpoint = "http://${aws_instance.mcp_server.public_ip}:11434"
    ollama_api      = "http://${aws_instance.mcp_server.public_ip}:11434/api/generate"
    ollama_models   = "http://${aws_instance.mcp_server.public_ip}:11434/api/tags"
    iam_role      = aws_iam_role.mcp_server_role.name
    s3_access     = aws_s3_bucket.bedrock_training_data.id
    tools = [
      "list_s3_buckets - List all S3 buckets",
      "list_s3_objects - List objects in bucket",
      "read_s3_object - Read any S3 object (includes PII/PCI data)",
      "write_s3_object - Write to S3 without validation",
      "execute_command - Run arbitrary shell commands",
      "read_file - Read any file on the system",
      "get_instance_metadata - Get EC2 metadata including IAM credentials"
    ]
    ollama = {
      model    = "tinyllama"
      port     = 11434
      warnings = [
        "Ollama LLM is publicly exposed on port 11434",
        "NO AUTHENTICATION - anyone can generate text",
        "OLLAMA_ORIGINS=* allows any origin",
        "Can be used for prompt injection attacks",
        "Resource exhaustion via repeated requests"
      ]
    }
    warnings = [
      "MCP server is publicly exposed on port 8080",
      "Ollama LLM is publicly exposed on port 11434",
      "NO AUTHENTICATION required to connect",
      "Has access to S3 bucket with fake PII/PCI training data",
      "Allows arbitrary command execution",
      "Exposes instance IAM credentials via metadata",
      "IMDSv1 enabled - vulnerable to SSRF",
      "Running as root"
    ]
  }
}

output "warning" {
  description = "SECURITY WARNING"
  value       = "⚠️  THIS DEPLOYMENT CONTAINS NUMEROUS SECURITY VULNERABILITIES. DO NOT USE IN PRODUCTION!"
}

