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
      id                    = instance.id
      public_ip             = instance.public_ip
      private_ip            = instance.private_ip
      state                 = "stopped"
      contains_sensitive_data = idx < 3 ? "YES - Contains fake credit cards, SSNs, PII, and secrets" : "No"
      has_iam_role          = idx >= 3 ? "YES - Has IAM role with S3 access to PHI buckets" : "No"
      iam_role_name         = idx >= 3 ? aws_iam_role.phi_access_role.name : null
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
    role_name    = aws_iam_role.phi_access_role.name
    role_arn     = aws_iam_role.phi_access_role.arn
    attached_to = "EC2 instances 3 and 4 (indices 3 and 4)"
    permissions  = "Full S3 access (GetObject, PutObject, DeleteObject, ListBucket) on all 5 PHI buckets"
    warning      = "Overly permissive IAM policy - violates least privilege principle"
  }
}

output "warning" {
  description = "SECURITY WARNING"
  value       = "⚠️  THIS DEPLOYMENT CONTAINS NUMEROUS SECURITY VULNERABILITIES. DO NOT USE IN PRODUCTION!"
}

