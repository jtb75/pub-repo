terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Random provider for generating random names
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# VPC with default security settings (BAD: No proper segmentation)
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "insecure-vpc-${random_string.suffix.result}"
  }
}

# Internet Gateway (BAD: Allows unrestricted internet access)
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "insecure-igw-${random_string.suffix.result}"
  }
}

# Public subnet (BAD: Everything is public)
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet-${random_string.suffix.result}"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# Route table allowing all traffic to internet (BAD: No restrictions)
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "public-rt-${random_string.suffix.result}"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Security Group allowing ALL traffic from ANYWHERE (VERY BAD)
resource "aws_security_group" "wide_open" {
  name        = "wide-open-sg-${random_string.suffix.result}"
  description = "Security group allowing all traffic - DO NOT USE IN PRODUCTION"
  vpc_id      = aws_vpc.main.id

  # Allow ALL inbound traffic
  ingress {
    description = "Allow all inbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow ALL outbound traffic
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "wide-open-sg-${random_string.suffix.result}"
  }
}

# Get latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# 5 EC2 instances with random names, IMDSv1, and full public exposure
resource "random_string" "instance_names" {
  count   = 5
  length  = 12
  special = false
  upper   = false
}

# Local values for user_data scripts to avoid parsing issues with nested heredocs
locals {
  user_data_with_sensitive_data = <<-EOF
#!/bin/bash
# This instance is intentionally insecure
echo "Instance is running with IMDSv1 enabled"

# BAD: Creating files with fake sensitive data in accessible locations
mkdir -p /tmp/data /home/ec2-user/secrets /var/www/html

# Generate fake credit card numbers (at least 10)
cat > /tmp/data/credit_cards.txt <<'CARDS'
# FAKE CREDIT CARD NUMBERS - FOR DEMONSTRATION ONLY
4532-1234-5678-9010|John Doe|12/25|123
5555-4444-3333-2222|Jane Smith|03/26|456
4111-1111-1111-1111|Bob Johnson|06/27|789
4000-0000-0000-0002|Alice Williams|09/28|321
5105-1051-0510-5100|Charlie Brown|01/29|654
6011-1111-1111-1117|Diana Prince|04/30|987
3782-822463-10005|Edward Norton|07/31|147
3714-496353-98431|Frank Miller|10/32|258
3056-9309-0259-04|Grace Kelly|02/33|369
5424-0000-0000-0015|Henry Ford|05/34|741
4242-4242-4242-4242|Iris Watson|08/35|852
5200-8282-8282-8210|Jack London|11/36|963
CARDS

# Generate fake Social Security Numbers
cat > /tmp/data/ssn_data.txt <<'SSN'
# FAKE SOCIAL SECURITY NUMBERS - FOR DEMONSTRATION ONLY
123-45-6789|John Doe|1985-03-15
234-56-7890|Jane Smith|1990-07-22
345-67-8901|Bob Johnson|1978-11-08
456-78-9012|Alice Williams|1992-01-30
567-89-0123|Charlie Brown|1988-05-14
678-90-1234|Diana Prince|1983-09-27
789-01-2345|Edward Norton|1995-12-03
890-12-3456|Frank Miller|1980-04-18
901-23-4567|Grace Kelly|1987-08-21
012-34-5678|Henry Ford|1993-02-09
SSN

# Generate fake PII (Personally Identifiable Information)
cat > /tmp/data/pii_data.txt <<'PII'
# FAKE PII DATA - FOR DEMONSTRATION ONLY
Name: Sarah Connor|DOB: 1985-05-12|Email: sarah.connor@example.com|Phone: 555-0101|Address: 123 Main St, Anytown, ST 12345
Name: Michael Chen|DOB: 1990-08-23|Email: m.chen@example.com|Phone: 555-0102|Address: 456 Oak Ave, Springfield, IL 62701
Name: Emily Rodriguez|DOB: 1987-11-07|Email: emily.r@example.com|Phone: 555-0103|Address: 789 Pine Rd, Austin, TX 78701
Name: David Kim|DOB: 1992-02-19|Email: david.kim@example.com|Phone: 555-0104|Address: 321 Elm St, Seattle, WA 98101
Name: Lisa Anderson|DOB: 1984-09-14|Email: lisa.a@example.com|Phone: 555-0105|Address: 654 Maple Dr, Denver, CO 80202
Name: Robert Taylor|DOB: 1989-06-28|Email: robert.t@example.com|Phone: 555-0106|Address: 987 Cedar Ln, Miami, FL 33101
Name: Jennifer Martinez|DOB: 1991-12-05|Email: j.martinez@example.com|Phone: 555-0107|Address: 147 Birch Way, Phoenix, AZ 85001
Name: Christopher Lee|DOB: 1986-03-20|Email: chris.lee@example.com|Phone: 555-0108|Address: 258 Spruce Ct, Boston, MA 02101
Name: Amanda White|DOB: 1993-07-11|Email: amanda.w@example.com|Phone: 555-0109|Address: 369 Willow St, Portland, OR 97201
Name: James Wilson|DOB: 1988-10-25|Email: james.wilson@example.com|Phone: 555-0110|Address: 741 Ash Blvd, Nashville, TN 37201
PII

# Generate fake secrets and API keys
cat > /home/ec2-user/secrets/api_keys.txt <<'SECRETS'
# FAKE API KEYS AND SECRETS - FOR DEMONSTRATION ONLY
# These are intentionally fake and should never be used
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DATABASE_PASSWORD=SuperSecret123!@#
API_KEY=FAKE_API_KEY_sk_live_FAKE123456789
JWT_SECRET=FAKE_JWT_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9FAKE
STRIPE_SECRET_KEY=FAKE_sk_test_FAKE_STRIPE_KEY_987654321
GITHUB_TOKEN=FAKE_ghp_FAKE_TOKEN_1234567890abcdefghijklmnop
SLACK_WEBHOOK=FAKE_https://hooks.slack.com/services/FAKE/FAKE/FAKE_WEBHOOK_URL
MONGODB_URI=mongodb://admin:password123@cluster0.example.mongodb.net/dbname
REDIS_PASSWORD=RedisSecretPassword456!
DOCKER_REGISTRY_TOKEN=FAKE_dckr_pat_FAKE_TOKEN_1234567890
TWILIO_AUTH_TOKEN=FAKE_TWILIO_TOKEN_1234567890abcdefghijklmnop
SECRETS

# Create a database dump file with fake data
cat > /tmp/data/database_dump.sql <<'SQL'
-- FAKE DATABASE DUMP - FOR DEMONSTRATION ONLY
INSERT INTO users (id, username, email, password_hash, ssn, credit_card) VALUES
(1, 'admin', 'admin@example.com', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', '123-45-6789', '4532-1234-5678-9010'),
(2, 'user1', 'user1@example.com', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', '234-56-7890', '5555-4444-3333-2222'),
(3, 'user2', 'user2@example.com', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', '345-67-8901', '4111-1111-1111-1111');
SQL

# Create a config file with hardcoded credentials
cat > /var/www/html/config.php <<'PHP'
<?php
// FAKE CONFIG FILE - FOR DEMONSTRATION ONLY
$db_host = "database.example.com";
$db_user = "admin";
$db_pass = "SuperSecretPassword123!";
$db_name = "production_db";
$api_key = "FAKE_sk_live_FAKE_API_KEY_123456789";
$admin_email = "admin@example.com";
$admin_password = "Admin123!@#";
?>
PHP

# Make files world-readable (VERY BAD)
chmod 644 /tmp/data/*.txt
chmod 644 /tmp/data/*.sql
chmod 644 /home/ec2-user/secrets/*.txt
chmod 644 /var/www/html/config.php

# BAD: Log sensitive data to syslog
logger "User data script completed. Sensitive data files created in /tmp/data and /home/ec2-user/secrets"
EOF

  user_data_simple = <<-EOF
#!/bin/bash
# This instance is intentionally insecure
echo "Instance is running with IMDSv1 enabled"
# BAD: No secrets management, might log sensitive data
EOF
}

# IAM role for instances 3 and 4 with overly permissive S3 access (BAD: Too broad permissions)
resource "aws_iam_role" "phi_access_role" {
  name = "phi-access-role-${random_string.suffix.result}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "phi-access-role-${random_string.suffix.result}"
    Environment = "insecure-demo"
  }
}

# BAD: Overly permissive IAM policy allowing full access to PHI buckets
resource "aws_iam_role_policy" "phi_bucket_access" {
  name = "phi-bucket-full-access-${random_string.suffix.result}"
  role = aws_iam_role.phi_access_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetObjectVersion",
          "s3:DeleteObjectVersion"
        ]
        Resource = [
          for bucket in aws_s3_bucket.phi_buckets : "${bucket.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [
          for bucket in aws_s3_bucket.phi_buckets : bucket.arn
        ]
      }
    ]
  })
}

# Instance profile for EC2 instances
resource "aws_iam_instance_profile" "phi_access_profile" {
  name = "phi-access-profile-${random_string.suffix.result}"
  role = aws_iam_role.phi_access_role.name

  tags = {
    Name        = "phi-access-profile-${random_string.suffix.result}"
    Environment = "insecure-demo"
  }
}

resource "aws_instance" "insecure_instances" {
  count                       = 5
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.wide_open.id]
  associate_public_ip_address = true

  # BAD: Attach IAM role with overly permissive S3 access to instances 3 and 4
  iam_instance_profile = count.index >= 3 ? aws_iam_instance_profile.phi_access_profile.name : null

  # BAD: IMDSv1 enabled (http_tokens = "optional")
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # BAD: Allows IMDSv1
    http_put_response_hop_limit = 1
  }

  # BAD: User data that might expose sensitive info
  # First 3 instances contain fake sensitive data (BAD: Exposed secrets, PII, credit cards, SSNs)
  user_data = count.index < 3 ? local.user_data_with_sensitive_data : local.user_data_simple

  tags = {
    Name        = "insecure-instance-${random_string.instance_names[count.index].result}"
    Environment = "insecure-demo"
  }
}

# Stop all instances after creation (BAD: Still vulnerable when stopped, but at least not running)
resource "aws_ec2_instance_state" "stop_instances" {
  count       = 5
  instance_id = aws_instance.insecure_instances[count.index].id
  state       = "stopped"
}

# 5 private S3 buckets for PHI data (BAD: Still has security issues despite being "private")
resource "random_string" "phi_bucket_names" {
  count   = 5
  length  = 16
  special = false
  upper   = false
  lower   = true
}

resource "aws_s3_bucket" "phi_buckets" {
  count  = 5
  bucket = "phi-bucket-${random_string.phi_bucket_names[count.index].result}"

  tags = {
    Name        = "phi-bucket-${random_string.phi_bucket_names[count.index].result}"
    Environment = "insecure-demo"
    DataType    = "PHI"
  }
}

# BAD: Public access block enabled but other security issues remain
resource "aws_s3_bucket_public_access_block" "phi_buckets" {
  count  = 5
  bucket = aws_s3_bucket.phi_buckets[count.index].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# BAD: No encryption enabled on PHI buckets
# BAD: No versioning enabled
# BAD: No access logging
# BAD: No lifecycle policies
# BAD: No MFA delete

# Add fake PHI data to the buckets
resource "aws_s3_object" "phi_patient_records" {
  count  = 5
  bucket = aws_s3_bucket.phi_buckets[count.index].id
  key    = "patient-records/patients-${count.index + 1}.json"
  content = jsonencode({
    patients = [
      {
        patient_id            = "MRN-${count.index + 1}-001"
        name                  = "Patient ${count.index + 1} Alpha"
        date_of_birth         = "1985-03-15"
        ssn                   = "123-45-678${count.index}"
        medical_record_number = "MRN-${count.index + 1}-001"
        diagnosis             = "Hypertension, Type 2 Diabetes"
        medications           = ["Metformin 500mg", "Lisinopril 10mg"]
        insurance_id          = "INS-${count.index + 1}-001"
        insurance_provider    = "Fake Insurance Co"
        admission_date        = "2024-01-15"
        discharge_date        = "2024-01-20"
        physician             = "Dr. Smith"
        notes                 = "Patient requires ongoing monitoring"
      },
      {
        patient_id            = "MRN-${count.index + 1}-002"
        name                  = "Patient ${count.index + 1} Beta"
        date_of_birth         = "1990-07-22"
        ssn                   = "234-56-789${count.index}"
        medical_record_number = "MRN-${count.index + 1}-002"
        diagnosis             = "Asthma, Allergic Rhinitis"
        medications           = ["Albuterol Inhaler", "Fluticasone"]
        insurance_id          = "INS-${count.index + 1}-002"
        insurance_provider    = "Fake Insurance Co"
        admission_date        = "2024-02-10"
        discharge_date        = "2024-02-12"
        physician             = "Dr. Jones"
        notes                 = "Patient has seasonal allergies"
      },
      {
        patient_id            = "MRN-${count.index + 1}-003"
        name                  = "Patient ${count.index + 1} Gamma"
        date_of_birth         = "1978-11-08"
        ssn                   = "345-67-890${count.index}"
        medical_record_number = "MRN-${count.index + 1}-003"
        diagnosis             = "Coronary Artery Disease"
        medications           = ["Aspirin 81mg", "Atorvastatin 40mg"]
        insurance_id          = "INS-${count.index + 1}-003"
        insurance_provider    = "Fake Insurance Co"
        admission_date        = "2024-03-05"
        discharge_date        = "2024-03-08"
        physician             = "Dr. Williams"
        notes                 = "Patient requires cardiac monitoring"
      }
    ]
  })

  content_type = "application/json"

  depends_on = [aws_s3_bucket_public_access_block.phi_buckets]
}

resource "aws_s3_object" "phi_lab_results" {
  count   = 5
  bucket  = aws_s3_bucket.phi_buckets[count.index].id
  key     = "lab-results/labs-${count.index + 1}.csv"
  content = <<-CSV
    # FAKE LAB RESULTS - FOR DEMONSTRATION ONLY
    Patient ID,Name,Date,Test,Result,Reference Range,Status
    MRN-${count.index + 1}-001,Patient ${count.index + 1} Alpha,2024-01-16,Glucose,95,70-100 mg/dL,Normal
    MRN-${count.index + 1}-001,Patient ${count.index + 1} Alpha,2024-01-16,Hemoglobin A1C,6.2,<5.7%,Elevated
    MRN-${count.index + 1}-002,Patient ${count.index + 1} Beta,2024-02-11,White Blood Count,7200,4000-11000 cells/μL,Normal
    MRN-${count.index + 1}-002,Patient ${count.index + 1} Beta,2024-02-11,Eosinophils,8,0-4%,Elevated
    MRN-${count.index + 1}-003,Patient ${count.index + 1} Gamma,2024-03-06,Cholesterol Total,220,<200 mg/dL,Elevated
    MRN-${count.index + 1}-003,Patient ${count.index + 1} Gamma,2024-03-06,LDL Cholesterol,145,<100 mg/dL,Elevated
  CSV

  content_type = "text/csv"

  depends_on = [aws_s3_bucket_public_access_block.phi_buckets]
}

resource "aws_s3_object" "phi_insurance_info" {
  count   = 5
  bucket  = aws_s3_bucket.phi_buckets[count.index].id
  key     = "insurance/insurance-${count.index + 1}.txt"
  content = <<-TXT
    # FAKE INSURANCE INFORMATION - FOR DEMONSTRATION ONLY
    Insurance Provider: Fake Insurance Co
    Policy Number: POL-${count.index + 1}-001
    Group Number: GRP-${count.index + 1}-001
    Member ID: MEM-${count.index + 1}-001
    Patient Name: Patient ${count.index + 1} Alpha
    Date of Birth: 1985-03-15
    SSN: 123-45-678${count.index}
    Coverage Type: PPO
    Effective Date: 2024-01-01
    Expiration Date: 2024-12-31
    Copay: $25
    Deductible: $1000
    Out of Pocket Max: $5000
  TXT

  content_type = "text/plain"

  depends_on = [aws_s3_bucket_public_access_block.phi_buckets]
}

# 10 publicly exposed S3 buckets with random names
resource "random_string" "bucket_names" {
  count   = 10
  length  = 16
  special = false
  upper   = false
  lower   = true
}

resource "aws_s3_bucket" "public_buckets" {
  count  = 10
  bucket = "insecure-bucket-${random_string.bucket_names[count.index].result}"

  tags = {
    Name        = "insecure-bucket-${random_string.bucket_names[count.index].result}"
    Environment = "insecure-demo"
  }
}

# BAD: Public access block disabled (allows public access)
resource "aws_s3_bucket_public_access_block" "public_buckets" {
  count  = 10
  bucket = aws_s3_bucket.public_buckets[count.index].id

  block_public_acls       = false # BAD: Allows public ACLs
  block_public_policy     = false # BAD: Allows public policies
  ignore_public_acls      = false # BAD: Doesn't ignore public ACLs
  restrict_public_buckets = false # BAD: Doesn't restrict public buckets
}

# BAD: Enable ACLs on bucket (required to set ACLs - modern buckets have ACLs disabled by default)
resource "aws_s3_bucket_ownership_controls" "public_buckets" {
  count  = 10
  bucket = aws_s3_bucket.public_buckets[count.index].id

  rule {
    object_ownership = "BucketOwnerPreferred" # BAD: Allows ACLs
  }

  depends_on = [aws_s3_bucket_public_access_block.public_buckets]
}

# BAD: Bucket policy allowing public read access
resource "aws_s3_bucket_policy" "public_read" {
  count  = 10
  bucket = aws_s3_bucket.public_buckets[count.index].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.public_buckets[count.index].arn}/*"
      },
      {
        Sid       = "PublicListBucket"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.public_buckets[count.index].arn
      },
      {
        Sid       = "PublicWriteObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.public_buckets[count.index].arn}/*"
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.public_buckets]
}

# BAD: ACL allowing public read
resource "aws_s3_bucket_acl" "public_buckets" {
  count  = 10
  bucket = aws_s3_bucket.public_buckets[count.index].id
  acl    = "public-read-write" # BAD: Public read and write access

  depends_on = [
    aws_s3_bucket_public_access_block.public_buckets,
    aws_s3_bucket_ownership_controls.public_buckets,
  ]
}

# ============================================================================
# FREE TIER BAD PATTERNS - No additional cost
# ============================================================================

# BAD: IAM Users with admin access and long-lived access keys
resource "aws_iam_user" "admin_users" {
  count = 3
  name  = "admin-user-${count.index + 1}-${random_string.suffix.result}"

  tags = {
    Name        = "admin-user-${count.index + 1}-${random_string.suffix.result}"
    Environment = "insecure-demo"
  }
}

# BAD: Attach AdministratorAccess policy directly to users
resource "aws_iam_user_policy_attachment" "admin_access" {
  count      = 3
  user       = aws_iam_user.admin_users[count.index].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" # BAD: Full admin access
}

# BAD: Create long-lived access keys (no rotation, no expiration)
resource "aws_iam_access_key" "admin_keys" {
  count = 3
  user  = aws_iam_user.admin_users[count.index].name
  # BAD: No key rotation policy, keys never expire
}

# BAD: No MFA required for admin users
# (MFA is free but not enabled - demonstrating the anti-pattern)

# BAD: CloudTrail not enabled or misconfigured
# Note: CloudTrail is free for management events, but we're demonstrating NOT using it
# We'll create a comment showing what NOT to do rather than actually disabling it
# (since you can't "disable" CloudTrail via Terraform if it's already enabled)

# BAD: VPC Flow Logs disabled (should be enabled for security monitoring)
# VPC Flow Logs: First 10GB per month free
# We're demonstrating NOT enabling them
# (Cannot create a resource to "disable" something, but we document the anti-pattern)

# BAD: Lambda function with secrets in environment variables and overly permissive role
resource "aws_iam_role" "lambda_role" {
  name = "lambda-overly-permissive-role-${random_string.suffix.result}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "lambda-overly-permissive-role-${random_string.suffix.result}"
    Environment = "insecure-demo"
  }
}

# BAD: Overly permissive Lambda IAM policy (allows everything)
resource "aws_iam_role_policy" "lambda_full_access" {
  name = "lambda-full-access-${random_string.suffix.result}"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*" # BAD: Wildcard permission
        Resource = "*" # BAD: All resources
      }
    ]
  })
}

# Create Lambda function code
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_function_${random_string.suffix.result}.zip"
  source {
    content  = <<-PYTHON
def handler(event, context):
    # BAD: This function would use the environment variables with secrets
    import os
    db_password = os.environ.get('DATABASE_PASSWORD')
    api_key = os.environ.get('API_KEY')
    # In a real scenario, these would be logged or exposed
    return {
        'statusCode': 200,
        'body': 'Function executed (secrets in env vars - BAD!)'
    }
PYTHON
    filename = "index.py"
  }
}

# BAD: Lambda function with secrets in plain text environment variables
resource "aws_lambda_function" "insecure_lambda" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "insecure-lambda-${random_string.suffix.result}"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.handler"
  runtime          = "python3.11"
  timeout          = 30
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  # BAD: Secrets stored in plain text environment variables
  # Note: AWS_ACCESS_KEY and AWS_SECRET_KEY are reserved by Lambda, using alternative names
  environment {
    variables = {
      DATABASE_PASSWORD   = "SuperSecretPassword123!"
      API_KEY             = "FAKE_sk_live_FAKE_API_KEY_123456789"
      FAKE_AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
      FAKE_AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      JWT_SECRET          = "FAKE_JWT_SECRET_KEY_DO_NOT_USE"
      STRIPE_KEY          = "FAKE_sk_test_FAKE_STRIPE_KEY"
    }
  }

  # BAD: No VPC configuration (runs in public subnet by default)
  # BAD: No dead letter queue configured
  # BAD: No reserved concurrent executions limit

  tags = {
    Name        = "insecure-lambda-${random_string.suffix.result}"
    Environment = "insecure-demo"
  }
}

# BAD: API Gateway with no authentication
resource "aws_api_gateway_rest_api" "insecure_api" {
  name        = "insecure-api-${random_string.suffix.result}"
  description = "API Gateway with no authentication - DO NOT USE IN PRODUCTION"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = {
    Name        = "insecure-api-${random_string.suffix.result}"
    Environment = "insecure-demo"
  }
}

resource "aws_api_gateway_resource" "insecure_api_resource" {
  rest_api_id = aws_api_gateway_rest_api.insecure_api.id
  parent_id   = aws_api_gateway_rest_api.insecure_api.root_resource_id
  path_part   = "data"
}

resource "aws_api_gateway_method" "insecure_api_method" {
  rest_api_id      = aws_api_gateway_rest_api.insecure_api.id
  resource_id      = aws_api_gateway_resource.insecure_api_resource.id
  http_method      = "GET"
  authorization    = "NONE" # BAD: No authentication required
  api_key_required = false  # BAD: No API key required
}

resource "aws_api_gateway_integration" "insecure_api_integration" {
  rest_api_id = aws_api_gateway_rest_api.insecure_api.id
  resource_id = aws_api_gateway_resource.insecure_api_resource.id
  http_method = aws_api_gateway_method.insecure_api_method.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.insecure_lambda.invoke_arn
}

# BAD: No WAF attached to API Gateway
# BAD: No rate limiting configured
# BAD: No CORS restrictions
# BAD: No request validation

resource "aws_api_gateway_deployment" "insecure_api_deployment" {
  depends_on = [
    aws_api_gateway_method.insecure_api_method,
    aws_api_gateway_integration.insecure_api_integration,
  ]

  rest_api_id = aws_api_gateway_rest_api.insecure_api.id
}

# BAD: Using "prod" stage name for insecure API
resource "aws_api_gateway_stage" "insecure_api_stage" {
  deployment_id = aws_api_gateway_deployment.insecure_api_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.insecure_api.id
  stage_name    = "prod" # BAD: Using "prod" stage name for insecure API
}

# BAD: CloudWatch Log Group with sensitive data (logs are free for first 5GB)
resource "aws_cloudwatch_log_group" "insecure_logs" {
  name              = "/aws/lambda/insecure-lambda-${random_string.suffix.result}"
  retention_in_days = 0 # BAD: Logs never expire (costs money, but also security risk)

  tags = {
    Name        = "insecure-lambda-logs-${random_string.suffix.result}"
    Environment = "insecure-demo"
  }
}

# BAD: CloudWatch Log Group for API Gateway (no encryption, no retention)
resource "aws_cloudwatch_log_group" "api_gateway_logs" {
  name              = "/aws/apigateway/insecure-api-${random_string.suffix.result}"
  retention_in_days = 0 # BAD: Logs never expire

  tags = {
    Name        = "insecure-api-logs-${random_string.suffix.result}"
    Environment = "insecure-demo"
  }
}

# BAD: Lambda permission allows API Gateway to invoke (but also allows anyone with API endpoint)
resource "aws_lambda_permission" "api_gateway_invoke" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.insecure_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.insecure_api.execution_arn}/*/*"
}

