# Heimdall PR Simulator Demo
# This is a SAFE configuration

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Safe IAM User
resource "aws_iam_user" "developer" {
  name = "alice-developer"
  path = "/developers/"

  tags = {
    Environment = "development"
    ManagedBy   = "terraform"
    Team        = "engineering"
  }
}

# Safe Read-Only Policy
resource "aws_iam_user_policy" "dev_readonly" {
  name = "developer-readonly"
  user = aws_iam_user.developer.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "ec2:Describe*",
          "lambda:GetFunction",
          "lambda:ListFunctions"
        ]
        Resource = "*"
      }
    ]
  })
}

# Safe IAM Role for Lambda
resource "aws_iam_role" "lambda_role" {
  name = "demo-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Environment = "development"
  }
}

# Attach basic Lambda execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Outputs
output "developer_user_arn" {
  value       = aws_iam_user.developer.arn
  description = "ARN of the developer user"
}

output "lambda_role_arn" {
  value       = aws_iam_role.lambda_role.arn
  description = "ARN of the Lambda execution role"
}
