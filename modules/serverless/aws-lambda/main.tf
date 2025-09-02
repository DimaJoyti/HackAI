# AWS Lambda Functions Module
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.9.0"
    }
  }
}

# IAM Role for Lambda Functions
resource "aws_iam_role" "lambda_role" {
  count = var.enable_aws_lambda ? 1 : 0
  name  = "${var.project_name}-${var.environment}-lambda-role"

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

  tags = var.common_tags
}

# IAM Policy for Lambda Functions
resource "aws_iam_role_policy" "lambda_policy" {
  count = var.enable_aws_lambda ? 1 : 0
  name  = "${var.project_name}-${var.environment}-lambda-policy"
  role  = aws_iam_role.lambda_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages",
          "ec2:DescribeSnapshots",
          "ec2:DescribeVolumes",
          "application-autoscaling:*",
          "ecs:*",
          "eks:*",
          "cloudwatch:*"
        ]
        Resource = "*"
      }
    ]
  })
}

# Auto Scaler Lambda Function
resource "aws_lambda_function" "auto_scaler" {
  count         = var.enable_aws_lambda ? 1 : 0
  filename      = var.auto_scaler_zip_path
  function_name = "${var.project_name}-${var.environment}-auto-scaler"
  role          = aws_iam_role.lambda_role[0].arn
  handler       = "main"
  runtime       = "go1.x"
  timeout       = 300

  environment {
    variables = {
      ENVIRONMENT = var.environment
      PROJECT     = var.project_name
    }
  }

  tags = var.common_tags
}

# CloudWatch Event Rule for Auto Scaler
resource "aws_cloudwatch_event_rule" "auto_scaler_schedule" {
  count               = var.enable_aws_lambda ? 1 : 0
  name                = "${var.project_name}-${var.environment}-auto-scaler-schedule"
  description         = "Trigger auto scaler every 5 minutes"
  schedule_expression = "rate(5 minutes)"

  tags = var.common_tags
}

# CloudWatch Event Target
resource "aws_cloudwatch_event_target" "auto_scaler_target" {
  count     = var.enable_aws_lambda ? 1 : 0
  rule      = aws_cloudwatch_event_rule.auto_scaler_schedule[0].name
  target_id = "AutoScalerTarget"
  arn       = aws_lambda_function.auto_scaler[0].arn
}

# Lambda Permission for CloudWatch Events
resource "aws_lambda_permission" "allow_cloudwatch" {
  count         = var.enable_aws_lambda ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.auto_scaler[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.auto_scaler_schedule[0].arn
}

# Security Scanner Lambda Function
resource "aws_lambda_function" "security_scanner" {
  count         = var.enable_aws_lambda ? 1 : 0
  filename      = var.security_scanner_zip_path
  function_name = "${var.project_name}-${var.environment}-security-scanner"
  role          = aws_iam_role.lambda_role[0].arn
  handler       = "main"
  runtime       = "go1.x"
  timeout       = 900

  environment {
    variables = {
      ENVIRONMENT = var.environment
      PROJECT     = var.project_name
    }
  }

  tags = var.common_tags
}

# CloudWatch Event Rule for Security Scanner
resource "aws_cloudwatch_event_rule" "security_scanner_schedule" {
  count               = var.enable_aws_lambda ? 1 : 0
  name                = "${var.project_name}-${var.environment}-security-scanner-schedule"
  description         = "Trigger security scanner daily"
  schedule_expression = "rate(1 day)"

  tags = var.common_tags
}

# CloudWatch Event Target for Security Scanner
resource "aws_cloudwatch_event_target" "security_scanner_target" {
  count     = var.enable_aws_lambda ? 1 : 0
  rule      = aws_cloudwatch_event_rule.security_scanner_schedule[0].name
  target_id = "SecurityScannerTarget"
  arn       = aws_lambda_function.security_scanner[0].arn
}

# Lambda Permission for Security Scanner
resource "aws_lambda_permission" "allow_cloudwatch_security" {
  count         = var.enable_aws_lambda ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_scanner[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_scanner_schedule[0].arn
}

# Variables
variable "enable_aws_lambda" {
  description = "Enable AWS Lambda functions"
  type        = bool
  default     = false
}

variable "project_name" {
  description = "Project name"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "auto_scaler_zip_path" {
  description = "Path to auto scaler Lambda zip file"
  type        = string
  default     = "auto-scaler.zip"
}

variable "security_scanner_zip_path" {
  description = "Path to security scanner Lambda zip file"
  type        = string
  default     = "security-scanner.zip"
}

variable "common_tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}

# Outputs
output "auto_scaler_function_name" {
  description = "Auto scaler Lambda function name"
  value       = var.enable_aws_lambda ? aws_lambda_function.auto_scaler[0].function_name : null
}

output "auto_scaler_function_arn" {
  description = "Auto scaler Lambda function ARN"
  value       = var.enable_aws_lambda ? aws_lambda_function.auto_scaler[0].arn : null
}

output "security_scanner_function_name" {
  description = "Security scanner Lambda function name"
  value       = var.enable_aws_lambda ? aws_lambda_function.security_scanner[0].function_name : null
}

output "security_scanner_function_arn" {
  description = "Security scanner Lambda function ARN"
  value       = var.enable_aws_lambda ? aws_lambda_function.security_scanner[0].arn : null
}
