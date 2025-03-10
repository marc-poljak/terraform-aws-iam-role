// lambda_and_boundary.tftest.hcl - Lambda Role and Permission Boundary Tests
//
// This file focuses on testing Lambda function roles and the permissions boundary feature

variables {
  // Basic required variables
  role_name = "test-lambda-role"
  trust_relationship_policy = {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals = {
      Service = ["lambda.amazonaws.com"]
    }
    condition = null
  }

  // Default values for other variables
  role_path                = "/lambda/"
  role_description         = "Test role for Lambda function tests"
  role_max_session_duration = 3600
  force_detach_policies    = false
  permissions_boundary     = null
  tags                     = { ManagedBy = "Terraform" }
  role_policies           = {}
  managed_policy_arns     = []
}

// Test Lambda role with managed policies
run "lambda_role_with_managed_policies" {
  variables {
    role_name = "lambda-function-role"

    managed_policy_arns = [
      "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
      "arn:aws:iam::aws:policy/AmazonDynamoDBReadOnlyAccess",
      "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    ]
  }

  command = apply

  // Verify role was created
  assert {
    condition     = output.name == "lambda-function-role"
    error_message = "Role name output doesn't match expected value"
  }

  // Verify managed policies
  assert {
    condition     = length(output.policy_attachments) == 3
    error_message = "Expected 3 managed policies"
  }

  assert {
    condition     = contains(output.policy_attachments, "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    error_message = "Expected AWSLambdaBasicExecutionRole managed policy"
  }
}

// Test role with permissions boundary
run "role_with_permissions_boundary" {
  variables {
    permissions_boundary = "arn:aws:iam::123456789012:policy/development-boundary"

    role_policies = {
      "s3_limited_access" = {
        effect    = "Allow"
        actions   = ["s3:GetObject", "s3:ListBucket"]
        resources = ["arn:aws:s3:::app-config-bucket/*"]
        condition = null
      }
    }
  }

  command = apply

  // Verify permissions boundary is set
  assert {
    condition     = aws_iam_role.this.permissions_boundary == "arn:aws:iam::123456789012:policy/development-boundary"
    error_message = "Permissions boundary doesn't match expected value"
  }

  // Verify inline policy still works with boundary
  assert {
    condition     = length(output.inline_policies) == 1
    error_message = "Expected 1 inline policy"
  }
}

// Test Lambda role with comprehensive configuration
run "comprehensive_lambda_role" {
  variables {
    role_name = "comprehensive-lambda-role"
    role_description = "Comprehensive Lambda role with multiple permissions"

    trust_relationship_policy = {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals = {
        Service = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"]
      }
      condition = {
        StringEquals = {
          test     = "StringEquals"
          variable = "aws:SourceAccount"
          values   = ["123456789012"]
        }
      }
    }

    role_policies = {
      "s3_data_processing" = {
        effect    = "Allow"
        actions   = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        resources = [
          "arn:aws:s3:::data-processing-bucket/*"
        ]
        condition = null
      },
      "sns_publishing" = {
        effect    = "Allow"
        actions   = ["sns:Publish"]
        resources = ["arn:aws:sns:*:*:processing-updates"]
        condition = null
      },
      "dynamodb_crud" = {
        effect    = "Allow"
        actions   = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        resources = ["arn:aws:dynamodb:*:*:table/processing-metadata"]
        condition = null
      }
    }

    managed_policy_arns = [
      "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    ]

    permissions_boundary = "arn:aws:iam::123456789012:policy/lambda-boundary"

    tags = {
      Environment = "Production"
      Service     = "DataProcessing"
      Function    = "ETL"
      ManagedBy   = "Terraform"
    }
  }

  command = apply

  // Verify complex role configuration
  assert {
    condition     = output.name == "comprehensive-lambda-role"
    error_message = "Role name output doesn't match expected value"
  }

  // Verify permissions boundary
  assert {
    condition     = aws_iam_role.this.permissions_boundary == "arn:aws:iam::123456789012:policy/lambda-boundary"
    error_message = "Permissions boundary doesn't match expected value"
  }

  // Verify inline policies
  assert {
    condition     = length(output.inline_policies) == 3
    error_message = "Expected 3 inline policies"
  }

  // Verify managed policies
  assert {
    condition     = length(output.policy_attachments) == 1
    error_message = "Expected 1 managed policy"
  }

  // Verify tags
  assert {
    condition     = length(aws_iam_role.this.tags) == 4
    error_message = "Expected 4 tags on the role"
  }
}