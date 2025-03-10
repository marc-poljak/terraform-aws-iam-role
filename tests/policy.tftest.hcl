// policy.tftest.hcl - Policy Configuration Tests for AWS IAM Role Module
//
// This file contains tests for verifying the module's handling of
// inline policies and managed policies.

variables {
  // Basic required variables
  role_name = "test-policy-role"
  trust_relationship_policy = {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals = {
      Service = ["lambda.amazonaws.com"]
    }
    condition = null
  }

  // Default values for other variables
  role_path                = "/"
  role_description         = "Test role for policy tests"
  role_max_session_duration = 3600
  force_detach_policies    = false
  permissions_boundary     = null
  tags                     = { ManagedBy = "Terraform" }

  // Policy variables will be set in individual tests
  role_policies           = {}
  managed_policy_arns     = []
}

// Test role with inline policies
run "inline_policies" {
  variables {
    role_policies = {
      "s3_read_access" = {
        effect    = "Allow"
        actions   = ["s3:GetObject", "s3:ListBucket"]
        resources = ["arn:aws:s3:::example-bucket", "arn:aws:s3:::example-bucket/*"]
        condition = null
      },
      "dynamodb_access" = {
        effect    = "Allow"
        actions   = ["dynamodb:GetItem", "dynamodb:Query"]
        resources = ["arn:aws:dynamodb:*:*:table/example-table"]
        condition = null
      }
    }
  }

  command = apply

  // Verify inline policies were created
  assert {
    condition     = length(output.inline_policies) == 2
    error_message = "Expected 2 inline policies to be created"
  }

  assert {
    condition     = contains(keys(output.inline_policies), "s3_read_access")
    error_message = "Expected s3_read_access inline policy to be created"
  }

  assert {
    condition     = contains(keys(output.inline_policies), "dynamodb_access")
    error_message = "Expected dynamodb_access inline policy to be created"
  }

  // Verify policy documents
  assert {
    condition     = can(aws_iam_role_policy.role_policies["s3_read_access"].policy)
    error_message = "s3_read_access policy document is invalid"
  }

  assert {
    condition     = can(aws_iam_role_policy.role_policies["dynamodb_access"].policy)
    error_message = "dynamodb_access policy document is invalid"
  }
}

// Test role with a policy containing conditions
run "policy_with_conditions" {
  variables {
    role_policies = {
      "conditional_access" = {
        effect    = "Allow"
        actions   = ["s3:GetObject"]
        resources = ["arn:aws:s3:::example-bucket/*"]
        condition = {
          StringEquals = {
            test     = "StringEquals"
            variable = "aws:RequestTag/Environment"
            values   = ["Production"]
          }
        }
      }
    }
  }

  command = apply

  // Verify condition is properly added to policy
  assert {
    condition     = contains(keys(output.inline_policies), "conditional_access")
    error_message = "Expected conditional_access inline policy to be created"
  }

  // Check for policy document validity
  assert {
    condition     = can(jsondecode(aws_iam_role_policy.role_policies["conditional_access"].policy))
    error_message = "conditional_access policy document is not valid JSON"
  }
}

// Test role with managed policy attachments
run "managed_policies" {
  variables {
    managed_policy_arns = [
      "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
      "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    ]
  }

  command = apply

  // Verify managed policies are attached
  assert {
    condition     = length(output.policy_attachments) == 2
    error_message = "Expected 2 managed policies to be attached"
  }

  assert {
    condition     = contains(output.policy_attachments, "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")
    error_message = "Expected AmazonS3ReadOnlyAccess managed policy to be attached"
  }

  assert {
    condition     = contains(output.policy_attachments, "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    error_message = "Expected AWSLambdaBasicExecutionRole managed policy to be attached"
  }
}

// Test role with both inline and managed policies
run "combined_policies" {
  variables {
    role_policies = {
      "s3_write_access" = {
        effect    = "Allow"
        actions   = ["s3:PutObject"]
        resources = ["arn:aws:s3:::example-bucket/*"]
        condition = null
      }
    }
    managed_policy_arns = [
      "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    ]
  }

  command = apply

  // Verify both policy types are present
  assert {
    condition     = length(output.inline_policies) == 1
    error_message = "Expected 1 inline policy to be created"
  }

  assert {
    condition     = length(output.policy_attachments) == 1
    error_message = "Expected 1 managed policy to be attached"
  }
}