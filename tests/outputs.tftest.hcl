// outputs.tftest.hcl - Output Tests for AWS IAM Role Module
//
// This file contains tests focused on validating the module outputs.

variables {
  // Basic required variables
  role_name = "test-output-role"
  trust_relationship_policy = {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals = {
      Service = ["ec2.amazonaws.com"]
    }
    condition = null
  }

  // Default values for other variables
  role_path                = "/test-path/"
  role_description         = "Test role for output tests"
  role_max_session_duration = 3600
  force_detach_policies    = false
  permissions_boundary     = null
  tags                     = { ManagedBy = "Terraform" }
  role_policies           = {
    "test_policy" = {
      effect    = "Allow"
      actions   = ["s3:GetObject"]
      resources = ["*"]
      condition = null
    }
  }
  managed_policy_arns     = [
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
  ]
}

// Test all outputs with a fully configured role
run "validate_all_outputs" {
  command = apply

  // Validate output existence and types
  assert {
    condition     = output.name != null && output.name == var.role_name
    error_message = "Role name output is incorrect"
  }

  assert {
    condition     = output.path != null && output.path == var.role_path
    error_message = "Role path output is incorrect"
  }

  assert {
    condition     = output.id != null
    error_message = "Role ID output is missing"
  }

  assert {
    condition     = output.arn != null
    error_message = "Role ARN output is missing"
  }

  assert {
    condition     = output.unique_id != null
    error_message = "Role unique_id output is missing"
  }

  // Validate AWS account ID is included in ARN
  assert {
    condition     = can(regex("arn:aws:iam::\\d+:role", output.arn))
    error_message = "Role ARN format is incorrect"
  }

  // Validate role name is included in ARN
  assert {
    condition     = can(regex("role${var.role_path}${var.role_name}", output.arn))
    error_message = "Role ARN doesn't include the correct path and name"
  }

  // Validate policy attachments output
  assert {
    condition     = length(output.policy_attachments) == 1
    error_message = "Expected 1 policy attachment"
  }

  assert {
    condition     = output.policy_attachments[0] == var.managed_policy_arns[0]
    error_message = "Policy attachment ARN doesn't match expected value"
  }

  // Validate inline policies output
  assert {
    condition     = length(output.inline_policies) == 1
    error_message = "Expected 1 inline policy"
  }

  assert {
    condition     = contains(keys(output.inline_policies), "test_policy")
    error_message = "Expected test_policy in inline policies output"
  }
}

// Test outputs with non-default path
run "validate_custom_path_outputs" {
  variables {
    role_path = "/custom/path/"
  }

  command = apply

  assert {
    condition     = output.path == "/custom/path/"
    error_message = "Role path output doesn't match custom path"
  }

  assert {
    condition     = can(regex("role/custom/path/${var.role_name}", output.arn))
    error_message = "Role ARN doesn't include the custom path"
  }
}

// Test outputs with multiple policies
run "validate_multiple_policies_outputs" {
  variables {
    role_policies = {
      "s3_policy" = {
        effect    = "Allow"
        actions   = ["s3:GetObject"]
        resources = ["*"]
        condition = null
      },
      "dynamodb_policy" = {
        effect    = "Allow"
        actions   = ["dynamodb:GetItem"]
        resources = ["*"]
        condition = null
      }
    }
    managed_policy_arns = [
      "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
      "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    ]
  }

  command = apply

  assert {
    condition     = length(output.inline_policies) == 2
    error_message = "Expected 2 inline policies in output"
  }

  assert {
    condition     = contains(keys(output.inline_policies), "s3_policy") && contains(keys(output.inline_policies), "dynamodb_policy")
    error_message = "Expected both s3_policy and dynamodb_policy in inline policies output"
  }

  assert {
    condition     = length(output.policy_attachments) == 2
    error_message = "Expected 2 policy attachments in output"
  }
}