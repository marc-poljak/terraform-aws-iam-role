// main.tftest.hcl - Basic Functionality Tests for AWS IAM Role Module
//
// This file contains basic tests to verify that the IAM role module
// correctly creates resources with default and custom configurations.

variables {
  // Basic required variables
  role_name = "test-role"
  trust_relationship_policy = {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals = {
      Service = ["ec2.amazonaws.com"]
    }
    condition = null
  }

  // Optional variables with defaults
  role_path                = "/"
  role_description         = "Test role created by terraform test"
  role_max_session_duration = 3600
  force_detach_policies    = false
  permissions_boundary     = null
  tags                     = {
    Environment = "Test"
    ManagedBy   = "Terraform"
  }

  // Empty policies and managed ARNs to test basic role creation
  role_policies           = {}
  managed_policy_arns     = []
}

// Test default IAM role creation with minimal configuration
run "create_basic_role" {
  command = apply

  // Validate IAM role outputs
  assert {
    condition     = output.name == var.role_name
    error_message = "IAM role name output doesn't match expected value"
  }

  assert {
    condition     = output.path == var.role_path
    error_message = "IAM role path output doesn't match expected value"
  }

  assert {
    condition     = length(output.policy_attachments) == 0
    error_message = "Expected no policy attachments"
  }

  assert {
    condition     = length(output.inline_policies) == 0
    error_message = "Expected no inline policies"
  }

  // Validate resource attributes
  assert {
    condition     = aws_iam_role.this.max_session_duration == var.role_max_session_duration
    error_message = "IAM role max session duration doesn't match expected value"
  }

  assert {
    condition     = aws_iam_role.this.description == var.role_description
    error_message = "IAM role description doesn't match expected value"
  }

  assert {
    condition     = aws_iam_role.this.force_detach_policies == var.force_detach_policies
    error_message = "IAM role force_detach_policies doesn't match expected value"
  }

  // Validate the trust relationship policy content
  assert {
    condition     = can(jsondecode(aws_iam_role.this.assume_role_policy))
    error_message = "IAM role assume_role_policy is not valid JSON"
  }

  // Validate tags are set correctly
  assert {
    condition     = aws_iam_role.this.tags["Environment"] == var.tags["Environment"]
    error_message = "IAM role Environment tag doesn't match expected value"
  }

  assert {
    condition     = aws_iam_role.this.tags["ManagedBy"] == var.tags["ManagedBy"]
    error_message = "IAM role ManagedBy tag doesn't match expected value"
  }
}

// Test role with custom session duration
run "customize_session_duration" {
  variables {
    role_max_session_duration = 43200  // 12 hours
  }

  command = apply

  assert {
    condition     = aws_iam_role.this.max_session_duration == 43200
    error_message = "IAM role max session duration doesn't match expected custom value"
  }
}