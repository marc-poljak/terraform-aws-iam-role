// negative.tftest.hcl - Negative Tests for AWS IAM Role Module
//
// This file contains tests to verify the module's behavior with invalid inputs
// and edge cases. These tests are expected to fail in specific ways.

variables {
  // Basic required variables
  role_name = "test-negative-role"
  trust_relationship_policy = {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals = {
      Service = ["ec2.amazonaws.com"]
    }
    condition = null
  }

  // Default values for other variables
  role_path                = "/"
  role_description         = "Test role for negative tests"
  role_max_session_duration = 3600
  force_detach_policies    = false
  permissions_boundary     = null
  tags                     = { ManagedBy = "Terraform" }
  role_policies           = {}
  managed_policy_arns     = []
}

// Test role with invalid session duration (too high)
run "invalid_session_duration_high" {
  variables {
    role_max_session_duration = 86401  // AWS maximum is 86400 (24 hours)
  }

  // This should fail validation
  command = plan
  expect_failures = [
    aws_iam_role.this
  ]
}

// Test role with invalid session duration (too low)
run "invalid_session_duration_low" {
  variables {
    role_max_session_duration = 3599  // AWS minimum is 3600 (1 hour)
  }

  // This should fail validation
  command = plan
  expect_failures = [
    aws_iam_role.this
  ]
}

// Test role with empty trust relationship principals
run "empty_trust_principals" {
  variables {
    trust_relationship_policy = {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals = {}
      condition = null
    }
  }

  // This should fail because principals can't be empty
  command = plan
  expect_failures = [
    data.aws_iam_policy_document.trust_relationship
  ]
}

// Test role with invalid principal type
run "invalid_principal_type" {
  variables {
    trust_relationship_policy = {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals = {
        InvalidType = ["ec2.amazonaws.com"]
      }
      condition = null
    }
  }

  // This will likely succeed in plan but fail in apply
  command = plan
  expect_failures = [
    data.aws_iam_policy_document.trust_relationship
  ]
}

// Test role with invalid policy effect
run "invalid_policy_effect" {
  variables {
    role_policies = {
      "test_policy" = {
        effect    = "InvalidEffect"  // Should be Allow or Deny
        actions   = ["s3:GetObject"]
        resources = ["*"]
        condition = null
      }
    }
  }

  // This should fail validation
  command = plan
  expect_failures = [
    data.aws_iam_policy_document.role_policies["test_policy"]
  ]
}

// Test role with empty policy actions
run "empty_policy_actions" {
  variables {
    role_policies = {
      "empty_actions" = {
        effect    = "Allow"
        actions   = []
        resources = ["*"]
        condition = null
      }
    }
  }

  // This should fail validation or be caught by the module
  command = plan
  expect_failures = [
    data.aws_iam_policy_document.role_policies["empty_actions"]
  ]
}

// Test role with empty policy resources
run "empty_policy_resources" {
  variables {
    role_policies = {
      "empty_resources" = {
        effect    = "Allow"
        actions   = ["s3:GetObject"]
        resources = []
        condition = null
      }
    }
  }

  // This should fail validation or be caught by the module
  command = plan
  expect_failures = [
    data.aws_iam_policy_document.role_policies["empty_resources"]
  ]
}

// Test role with invalid condition test operator
run "invalid_condition_operator" {
  variables {
    role_policies = {
      "invalid_condition" = {
        effect    = "Allow"
        actions   = ["s3:GetObject"]
        resources = ["*"]
        condition = {
          InvalidOperator = {
            test     = "InvalidOperator"
            variable = "aws:RequestTag/Environment"
            values   = ["Production"]
          }
        }
      }
    }
  }

  // This should fail validation
  command = plan
  expect_failures = [
    data.aws_iam_policy_document.role_policies["invalid_condition"]
  ]
}

// Test role with invalid managed policy ARN format
run "invalid_managed_policy_arn" {
  variables {
    managed_policy_arns = [
      "not-a-valid-arn"
    ]
  }

  // This should fail validation or be caught during apply
  command = plan
  expect_failures = [
    aws_iam_role_policy_attachment.managed_policy[0]
  ]
}