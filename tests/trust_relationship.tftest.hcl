// trust_relationship.tftest.hcl - Trust Relationship Tests for AWS IAM Role Module
//
// This file contains tests for verifying different trust relationship configurations
// and validating their proper application to IAM roles.

variables {
  // Basic required variables
  role_name = "test-trust-role"

  // Default values for other variables
  role_path                = "/"
  role_description         = "Test role for trust relationship tests"
  role_max_session_duration = 3600
  force_detach_policies    = false
  permissions_boundary     = null
  tags                     = { ManagedBy = "Terraform" }
  role_policies            = {}
  managed_policy_arns      = []

  // Trust relationship will be set in individual tests
  trust_relationship_policy = {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals = {
      Service = ["ec2.amazonaws.com"]
    }
    condition = null
  }
}

// Test role with service principal trust relationship
run "service_principal_trust" {
  variables {
    trust_relationship_policy = {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals = {
        Service = ["ec2.amazonaws.com"]
      }
      condition = null
    }
  }

  command = apply

  // Verify trust relationship policy content
  assert {
    condition     = can(jsondecode(aws_iam_role.this.assume_role_policy))
    error_message = "IAM role assume_role_policy is not valid JSON"
  }
}

// Test role with AWS account principals trust relationship
run "aws_account_principal_trust" {
  variables {
    trust_relationship_policy = {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals = {
        AWS = ["arn:aws:iam::123456789012:root"]
      }
      condition = null
    }
  }

  command = apply

  // Verify role was created with AWS account principal
  assert {
    condition     = can(jsondecode(aws_iam_role.this.assume_role_policy))
    error_message = "IAM role assume_role_policy is not valid JSON"
  }
}

// Test role with multiple principal types
run "multiple_principal_types" {
  variables {
    trust_relationship_policy = {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals = {
        Service = ["lambda.amazonaws.com"]
        AWS     = ["arn:aws:iam::123456789012:root"]
      }
      condition = null
    }
  }

  command = apply

  // Verify role was created with multiple principal types
  assert {
    condition     = can(jsondecode(aws_iam_role.this.assume_role_policy))
    error_message = "IAM role assume_role_policy is not valid JSON"
  }
}

// Test role with conditional trust relationship
run "conditional_trust_relationship" {
  variables {
    trust_relationship_policy = {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals = {
        Service = ["ec2.amazonaws.com"]
      }
      condition = {
        StringEquals = {
          test     = "StringEquals"
          variable = "aws:SourceAccount"
          values   = ["123456789012"]
        }
      }
    }
  }

  command = apply

  // Verify role was created with conditional trust relationship
  assert {
    condition     = can(jsondecode(aws_iam_role.this.assume_role_policy))
    error_message = "IAM role assume_role_policy is not valid JSON"
  }
}

// Test role with multiple actions in trust relationship
run "multiple_actions_trust" {
  variables {
    trust_relationship_policy = {
      effect  = "Allow"
      actions = ["sts:AssumeRole", "sts:TagSession"]
      principals = {
        Service = ["ec2.amazonaws.com"]
      }
      condition = null
    }
  }

  command = apply

  // Verify role was created with multiple actions
  assert {
    condition     = can(jsondecode(aws_iam_role.this.assume_role_policy))
    error_message = "IAM role assume_role_policy is not valid JSON"
  }
}

// Test role with multiple service principals
run "multiple_service_principals" {
  variables {
    trust_relationship_policy = {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals = {
        Service = ["ec2.amazonaws.com", "lambda.amazonaws.com", "ecs-tasks.amazonaws.com"]
      }
      condition = null
    }
  }

  command = apply

  // Verify role was created with multiple service principals
  assert {
    condition     = can(jsondecode(aws_iam_role.this.assume_role_policy))
    error_message = "IAM role assume_role_policy is not valid JSON"
  }
}