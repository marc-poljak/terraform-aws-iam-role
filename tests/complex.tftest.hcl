// complex.tftest.hcl - Complex Scenario Tests for AWS IAM Role Module
//
// This file contains tests for complex scenarios that combine multiple features
// of the module to verify they work together properly.

variables {
  // Basic required variables
  role_name = "test-complex-role"
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
  role_description         = "Test role for complex scenarios"
  role_max_session_duration = 3600
  force_detach_policies    = false
  permissions_boundary     = null
  tags                     = { ManagedBy = "Terraform" }
  role_policies           = {}
  managed_policy_arns     = []
}

// Test comprehensive EC2 instance role scenario
run "ec2_instance_role_scenario" {
  variables {
    role_name = "ec2-instance-role"
    role_description = "Role for EC2 instances in production environment"
    role_path = "/service-roles/ec2/"
    role_max_session_duration = 7200

    trust_relationship_policy = {
      effect  = "Allow"
      actions = ["sts:AssumeRole", "sts:TagSession"]
      principals = {
        Service = ["ec2.amazonaws.com"]
      }
      condition = {
        StringEquals = {
          test     = "StringEquals"
          variable = "aws:RequestTag/Environment"
          values   = ["Production"]
        }
      }
    }

    role_policies = {
      "s3_access" = {
        effect    = "Allow"
        actions   = ["s3:GetObject", "s3:ListBucket"]
        resources = [
          "arn:aws:s3:::app-config-bucket",
          "arn:aws:s3:::app-config-bucket/*"
        ]
        condition = null
      },
      "dynamodb_read" = {
        effect    = "Allow"
        actions   = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"]
        resources = ["arn:aws:dynamodb:*:*:table/app-data-table"]
        condition = {
          StringEquals = {
            test     = "StringEquals"
            variable = "aws:RequestTag/Project"
            values   = ["MainApp"]
          }
        }
      }
    }

    managed_policy_arns = [
      "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
      "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
    ]

    tags = {
      Environment = "Production"
      Service     = "EC2"
      Project     = "MainApp"
      ManagedBy   = "Terraform"
    }
  }

  command = apply

  // Verify role basic attributes
  assert {
    condition     = output.name == "ec2-instance-role"
    error_message = "Role name output doesn't match expected value"
  }

  assert {
    condition     = output.path == "/service-roles/ec2/"
    error_message = "Role path output doesn't match expected value"
  }

  // Verify inline policies
  assert {
    condition     = length(output.inline_policies) == 2
    error_message = "Expected 2 inline policies"
  }

  assert {
    condition     = contains(keys(output.inline_policies), "s3_access") && contains(keys(output.inline_policies), "dynamodb_read")
    error_message = "Expected s3_access and dynamodb_read policies"
  }

  // Verify managed policies
  assert {
    condition     = length(output.policy_attachments) == 2
    error_message = "Expected 2 managed policies"
  }

  assert {
    condition     = contains(output.policy_attachments, "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore")
    error_message = "Expected AmazonSSMManagedInstanceCore managed policy to be attached"
  }

  assert {
    condition     = contains(output.policy_attachments, "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy")
    error_message = "Expected CloudWatchAgentServerPolicy managed policy to be attached"
  }

  // Verify tags
  assert {
    condition     = length(aws_iam_role.this.tags) == 4
    error_message = "Expected 4 tags on the role"
  }

  assert {
    condition     = aws_iam_role.this.tags["Environment"] == "Production"
    error_message = "Environment tag value doesn't match expected value"
  }

  assert {
    condition     = aws_iam_role.this.tags["Service"] == "EC2"
    error_message = "Service tag value doesn't match expected value"
  }

  assert {
    condition     = aws_iam_role.this.tags["Project"] == "MainApp"
    error_message = "Project tag value doesn't match expected value"
  }

  // Verify session duration
  assert {
    condition     = aws_iam_role.this.max_session_duration == 7200
    error_message = "Session duration doesn't match expected value"
  }

  // Verify trust relationship includes the condition
  assert {
    condition     = can(jsondecode(aws_iam_role.this.assume_role_policy))
    error_message = "IAM role assume_role_policy is not valid JSON"
  }
}

// Test combined service role with custom path and multiple principals
run "service_role_with_multiple_principals" {
  variables {
    role_name = "multi-service-role"
    role_description = "Role that can be assumed by multiple services"
    role_path = "/service-roles/shared/"

    trust_relationship_policy = {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals = {
        Service = ["lambda.amazonaws.com", "ecs-tasks.amazonaws.com", "states.amazonaws.com"]
      }
      condition = null
    }

    role_policies = {
      "read_only_access" = {
        effect    = "Allow"
        actions   = [
          "s3:GetObject",
          "s3:ListBucket",
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        resources = ["*"]
        condition = null
      },
      "restricted_write_access" = {
        effect    = "Allow"
        actions   = [
          "s3:PutObject",
          "dynamodb:PutItem"
        ]
        resources = [
          "arn:aws:s3:::log-bucket/*",
          "arn:aws:dynamodb:*:*:table/service-table"
        ]
        condition = null
      }
    }

    permissions_boundary = "arn:aws:iam::123456789012:policy/service-boundary"

    tags = {
      Environment = "Development"
      ManagedBy   = "Terraform"
    }
  }

  command = apply

  // Verify role creation with custom path
  assert {
    condition     = output.path == "/service-roles/shared/"
    error_message = "Role path output doesn't match expected value"
  }

  // Verify trust relationship with multiple services
  assert {
    condition     = can(jsondecode(aws_iam_role.this.assume_role_policy))
    error_message = "IAM role assume_role_policy is not valid JSON"
  }

  // Verify permissions boundary is set
  assert {
    condition     = aws_iam_role.this.permissions_boundary == "arn:aws:iam::123456789012:policy/service-boundary"
    error_message = "Permissions boundary doesn't match expected value"
  }

  // Verify inline policies
  assert {
    condition     = length(output.inline_policies) == 2
    error_message = "Expected 2 inline policies"
  }

  assert {
    condition     = contains(keys(output.inline_policies), "read_only_access") && contains(keys(output.inline_policies), "restricted_write_access")
    error_message = "Expected read_only_access and restricted_write_access policies"
  }
}