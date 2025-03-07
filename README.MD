# AWS IAM Role Terraform Module

This Terraform module creates an IAM role with customizable trust relationships, inline policies, and attached managed policies.

## ⚠️ Disclaimer

**USE AT YOUR OWN RISK**. This tool is provided "as is", without warranty of any kind, express or implied. Neither the authors nor contributors shall be liable for any damages or consequences arising from the use of this tool. Always:
* 🧪 Test in a non-production environment first
* ✓ Verify results manually before taking action
* 💾 Maintain proper backups
* 🔒 Follow your organization's security policies

## Features

- 🔑 Create IAM roles with configurable session duration and permissions boundary
- 🤝 Define custom trust relationships (assume role policies)
- 📝 Add inline policies with granular permissions
- 🔌 Attach AWS managed policies
- 🏷️ Apply tags for better resource management
- 🛣️ Configurable path and description

## Usage

```hcl
module "example_iam_role" {
  source = "path/to/module"

  role_name        = "example-role"
  role_description = "Example role for demonstration purposes"
  
  trust_relationship_policy = {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals = {
      Service = ["ec2.amazonaws.com"]
    }
  }

  role_policies = {
    "s3_access" = {
      effect    = "Allow"
      actions   = ["s3:GetObject", "s3:PutObject"]
      resources = ["arn:aws:s3:::example-bucket/*"]
    }
  }

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
  ]

  tags = {
    Environment = "Production"
    Project     = "ExampleProject"
  }
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| role_name | Name of the IAM role | `string` | n/a | yes |
| role_path | Path for the IAM role | `string` | `"/"` | no |
| role_description | Description for the IAM role | `string` | `""` | no |
| role_max_session_duration | Maximum session duration in seconds for the IAM role | `number` | `3600` | no |
| trust_relationship_policy | Trust relationship policy configuration | `object` | n/a | yes |
| role_policies | Map of policy names to policy configurations | `map(object)` | `{}` | no |
| managed_policy_arns | List of managed IAM policy ARNs to attach to the IAM role | `list(string)` | `[]` | no |
| force_detach_policies | Whether to force detach policies when destroying the IAM role | `bool` | `false` | no |
| permissions_boundary | ARN of the policy that is used to set the permissions boundary for the role | `string` | `null` | no |
| tags | A map of tags to add to IAM role | `map(string)` | `{}` | no |

### Trust Relationship Policy Structure

```hcl
trust_relationship_policy = {
  effect     = "Allow"              # Effect of the policy (Allow/Deny)
  actions    = ["sts:AssumeRole"]   # Actions permitted for assuming the role
  principals = {                    # Map of principal types to identifiers
    Service = ["ec2.amazonaws.com"] # Example for service principal
  }
  condition = {                     # Optional conditions (map)
    StringEquals = {
      test     = "StringEquals"
      variable = "aws:RequestTag/Environment"
      values   = ["Production"]
    }
  }
}
```

### Role Policies Structure

```hcl
role_policies = {
  "policy_name" = {
    effect    = "Allow"                              # Effect of the policy (Allow/Deny)
    actions   = ["s3:GetObject", "s3:PutObject"]     # List of IAM actions
    resources = ["arn:aws:s3:::example-bucket/*"]    # List of resource ARNs
    condition = {                                    # Optional conditions (map)
      StringEquals = {
        test     = "StringEquals"
        variable = "aws:RequestTag/Environment"
        values   = ["Production"]
      }
    }
  }
}
```

## Outputs

| Name | Description |
|------|-------------|
| arn | ARN of the IAM role |
| name | Name of the IAM role |
| id | ID of the IAM role |
| unique_id | Unique ID assigned by AWS to the IAM role |
| path | Path of the IAM role |
| policy_attachments | Map of policy attachments |
| inline_policies | Map of inline policy names |

## Best Practices

- Follow the principle of least privilege when defining IAM policies
- Use conditions to further restrict policy scope when appropriate
- Consider using a permissions boundary for added security
- Apply meaningful tags for better resource management
- Use descriptive names for inline policies

## Examples

### EC2 Instance Role

```hcl
module "ec2_instance_role" {
  source = "path/to/module"

  role_name = "ec2-instance-role"
  
  trust_relationship_policy = {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals = {
      Service = ["ec2.amazonaws.com"]
    }
  }

  role_policies = {
    "s3_read_only" = {
      effect    = "Allow"
      actions   = ["s3:GetObject", "s3:ListBucket"]
      resources = [
        "arn:aws:s3:::app-config-bucket",
        "arn:aws:s3:::app-config-bucket/*"
      ]
    }
  }

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  ]

  tags = {
    Environment = "Production"
    Service     = "WebApp"
  }
}
```

### Lambda Function Role with Conditions

```hcl
module "lambda_role" {
  source = "path/to/module"

  role_name        = "lambda-processor-role"
  role_description = "Role for Lambda data processor"
  
  trust_relationship_policy = {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals = {
      Service = ["lambda.amazonaws.com"]
    }
  }

  role_policies = {
    "dynamodb_access" = {
      effect    = "Allow"
      actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"]
      resources = ["arn:aws:dynamodb:*:*:table/data-processing-table"]
      condition = {
        StringEquals = {
          test     = "StringEquals"
          variable = "aws:RequestTag/Environment"
          values   = ["Production"]
        }
      }
    },
    "s3_log_access" = {
      effect    = "Allow"
      actions   = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListBucket"
      ]
      resources = [
        "arn:aws:s3:::lambda-processing-logs",
        "arn:aws:s3:::lambda-processing-logs/*"
      ]
    }
  }

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  ]

  tags = {
    Environment = "Production"
    Function    = "DataProcessing"
  }
}
```

## Requirements

| Name | Version |
|------|---------|
| terraform | ~> 1.9 |
| aws | ~> 5.57 |
        
## License

MIT


## Credits

Refactoring and enhancement guidance provided with assistance from Claude AI (Anthropic).
