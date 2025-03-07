################################################################################
# IAM Role
################################################################################

# Trusted entities that can assume this role
data "aws_iam_policy_document" "trust_relationship" {
  statement {
    effect  = var.trust_relationship_policy.effect
    actions = var.trust_relationship_policy.actions

    dynamic "principals" {
      for_each = var.trust_relationship_policy.principals
      content {
        type        = principals.key
        identifiers = principals.value
      }
    }

    dynamic "condition" {
      for_each = var.trust_relationship_policy.condition != null ? var.trust_relationship_policy.condition : {}
      content {
        test     = condition.value.test
        variable = condition.value.variable
        values   = condition.value.values
      }
    }
  }
}

# IAM role
resource "aws_iam_role" "this" {
  name                  = local.role_name
  path                  = var.role_path
  description           = var.role_description
  max_session_duration  = var.role_max_session_duration
  assume_role_policy    = data.aws_iam_policy_document.trust_relationship.json
  force_detach_policies = var.force_detach_policies
  permissions_boundary  = var.permissions_boundary
  tags                  = var.tags
}

# Permissions for the role
data "aws_iam_policy_document" "role_policies" {
  for_each = var.role_policies

  statement {
    effect    = each.value.effect
    actions   = each.value.actions
    resources = each.value.resources

    dynamic "condition" {
      for_each = each.value.condition != null ? each.value.condition : {}
      content {
        test     = condition.value.test
        variable = condition.value.variable
        values   = condition.value.values
      }
    }
  }
}

# Attach role policies
resource "aws_iam_role_policy" "role_policies" {
  for_each = var.role_policies

  name   = each.key
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.role_policies[each.key].json
}

# Attach managed policies
resource "aws_iam_role_policy_attachment" "managed_policy" {
  count = length(var.managed_policy_arns)

  role       = aws_iam_role.this.name
  policy_arn = var.managed_policy_arns[count.index]
}

