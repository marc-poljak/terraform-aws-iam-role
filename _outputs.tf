################################################################################
# Expose Information about Module Instances
################################################################################

output "arn" {
  description = "ARN of the IAM role"
  value       = aws_iam_role.this.arn
}

output "name" {
  description = "Name of the IAM role"
  value       = aws_iam_role.this.name
}

output "id" {
  description = "ID of the IAM role"
  value       = aws_iam_role.this.id
}

output "unique_id" {
  description = "Unique ID assigned by AWS to the IAM role"
  value       = aws_iam_role.this.unique_id
}

output "path" {
  description = "Path of the IAM role"
  value       = aws_iam_role.this.path
}

output "policy_attachments" {
  description = "List of attached policy ARNs"
  value       = var.managed_policy_arns
}

output "inline_policies" {
  description = "Map of inline policy names"
  value       = { for k, v in aws_iam_role_policy.role_policies : k => v.name }
}