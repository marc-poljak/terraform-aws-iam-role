################################################################################
# Variables
################################################################################

variable "role_name" {
  description = "Name of the IAM role"
  type        = string
}

variable "role_path" {
  description = "Path for the IAM role"
  type        = string
  default     = "/"
}

variable "role_description" {
  description = "Description for the IAM role"
  type        = string
  default     = ""
}

variable "role_max_session_duration" {
  description = "Maximum session duration in seconds for the IAM role"
  type        = number
  default     = 3600
}

variable "trust_relationship_policy" {
  description = "Trust relationship policy configuration"
  type = object({
    effect     = string
    actions    = list(string)
    principals = map(list(string))
    condition = optional(map(object({
      test     = string
      variable = string
      values   = list(string)
    })))
  })
}

variable "role_policies" {
  description = "Map of policy names to policy configurations"
  type = map(object({
    effect    = string
    actions   = list(string)
    resources = list(string)
    condition = optional(map(object({
      test     = string
      variable = string
      values   = list(string)
    })))
  }))
  default = {}
}

variable "managed_policy_arns" {
  description = "List of managed IAM policy ARNs to attach to the IAM role"
  type        = list(string)
  default     = []
}

variable "force_detach_policies" {
  description = "Whether to force detach policies when destroying the IAM role"
  type        = bool
  default     = false
}

variable "permissions_boundary" {
  description = "ARN of the policy that is used to set the permissions boundary for the role"
  type        = string
  default     = null
}

variable "tags" {
  description = "A map of tags to add to IAM role"
  type        = map(string)
  default     = {}
}