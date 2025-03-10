# AWS IAM Role Module Tests

This directory contains tests for the AWS IAM Role Terraform module using Terraform's built-in testing framework.

## Test Files

- **main.tftest.hcl**: Basic functionality tests for role creation with default values
- **policy.tftest.hcl**: Tests for inline policies and managed policy attachments
- **trust_relationship.tftest.hcl**: Tests for different trust relationship configurations
- **negative.tftest.hcl**: Negative tests with invalid inputs to verify proper error handling
- **outputs.tftest.hcl**: Tests focused on validating module outputs
- **complex.tftest.hcl**: Complex scenario tests combining multiple module features
- **lambda_and_boundary.tftest.hcl**: Tests specifically for Lambda roles and permissions boundaries

## Running Tests

To run all tests from the module root directory:

```bash
terraform test
terraform test -var-file=filename.tfvars -verbose 
```

To run a specific test file:

```bash
terraform test -filter="tests/policy.tftest.hcl"
```

## Test Design

These tests follow these principles:

1. **Comprehensive Coverage**: Tests cover both basic functionality and edge cases
2. **Isolation**: Each test file focuses on a specific aspect of the module
3. **Validation**: Tests use assertions to validate expected behavior
4. **Documentation**: Each test includes comments explaining its purpose
5. **Idempotency**: Tests can be run multiple times without side effects

## Adding New Tests

When adding new tests:

1. Create a new `.tftest.hcl` file in this directory
2. Follow the established structure with clear variables and run blocks
3. Include descriptive comments explaining the test's purpose
4. Use meaningful test names and assertion error messages
5. Update this README to include the new test file

## Test Prerequisites

These tests assume:

1. AWS provider is properly configured
2. Sufficient IAM permissions to create and manage IAM roles
3. Terraform version ~> 1.9 (which includes the built-in testing framework)
