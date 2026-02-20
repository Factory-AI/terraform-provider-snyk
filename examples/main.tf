terraform {
  required_providers {
    snyk = {
      source  = "example/snyk"
      version = "~> 0.1"
    }
  }
}

# Configure the provider.
# Credentials can also be supplied via the SNYK_API_KEY and SNYK_ORG_ID
# environment variables so you don't have to hard-code secrets.
provider "snyk" {
  # api_key = var.snyk_api_key   # or set SNYK_API_KEY
  # org_id  = var.snyk_org_id    # or set SNYK_ORG_ID
}

# Monitor a public GitHub repository in Snyk.
resource "snyk_monitored_repo" "foo_bar" {
  owner = "foo"
  repo  = "bar"
  # branch           = "main"   # optional; defaults to the repo's default branch
  # integration_type = "github" # optional; defaults to "github"
}

# Output all Snyk project IDs created for the repository.
output "snyk_project_ids" {
  value = snyk_monitored_repo.foo_bar.project_ids
}

# --- Importing an already-monitored repository ---
#
# If "foo/bar" is already in Snyk, find its project ID(s) in the Snyk UI or
# via the API, then run:
#
#   tofu import snyk_monitored_repo.foo_bar "<project-id-1>,<project-id-2>"
#
# After the import the resource block above can manage the repository
# alongside any other infrastructure.
