# terraform-provider-snyk

[![License: MPL-2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![OpenTofu](https://img.shields.io/badge/OpenTofu-%3E%3D1.0-7B42BC?logo=opentofu&logoColor=white)](https://opentofu.org)

An OpenTofu / Terraform provider for managing repository monitoring in [Snyk](https://snyk.io).

Add a resource block, run `tofu apply`, and Snyk starts scanning your repo for vulnerabilities. Remove it, and the Snyk projects are cleaned up automatically.

## Quick Start

```hcl
terraform {
  required_providers {
    snyk = {
      source = "factory/snyk"
    }
  }
}

provider "snyk" {}

resource "snyk_monitored_repo" "my_app" {
  owner            = "my-org"
  repo             = "my-app"
  branch           = "main"
  integration_type = "github-enterprise"
}
```

```sh
export SNYK_API_KEY="your-snyk-api-token"
export SNYK_ORG_ID="your-snyk-org-uuid"
tofu apply
```

## Authentication

The provider supports two authentication methods (mutually exclusive):

| Method | Attributes | Environment Variables | Notes |
|--------|-----------|----------------------|-------|
| **API Key** (recommended) | `api_key` | `SNYK_API_KEY` | Works with all endpoints including import |
| **OAuth 2.0** | `client_id` + `client_secret` | `SNYK_CLIENT_ID` + `SNYK_CLIENT_SECRET` | Does **not** work with the v1 import endpoint |

Both methods also require `org_id` (or `SNYK_ORG_ID`).

> **Note:** The API key approach is recommended because Snyk's v1 import endpoint—used to start monitoring a repository—rejects OAuth Bearer tokens.

### Service Account Setup

Create an **Org-level service account** in Snyk with the **Org Admin** role (the import endpoint requires admin access):

**Settings → Service Accounts → Create a service account → Auth Type: API token**

## Provider Configuration

```hcl
provider "snyk" {
  # API key auth (recommended)
  api_key = var.snyk_api_key  # or set SNYK_API_KEY

  # OAuth auth (alternative — does not support imports)
  # client_id     = var.snyk_client_id      # or set SNYK_CLIENT_ID
  # client_secret = var.snyk_client_secret  # or set SNYK_CLIENT_SECRET

  org_id = var.snyk_org_id  # or set SNYK_ORG_ID
}
```

## Resources

### `snyk_monitored_repo`

Imports a repository into Snyk for monitoring. Snyk detects all supported manifest files (e.g., `go.mod`, `package.json`, `pom.xml`) and creates a project for each one.

#### Arguments

| Name | Required | Default | Description |
|------|:--------:|---------|-------------|
| `owner` | Yes | — | Repository owner (GitHub org or username) |
| `repo` | Yes | — | Repository name |
| `branch` | No | `""` (default branch) | Branch to monitor |
| `integration_type` | No | `"github"` | Snyk integration type (`github`, `github-enterprise`, `gitlab`, `bitbucket-cloud`, etc.) |

#### Attributes

| Name | Description |
|------|-------------|
| `id` | Comma-separated Snyk project IDs |
| `project_ids` | List of Snyk project IDs created for this repository |

#### Example

```hcl
resource "snyk_monitored_repo" "backend" {
  owner            = "my-org"
  repo             = "backend-api"
  branch           = "main"
  integration_type = "github-enterprise"
}

output "project_ids" {
  value = snyk_monitored_repo.backend.project_ids
}
```

## Importing Existing Repositories

If a repository is already monitored in Snyk (added via the UI or another tool), you can bring it under OpenTofu management:

```sh
tofu import snyk_monitored_repo.backend "my-org/backend-api"
```

The provider looks up the Snyk target by display name, discovers all projects under it, and populates the state automatically. No need to find individual project IDs.

## Lifecycle

| Operation | Behavior |
|-----------|----------|
| **Create** | Calls the Snyk v1 import endpoint, polls until complete, stores all project IDs |
| **Read** | Verifies each stored project still exists; removes from state if all deleted externally |
| **Update** | All attributes trigger destroy + recreate (Snyk has no in-place update) |
| **Delete** | Deletes every Snyk project associated with the repository |
| **Import** | Accepts `"owner/repo"`, looks up target via REST API, reconstructs full state |

## Building from Source

```sh
git clone https://github.com/factory-AI/terraform-provider-snyk.git
cd terraform-provider-snyk
go build -o terraform-provider-snyk .
```

### Local Development

Add to `~/.tofurc` (or `~/.terraformrc`):

```hcl
provider_installation {
  dev_overrides {
    "factory/snyk" = "/path/to/terraform-provider-snyk"
  }
  direct {}
}
```

With dev overrides, skip `tofu init` and go straight to `tofu plan`.

## Requirements

- **Go 1.21+** (to build)
- **OpenTofu >= 1.0** or **Terraform >= 1.0**
- A Snyk account with a configured SCM integration

## Author

[Factory.ai](https://factory.ai)

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
