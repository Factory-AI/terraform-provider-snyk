# terraform-provider-snyk

An OpenTofu / Terraform provider for managing repository monitoring in [Snyk](https://snyk.io). Add a resource block, run `tofu apply`, and Snyk starts scanning the repo for vulnerabilities. Remove it, and the Snyk projects are cleaned up.

## Quick start

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

| Method | Attributes | Environment variables | Notes |
|--------|-----------|----------------------|-------|
| **API key** (recommended) | `api_key` | `SNYK_API_KEY` | Works with all endpoints including import |
| **OAuth 2.0 client credentials** | `client_id` + `client_secret` | `SNYK_CLIENT_ID` + `SNYK_CLIENT_SECRET` | Does **not** work with the v1 import endpoint |

Both methods also require `org_id` (or `SNYK_ORG_ID`).

The API key approach is recommended because Snyk's v1 import endpoint — used to start monitoring a repository — rejects OAuth Bearer tokens.

### Service account setup

Create an **Org-level service account** in Snyk with the **Org Admin** role. The import endpoint requires admin access.

Settings > Service Accounts > Create a service account > Auth Type: API token

## Provider configuration

```hcl
provider "snyk" {
  # API key auth (recommended)
  api_key = var.snyk_api_key  # or set SNYK_API_KEY

  # OAuth auth (alternative — does not support imports)
  # client_id     = var.snyk_client_id      # or set SNYK_CLIENT_ID
  # client_secret = var.snyk_client_secret   # or set SNYK_CLIENT_SECRET

  org_id = var.snyk_org_id  # or set SNYK_ORG_ID
}
```

## Resources

### `snyk_monitored_repo`

Imports a repository into Snyk for monitoring. Snyk detects all supported manifest files (e.g. `go.mod`, `package.json`, `pom.xml`) and creates a project for each one.

#### Arguments

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `owner` | yes | — | Repository owner (GitHub org or username) |
| `repo` | yes | — | Repository name |
| `branch` | no | `""` (default branch) | Branch to monitor |
| `integration_type` | no | `"github"` | Snyk integration type (`github`, `github-enterprise`, `gitlab`, `bitbucket-cloud`, etc.) |

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

## Importing existing repositories

If a repository is already monitored in Snyk (added via the UI or another tool), you can bring it under OpenTofu management with:

```sh
tofu import snyk_monitored_repo.backend "my-org/backend-api"
```

The provider looks up the Snyk target by display name, discovers all projects under it, and populates the state automatically. No need to find individual project IDs.

## Lifecycle

- **Create** — calls the Snyk v1 import endpoint, polls the async job until complete, stores all resulting project IDs in state.
- **Read** — checks that each stored project still exists; removes the resource from state if all projects have been deleted externally.
- **Update** — all attributes trigger a destroy + recreate (Snyk has no in-place update for imports).
- **Delete** — deletes every Snyk project associated with the repository.
- **Import** — accepts `"owner/repo"`, looks up the target via the REST API, and reconstructs full state.

## Building from source

```sh
git clone https://github.com/factory-AI/tofu-snyk.git
cd tofu-snyk
go build -o terraform-provider-snyk .
```

### Local development with dev overrides

Add to `~/.tofurc`:

```hcl
provider_installation {
  dev_overrides {
    "factory/snyk" = "/path/to/tofu-snyk"
  }
  direct {}
}
```

With dev overrides, skip `tofu init` and go straight to `tofu plan`.

## Requirements

- Go 1.21+ (to build)
- OpenTofu >= 1.0 or Terraform >= 1.0
- A Snyk Enterprise account with a configured SCM integration
