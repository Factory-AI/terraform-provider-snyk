---
page_title: "Snyk Provider"
subcategory: ""
description: |-
  Manages resources in Snyk.io via the Snyk API.
---

# Snyk Provider

The Snyk provider allows you to manage resources in [Snyk.io](https://snyk.io) via the Snyk API. Currently, it supports importing and monitoring source code repositories.

## Authentication

The provider supports two authentication methods:

### API Key (Recommended)

Use a Snyk API token, which works with all API endpoints including the import functionality.

```terraform
provider "snyk" {
  api_key = var.snyk_api_key
  org_id  = var.snyk_org_id
}
```

Or set via environment variables:
- `SNYK_API_KEY`
- `SNYK_ORG_ID`

### OAuth 2.0

Use OAuth 2.0 client credentials for service account authentication.

~> **Note:** The v1 import endpoint does not support OAuth; use `api_key` if you need imports.

```terraform
provider "snyk" {
  client_id     = var.snyk_client_id
  client_secret = var.snyk_client_secret
  org_id        = var.snyk_org_id
}
```

Or set via environment variables:
- `SNYK_CLIENT_ID`
- `SNYK_CLIENT_SECRET`
- `SNYK_ORG_ID`

## Example Usage

```terraform
terraform {
  required_providers {
    snyk = {
      source  = "factory/snyk"
      version = "~> 0.1"
    }
  }
}

provider "snyk" {
  # Credentials can be set via environment variables
}

resource "snyk_monitored_repo" "example" {
  owner = "my-org"
  repo  = "my-repo"
}
```

## Schema

### Optional

- `api_key` (String, Sensitive) - Snyk API token. Works with all API endpoints. Can also be set via `SNYK_API_KEY`. Mutually exclusive with `client_id`/`client_secret`.
- `client_id` (String) - OAuth 2.0 client ID for the Snyk service account. Can also be set via `SNYK_CLIENT_ID`. Must be paired with `client_secret`.
- `client_secret` (String, Sensitive) - OAuth 2.0 client secret for the Snyk service account. Can also be set via `SNYK_CLIENT_SECRET`.
- `org_id` (String) - Snyk organization ID. Can also be set via `SNYK_ORG_ID`.
