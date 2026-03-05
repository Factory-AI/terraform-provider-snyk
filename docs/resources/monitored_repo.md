---
page_title: "snyk_monitored_repo Resource - terraform-provider-snyk"
subcategory: ""
description: |-
  Imports a source-code repository into Snyk and keeps it monitored.
---

# snyk_monitored_repo (Resource)

Imports a source-code repository into Snyk and keeps it monitored. Destroying this resource removes all Snyk projects that were created for the repository.

## Example Usage

```terraform
resource "snyk_monitored_repo" "example" {
  owner = "my-org"
  repo  = "my-repo"
}
```

### With Branch and Integration Type

```terraform
resource "snyk_monitored_repo" "example" {
  owner            = "my-org"
  repo             = "my-repo"
  branch           = "main"
  integration_type = "github"
}
```

## Schema

### Required

- `owner` (String) - Repository owner (GitHub organisation or username).
- `repo` (String) - Repository name.

### Optional

- `branch` (String) - Branch to monitor. Defaults to the repository's default branch when left empty.
- `integration_type` (String) - Snyk integration type. Defaults to `"github"`. Supported values include: `github`, `github-enterprise`, `gitlab`, `bitbucket-cloud`, `bitbucket-server`, `azure-repos`.

### Read-Only

- `id` (String) - Internal identifier (comma-separated Snyk project IDs).
- `project_ids` (List of String) - List of Snyk project IDs created for this repository (one per detected manifest file).

## Import

Import an existing monitored repository using the `owner/repo` format:

```shell
terraform import snyk_monitored_repo.example "owner/repo"
```

For example:

```shell
terraform import snyk_monitored_repo.my_app "my-org/my-app"
```
