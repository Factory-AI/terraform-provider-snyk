package provider

import (
	"context"
	"os"

	"github.com/example/terraform-provider-snyk/internal/snyk"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = &SnykProvider{}

// SnykProvider implements the OpenTofu provider interface for Snyk.
type SnykProvider struct {
	version string
}

// SnykProviderModel holds the provider-level configuration values.
type SnykProviderModel struct {
	APIKey types.String `tfsdk:"api_key"`
	OrgID  types.String `tfsdk:"org_id"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &SnykProvider{version: version}
	}
}

func (p *SnykProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "snyk"
	resp.Version = p.version
}

func (p *SnykProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages resources in Snyk.io via the Snyk v1 API.",
		Attributes: map[string]schema.Attribute{
			"api_key": schema.StringAttribute{
				Description: "Snyk API token. Can also be set via the SNYK_API_KEY environment variable.",
				Optional:    true,
				Sensitive:   true,
			},
			"org_id": schema.StringAttribute{
				Description: "Snyk organization ID. Can also be set via the SNYK_ORG_ID environment variable.",
				Optional:    true,
			},
		},
	}
}

func (p *SnykProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config SnykProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	apiKey := os.Getenv("SNYK_API_KEY")
	if !config.APIKey.IsNull() && !config.APIKey.IsUnknown() {
		apiKey = config.APIKey.ValueString()
	}
	if apiKey == "" {
		resp.Diagnostics.AddError(
			"Missing Snyk API key",
			"Set the api_key provider attribute or the SNYK_API_KEY environment variable.",
		)
	}

	orgID := os.Getenv("SNYK_ORG_ID")
	if !config.OrgID.IsNull() && !config.OrgID.IsUnknown() {
		orgID = config.OrgID.ValueString()
	}
	if orgID == "" {
		resp.Diagnostics.AddError(
			"Missing Snyk org ID",
			"Set the org_id provider attribute or the SNYK_ORG_ID environment variable.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	client := snyk.NewClient(apiKey, orgID)
	resp.ResourceData = client
	resp.DataSourceData = client
}

func (p *SnykProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewMonitoredRepoResource,
	}
}

func (p *SnykProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
