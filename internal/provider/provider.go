package provider

import (
	"context"
	"os"

	"github.com/factory-AI/tofu-snyk/internal/snyk"
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
	ClientID     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
	OrgID        types.String `tfsdk:"org_id"`
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
			"client_id": schema.StringAttribute{
				Description: "OAuth 2.0 client ID for the Snyk service account. Can also be set via SNYK_CLIENT_ID.",
				Optional:    true,
			},
			"client_secret": schema.StringAttribute{
				Description: "OAuth 2.0 client secret for the Snyk service account. Can also be set via SNYK_CLIENT_SECRET.",
				Optional:    true,
				Sensitive:   true,
			},
			"org_id": schema.StringAttribute{
				Description: "Snyk organization ID. Can also be set via SNYK_ORG_ID.",
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

	clientID := os.Getenv("SNYK_CLIENT_ID")
	if !config.ClientID.IsNull() && !config.ClientID.IsUnknown() {
		clientID = config.ClientID.ValueString()
	}
	if clientID == "" {
		resp.Diagnostics.AddError(
			"Missing Snyk client ID",
			"Set the client_id provider attribute or the SNYK_CLIENT_ID environment variable.",
		)
	}

	clientSecret := os.Getenv("SNYK_CLIENT_SECRET")
	if !config.ClientSecret.IsNull() && !config.ClientSecret.IsUnknown() {
		clientSecret = config.ClientSecret.ValueString()
	}
	if clientSecret == "" {
		resp.Diagnostics.AddError(
			"Missing Snyk client secret",
			"Set the client_secret provider attribute or the SNYK_CLIENT_SECRET environment variable.",
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

	client := snyk.NewClient(clientID, clientSecret, orgID)
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
