package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/factory-AI/terraform-provider-snyk/internal/snyk"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &MonitoredRepoResource{}
var _ resource.ResourceWithImportState = &MonitoredRepoResource{}

// NewMonitoredRepoResource is the factory function for this resource.
func NewMonitoredRepoResource() resource.Resource {
	return &MonitoredRepoResource{}
}

// MonitoredRepoResource manages a repository monitored by Snyk.
type MonitoredRepoResource struct {
	client *snyk.Client
}

// MonitoredRepoModel is the Terraform state model.
type MonitoredRepoModel struct {
	// Unique ID used by Terraform. We use the first project ID or the
	// comma-joined list if multiple projects were created.
	ID types.String `tfsdk:"id"`

	// owner/repo identify the source repository.
	Owner types.String `tfsdk:"owner"`
	Repo  types.String `tfsdk:"repo"`

	// Branch to monitor. Empty string means Snyk uses the default branch.
	Branch types.String `tfsdk:"branch"`

	// Integration type: "github", "github-enterprise", "gitlab",
	// "bitbucket-cloud", "bitbucket-server", "azure-repos", etc.
	IntegrationType types.String `tfsdk:"integration_type"`

	// Snyk project IDs created by the import (one per detected manifest file).
	ProjectIDs types.List `tfsdk:"project_ids"`
}

func (r *MonitoredRepoResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_monitored_repo"
}

func (r *MonitoredRepoResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Imports a source-code repository into Snyk and keeps it monitored. " +
			"Destroying this resource removes all Snyk projects that were created for the repository.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Internal identifier (comma-separated Snyk project IDs).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"owner": schema.StringAttribute{
				Required:    true,
				Description: "Repository owner (GitHub organisation or username).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"repo": schema.StringAttribute{
				Required:    true,
				Description: "Repository name.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"branch": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Branch to monitor. Defaults to the repository's default branch when left empty.",
				Default:     stringdefault.StaticString(""),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"integration_type": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Snyk integration type. Defaults to \"github\".",
				Default:     stringdefault.StaticString("github"),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"project_ids": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "List of Snyk project IDs created for this repository (one per detected manifest file).",
			},
		},
	}
}

func (r *MonitoredRepoResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*snyk.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data type",
			fmt.Sprintf("Expected *snyk.Client, got %T", req.ProviderData))
		return
	}
	r.client = client
}

// Create imports the repository into Snyk and waits for the job to complete.
func (r *MonitoredRepoResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan MonitoredRepoModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	integrationType := plan.IntegrationType.ValueString()
	integrationID, err := r.client.GetIntegrationID(integrationType)
	if err != nil {
		resp.Diagnostics.AddError("Failed to resolve integration ID", err.Error())
		return
	}

	importReq := snyk.ImportRequest{
		Target: snyk.ImportTarget{
			Owner:  plan.Owner.ValueString(),
			Name:   plan.Repo.ValueString(),
			Branch: plan.Branch.ValueString(),
		},
	}

	jobID, err := r.client.StartImport(integrationID, importReq)
	if err != nil {
		resp.Diagnostics.AddError("Failed to start Snyk import", err.Error())
		return
	}

	projectIDs, err := r.client.WaitForImport(integrationID, jobID, 5*time.Second, 10*time.Minute)
	if err != nil {
		resp.Diagnostics.AddError("Import job failed", err.Error())
		return
	}
	if len(projectIDs) == 0 {
		resp.Diagnostics.AddError(
			"Import produced no projects",
			fmt.Sprintf("Snyk found no supported manifest files in %s/%s. "+
				"Make sure the repository contains a recognised dependency file (package.json, pom.xml, go.mod, etc.).",
				plan.Owner.ValueString(), plan.Repo.ValueString()),
		)
		return
	}

	plan.ID = types.StringValue(strings.Join(projectIDs, ","))
	plan.ProjectIDs = stringSliceToList(projectIDs)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read verifies that each stored project still exists in Snyk.
func (r *MonitoredRepoResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state MonitoredRepoModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	projectIDs := listToStringSlice(state.ProjectIDs)
	surviving := make([]string, 0, len(projectIDs))

	for _, id := range projectIDs {
		project, err := r.client.GetProject(id)
		if err != nil {
			resp.Diagnostics.AddError("Failed to read Snyk project", err.Error())
			return
		}
		if project != nil {
			surviving = append(surviving, id)
		}
	}

	if len(surviving) == 0 {
		// All projects have been removed outside of Terraform; signal recreation.
		resp.State.RemoveResource(ctx)
		return
	}

	state.ProjectIDs = stringSliceToList(surviving)
	state.ID = types.StringValue(strings.Join(surviving, ","))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is a no-op because every mutable attribute has RequiresReplace set.
func (r *MonitoredRepoResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
}

// Delete removes all Snyk projects associated with the repository.
func (r *MonitoredRepoResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state MonitoredRepoModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	for _, id := range listToStringSlice(state.ProjectIDs) {
		if err := r.client.DeleteProject(id); err != nil {
			resp.Diagnostics.AddError("Failed to delete Snyk project", err.Error())
			return
		}
	}
}

// ImportState supports `tofu import snyk_monitored_repo.name "owner/repo"`.
//
// The provider looks up the Snyk target matching the display name, discovers
// all projects under it, and reads the first project to derive branch and
// integration type.
func (r *MonitoredRepoResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError(
			"Invalid import ID",
			fmt.Sprintf("Expected \"owner/repo\", got %q.", req.ID),
		)
		return
	}
	owner, repo := parts[0], parts[1]
	displayName := owner + "/" + repo

	targetID, err := r.client.FindTargetIDByDisplayName(displayName)
	if err != nil {
		resp.Diagnostics.AddError("Failed to find Snyk target", err.Error())
		return
	}

	projectIDs, err := r.client.ListProjectIDsByTarget(targetID)
	if err != nil {
		resp.Diagnostics.AddError("Failed to list projects for target", err.Error())
		return
	}
	if len(projectIDs) == 0 {
		resp.Diagnostics.AddError(
			"No projects found",
			fmt.Sprintf("Target %q exists but has no projects.", displayName),
		)
		return
	}

	first, err := r.client.GetProject(projectIDs[0])
	if err != nil {
		resp.Diagnostics.AddError("Failed to read Snyk project during import", err.Error())
		return
	}
	if first == nil {
		resp.Diagnostics.AddError("Project not found", fmt.Sprintf("Snyk project %s does not exist.", projectIDs[0]))
		return
	}

	state := MonitoredRepoModel{
		ID:              types.StringValue(strings.Join(projectIDs, ",")),
		Owner:           types.StringValue(owner),
		Repo:            types.StringValue(repo),
		Branch:          types.StringValue(first.Branch),
		IntegrationType: types.StringValue(first.Origin),
		ProjectIDs:      stringSliceToList(projectIDs),
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// parseProjectName splits a Snyk project name ("owner/repo:manifest") into
// owner and repo. It returns empty strings if the name cannot be parsed.
func parseProjectName(name string) (owner, repo string) {
	// Strip any trailing ":manifest-file" portion.
	if idx := strings.Index(name, ":"); idx != -1 {
		name = name[:idx]
	}
	parts := strings.SplitN(name, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", name
}

// stringSliceToList converts a []string to a types.List of StringType.
func stringSliceToList(ss []string) types.List {
	elems := make([]attr.Value, len(ss))
	for i, s := range ss {
		elems[i] = types.StringValue(s)
	}
	list, _ := types.ListValue(types.StringType, elems)
	return list
}

// listToStringSlice extracts strings from a types.List.
func listToStringSlice(l types.List) []string {
	elems := l.Elements()
	ss := make([]string, 0, len(elems))
	for _, e := range elems {
		if sv, ok := e.(types.String); ok {
			ss = append(ss, sv.ValueString())
		}
	}
	return ss
}
