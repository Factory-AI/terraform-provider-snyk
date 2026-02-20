package snyk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const baseURL = "https://api.snyk.io/v1"

// Client is an authenticated Snyk v1 API client.
type Client struct {
	apiKey     string
	orgID      string
	httpClient *http.Client
}

// NewClient creates a new Snyk API client.
func NewClient(apiKey, orgID string) *Client {
	return &Client{
		apiKey: apiKey,
		orgID:  orgID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) OrgID() string {
	return c.orgID
}

func (c *Client) do(method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshalling request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "token "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	return resp, nil
}

func checkStatus(resp *http.Response, expected int) error {
	if resp.StatusCode != expected {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// GetIntegrationID returns the integration ID for the given integration type
// (e.g. "github", "gitlab", "bitbucket-cloud").
func (c *Client) GetIntegrationID(integrationType string) (string, error) {
	resp, err := c.do("GET", fmt.Sprintf("/org/%s/integrations/%s", c.orgID, integrationType), nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if err := checkStatus(resp, http.StatusOK); err != nil {
		return "", fmt.Errorf("get integration %s: %w", integrationType, err)
	}

	var result struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding integration response: %w", err)
	}
	if result.ID == "" {
		return "", fmt.Errorf("integration %q not found or not configured in org %s", integrationType, c.orgID)
	}
	return result.ID, nil
}

// ImportRequest represents the body for a GitHub/GitHub Enterprise import.
type ImportRequest struct {
	Target ImportTarget `json:"target"`
}

// ImportTarget holds the owner, name, and branch of a repository.
type ImportTarget struct {
	Owner  string `json:"owner"`
	Name   string `json:"name"`
	Branch string `json:"branch,omitempty"`
}

// StartImport triggers an import job and returns the job ID extracted from the
// Location response header.
func (c *Client) StartImport(integrationID string, req ImportRequest) (string, error) {
	resp, err := c.do("POST",
		fmt.Sprintf("/org/%s/integrations/%s/import", c.orgID, integrationID),
		req,
	)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if err := checkStatus(resp, http.StatusCreated); err != nil {
		return "", fmt.Errorf("start import: %w", err)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("import response missing Location header")
	}

	// Location: https://api.snyk.io/v1/org/{orgId}/integrations/{integrationId}/import/{jobId}
	var orgID, integID, jobID string
	_, scanErr := fmt.Sscanf(location,
		baseURL+"/org/%s/integrations/%s/import/%s",
		&orgID, &integID, &jobID,
	)
	if scanErr != nil || jobID == "" {
		// fallback: take the last path segment
		jobID = lastPathSegment(location)
	}
	if jobID == "" {
		return "", fmt.Errorf("could not parse job ID from Location: %s", location)
	}
	return jobID, nil
}

func lastPathSegment(url string) string {
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] == '/' {
			return url[i+1:]
		}
	}
	return url
}

// ImportJobStatus is the status string returned by Snyk for an import job.
type ImportJobStatus string

const (
	ImportJobPending  ImportJobStatus = "pending"
	ImportJobComplete ImportJobStatus = "complete"
	ImportJobFailed   ImportJobStatus = "failed"
)

// ImportJobLog represents one entry in the import job's logs array.
type ImportJobLog struct {
	Name     string              `json:"name"`
	Status   ImportJobStatus     `json:"status"`
	Projects []ImportJobProject  `json:"projects"`
}

// ImportJobProject represents a single project created by an import.
type ImportJobProject struct {
	TargetFile string `json:"targetFile"`
	Success    bool   `json:"success"`
	ProjectURL string `json:"projectUrl"`
}

// ImportJob is the response from the get-import-job endpoint.
type ImportJob struct {
	ID      string          `json:"id"`
	Status  ImportJobStatus `json:"status"`
	Logs    []ImportJobLog  `json:"logs"`
}

// GetImportJob returns the current state of an import job.
func (c *Client) GetImportJob(integrationID, jobID string) (*ImportJob, error) {
	resp, err := c.do("GET",
		fmt.Sprintf("/org/%s/integrations/%s/import/%s", c.orgID, integrationID, jobID),
		nil,
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := checkStatus(resp, http.StatusOK); err != nil {
		return nil, fmt.Errorf("get import job: %w", err)
	}

	var job ImportJob
	if err := json.NewDecoder(resp.Body).Decode(&job); err != nil {
		return nil, fmt.Errorf("decoding import job: %w", err)
	}
	return &job, nil
}

// WaitForImport polls the import job until it reaches a terminal state, then
// returns the list of project IDs that were created.
func (c *Client) WaitForImport(integrationID, jobID string, pollInterval, timeout time.Duration) ([]string, error) {
	deadline := time.Now().Add(timeout)
	for {
		job, err := c.GetImportJob(integrationID, jobID)
		if err != nil {
			return nil, err
		}

		switch job.Status {
		case ImportJobComplete:
			return collectProjectIDs(job), nil
		case ImportJobFailed:
			return nil, fmt.Errorf("import job %s failed", jobID)
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for import job %s (last status: %s)", jobID, job.Status)
		}
		time.Sleep(pollInterval)
	}
}

func collectProjectIDs(job *ImportJob) []string {
	var ids []string
	seen := make(map[string]bool)
	for _, log := range job.Logs {
		for _, p := range log.Projects {
			if p.Success && p.ProjectURL != "" {
				id := lastPathSegment(p.ProjectURL)
				if !seen[id] {
					seen[id] = true
					ids = append(ids, id)
				}
			}
		}
	}
	return ids
}

// Project represents the fields we care about from a Snyk project.
type Project struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Origin string `json:"origin"`
	Branch string `json:"branch"`
}

// GetProject fetches a single project by ID.
func (c *Client) GetProject(projectID string) (*Project, error) {
	resp, err := c.do("GET",
		fmt.Sprintf("/org/%s/project/%s", c.orgID, projectID),
		nil,
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if err := checkStatus(resp, http.StatusOK); err != nil {
		return nil, fmt.Errorf("get project %s: %w", projectID, err)
	}

	var project Project
	if err := json.NewDecoder(resp.Body).Decode(&project); err != nil {
		return nil, fmt.Errorf("decoding project: %w", err)
	}
	return &project, nil
}

// DeleteProject removes a project from Snyk.
func (c *Client) DeleteProject(projectID string) error {
	resp, err := c.do("DELETE",
		fmt.Sprintf("/org/%s/project/%s", c.orgID, projectID),
		nil,
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if err := checkStatus(resp, http.StatusOK); err != nil {
		return fmt.Errorf("delete project %s: %w", projectID, err)
	}
	return nil
}
