package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	ghErrors "github.com/github/github-mcp-server/pkg/errors"
	"github.com/github/github-mcp-server/pkg/inventory"
	"github.com/github/github-mcp-server/pkg/scopes"
	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/github/github-mcp-server/pkg/utils"
	"github.com/google/go-github/v82/github"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ListDependabotAlertsResult struct {
	Alerts []*github.DependabotAlert `json:"alerts"`
}

func GetDependabotAlert(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataDependabot,
		mcp.Tool{
			Name:        "get_dependabot_alert",
			Description: t("TOOL_GET_DEPENDABOT_ALERT_DESCRIPTION", "Get details of a specific dependabot alert in a GitHub repository."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_GET_DEPENDABOT_ALERT_USER_TITLE", "Get dependabot alert"),
				ReadOnlyHint: true,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"owner": {
						Type:        "string",
						Description: "The owner of the repository.",
					},
					"repo": {
						Type:        "string",
						Description: "The name of the repository.",
					},
					"alertNumber": {
						Type:        "number",
						Description: "The number of the alert.",
					},
				},
				Required: []string{"owner", "repo", "alertNumber"},
			},
			OutputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"number": {Type: "integer"},
					"state":  {Type: "string"},
					"dependency": {
						Type: "object",
						Properties: map[string]*jsonschema.Schema{
							"package": {
								Type: "object",
								Properties: map[string]*jsonschema.Schema{
									"ecosystem": {Type: "string"},
									"name":      {Type: "string"},
								},
							},
							"manifest_path": {Type: "string"},
							"scope":         {Type: "string"},
						},
					},
					"security_advisory": {
						Type: "object",
						Properties: map[string]*jsonschema.Schema{
							"ghsa_id":     {Type: "string"},
							"cve_id":      {Type: "string"},
							"summary":     {Type: "string"},
							"description": {Type: "string"},
							"vulnerabilities": {
								Type: "array",
								Items: &jsonschema.Schema{
									Type: "object",
									Properties: map[string]*jsonschema.Schema{
										"package": {
											Type: "object",
											Properties: map[string]*jsonschema.Schema{
												"ecosystem": {Type: "string"},
												"name":      {Type: "string"},
											},
										},
										"severity":                 {Type: "string"},
										"vulnerable_version_range": {Type: "string"},
										"first_patched_version":    {Type: "object"},
										"patched_versions":         {Type: "string"},
										"vulnerable_functions":     {Type: "array", Items: &jsonschema.Schema{Type: "string"}},
									},
								},
							},
							"severity": {Type: "string"},
							"cvss": {
								Type: "object",
								Properties: map[string]*jsonschema.Schema{
									"score":         {Type: "number"},
									"vector_string": {Type: "string"},
								},
							},
							"cwes": {
								Type: "array",
								Items: &jsonschema.Schema{
									Type: "object",
									Properties: map[string]*jsonschema.Schema{
										"cwe_id": {Type: "string"},
										"name":   {Type: "string"},
									},
								},
							},
							"epss": {
								Type: "object",
								Properties: map[string]*jsonschema.Schema{
									"percentage": {Type: "number"},
									"percentile": {Type: "number"},
								},
							},
							"identifiers":  {Type: "array", Items: &jsonschema.Schema{Type: "object"}},
							"references":   {Type: "array", Items: &jsonschema.Schema{Type: "object"}},
							"published_at": {Type: "string"},
							"updated_at":   {Type: "string"},
							"withdrawn_at": {Type: "string"},
						},
					},
					"security_vulnerability": {
						Type: "object",
						Properties: map[string]*jsonschema.Schema{
							"package": {
								Type: "object",
								Properties: map[string]*jsonschema.Schema{
									"ecosystem": {Type: "string"},
									"name":      {Type: "string"},
								},
							},
							"severity":                 {Type: "string"},
							"vulnerable_version_range": {Type: "string"},
							"first_patched_version":    {Type: "object"},
							"patched_versions":         {Type: "string"},
							"vulnerable_functions":     {Type: "array", Items: &jsonschema.Schema{Type: "string"}},
						},
					},
					"url":               {Type: "string"},
					"html_url":          {Type: "string"},
					"created_at":        {Type: "string"},
					"updated_at":        {Type: "string"},
					"dismissed_at":      {Type: "string"},
					"dismissed_by":      UserSchema(),
					"dismissed_reason":  {Type: "string"},
					"dismissed_comment": {Type: "string"},
					"fixed_at":          {Type: "string"},
					"auto_dismissed_at": {Type: "string"},
					"repository":        {Type: "object"},
				},
			},
		},
		[]scopes.Scope{scopes.SecurityEvents},
		func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, *github.DependabotAlert, error) {
			owner, err := RequiredParam[string](args, "owner")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			repo, err := RequiredParam[string](args, "repo")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			alertNumber, err := RequiredInt(args, "alertNumber")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}

			client, err := deps.GetClient(ctx)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, err
			}

			alert, resp, err := client.Dependabot.GetRepoAlert(ctx, owner, repo, alertNumber)
			if err != nil {
				return ghErrors.NewGitHubAPIErrorResponse(ctx,
					fmt.Sprintf("failed to get alert with number '%d'", alertNumber),
					resp,
					err,
				), nil, nil
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, err
				}
				return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, "failed to get alert", resp, body), nil, nil
			}

			r, err := json.Marshal(alert)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to marshal alert", err), nil, err
			}

			return utils.NewToolResultText(string(r)), alert, nil
		},
	)
}

func ListDependabotAlerts(t translations.TranslationHelperFunc) inventory.ServerTool {
	return NewTool(
		ToolsetMetadataDependabot,
		mcp.Tool{
			Name:        "list_dependabot_alerts",
			Description: t("TOOL_LIST_DEPENDABOT_ALERTS_DESCRIPTION", "List dependabot alerts in a GitHub repository."),
			Annotations: &mcp.ToolAnnotations{
				Title:        t("TOOL_LIST_DEPENDABOT_ALERTS_USER_TITLE", "List dependabot alerts"),
				ReadOnlyHint: true,
			},
			InputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"owner": {
						Type:        "string",
						Description: "The owner of the repository.",
					},
					"repo": {
						Type:        "string",
						Description: "The name of the repository.",
					},
					"state": {
						Type:        "string",
						Description: "Filter dependabot alerts by state. Defaults to open",
						Enum:        []any{"open", "fixed", "dismissed", "auto_dismissed"},
						Default:     json.RawMessage(`"open"`),
					},
					"severity": {
						Type:        "string",
						Description: "Filter dependabot alerts by severity",
						Enum:        []any{"low", "medium", "high", "critical"},
					},
				},
				Required: []string{"owner", "repo"},
			},
			OutputSchema: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"alerts": {
						Type: "array",
						Items: &jsonschema.Schema{
							Type: "object",
							Properties: map[string]*jsonschema.Schema{
								"number": {Type: "integer"},
								"state":  {Type: "string"},
								"dependency": {
									Type: "object",
									Properties: map[string]*jsonschema.Schema{
										"package": {
											Type: "object",
											Properties: map[string]*jsonschema.Schema{
												"ecosystem": {Type: "string"},
												"name":      {Type: "string"},
											},
										},
										"manifest_path": {Type: "string"},
										"scope":         {Type: "string"},
									},
								},
								"security_advisory": {
									Type: "object",
									Properties: map[string]*jsonschema.Schema{
										"ghsa_id":     {Type: "string"},
										"cve_id":      {Type: "string"},
										"summary":     {Type: "string"},
										"description": {Type: "string"},
										"vulnerabilities": {
											Type: "array",
											Items: &jsonschema.Schema{
												Type: "object",
												Properties: map[string]*jsonschema.Schema{
													"package": {
														Type: "object",
														Properties: map[string]*jsonschema.Schema{
															"ecosystem": {Type: "string"},
															"name":      {Type: "string"},
														},
													},
													"severity":                 {Type: "string"},
													"vulnerable_version_range": {Type: "string"},
													"first_patched_version":    {Type: "object"},
													"patched_versions":         {Type: "string"},
													"vulnerable_functions":     {Type: "array", Items: &jsonschema.Schema{Type: "string"}},
												},
											},
										},
										"severity": {Type: "string"},
										"cvss": {
											Type: "object",
											Properties: map[string]*jsonschema.Schema{
												"score":         {Type: "number"},
												"vector_string": {Type: "string"},
											},
										},
										"cwes": {
											Type: "array",
											Items: &jsonschema.Schema{
												Type: "object",
												Properties: map[string]*jsonschema.Schema{
													"cwe_id": {Type: "string"},
													"name":   {Type: "string"},
												},
											},
										},
										"epss": {
											Type: "object",
											Properties: map[string]*jsonschema.Schema{
												"percentage": {Type: "number"},
												"percentile": {Type: "number"},
											},
										},
										"identifiers":  {Type: "array", Items: &jsonschema.Schema{Type: "object"}},
										"references":   {Type: "array", Items: &jsonschema.Schema{Type: "object"}},
										"published_at": {Type: "string"},
										"updated_at":   {Type: "string"},
										"withdrawn_at": {Type: "string"},
									},
								},
								"security_vulnerability": {
									Type: "object",
									Properties: map[string]*jsonschema.Schema{
										"package": {
											Type: "object",
											Properties: map[string]*jsonschema.Schema{
												"ecosystem": {Type: "string"},
												"name":      {Type: "string"},
											},
										},
										"severity":                 {Type: "string"},
										"vulnerable_version_range": {Type: "string"},
										"first_patched_version":    {Type: "object"},
										"patched_versions":         {Type: "string"},
										"vulnerable_functions":     {Type: "array", Items: &jsonschema.Schema{Type: "string"}},
									},
								},
								"url":               {Type: "string"},
								"html_url":          {Type: "string"},
								"created_at":        {Type: "string"},
								"updated_at":        {Type: "string"},
								"dismissed_at":      {Type: "string"},
								"dismissed_by":      UserSchema(),
								"dismissed_reason":  {Type: "string"},
								"dismissed_comment": {Type: "string"},
								"fixed_at":          {Type: "string"},
								"auto_dismissed_at": {Type: "string"},
								"repository":        {Type: "object"},
							},
						},
					},
				},
			},
		},
		[]scopes.Scope{scopes.SecurityEvents},
		func(ctx context.Context, deps ToolDependencies, _ *mcp.CallToolRequest, args map[string]any) (*mcp.CallToolResult, *ListDependabotAlertsResult, error) {
			owner, err := RequiredParam[string](args, "owner")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			repo, err := RequiredParam[string](args, "repo")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			state, err := OptionalParam[string](args, "state")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}
			severity, err := OptionalParam[string](args, "severity")
			if err != nil {
				return utils.NewToolResultError(err.Error()), nil, nil
			}

			client, err := deps.GetClient(ctx)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to get GitHub client", err), nil, err
			}

			alerts, resp, err := client.Dependabot.ListRepoAlerts(ctx, owner, repo, &github.ListAlertsOptions{
				State:    ToStringPtr(state),
				Severity: ToStringPtr(severity),
			})
			if err != nil {
				return ghErrors.NewGitHubAPIErrorResponse(ctx,
					fmt.Sprintf("failed to list alerts for repository '%s/%s'", owner, repo),
					resp,
					err,
				), nil, nil
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return utils.NewToolResultErrorFromErr("failed to read response body", err), nil, err
				}
				return ghErrors.NewGitHubAPIStatusErrorResponse(ctx, "failed to list alerts", resp, body), nil, nil
			}

			r, err := json.Marshal(alerts)
			if err != nil {
				return utils.NewToolResultErrorFromErr("failed to marshal alerts", err), nil, err
			}

			return utils.NewToolResultText(string(r)), &ListDependabotAlertsResult{Alerts: alerts}, nil
		},
	)
}
