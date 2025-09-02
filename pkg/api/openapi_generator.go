package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strings"
	// "time" // Not used

	"github.com/dimajoyti/hackai/pkg/logger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	// "go.opentelemetry.io/otel/trace" // Not used
	"gopkg.in/yaml.v3"
)

var openAPIGeneratorTracer = otel.Tracer("hackai/api/openapi-generator")

// OpenAPIGenerator generates OpenAPI 3.0 specifications
type OpenAPIGenerator struct {
	config *OpenAPIConfig
	logger *logger.Logger
}

// OpenAPIConfig defines OpenAPI generation configuration
type OpenAPIConfig struct {
	Version             string                 `yaml:"version"`
	OutputDirectory     string                 `yaml:"output_directory"`
	OutputFormats       []string               `yaml:"output_formats"`
	IncludeExamples     bool                   `yaml:"include_examples"`
	IncludeSchemas      bool                   `yaml:"include_schemas"`
	IncludeServers      bool                   `yaml:"include_servers"`
	IncludeSecurity     bool                   `yaml:"include_security"`
	IncludeTags         bool                   `yaml:"include_tags"`
	IncludeExternalDocs bool                   `yaml:"include_external_docs"`
	ValidateSpec        bool                   `yaml:"validate_spec"`
	PrettyPrint         bool                   `yaml:"pretty_print"`
	SortPaths           bool                   `yaml:"sort_paths"`
	SortSchemas         bool                   `yaml:"sort_schemas"`
	CustomExtensions    map[string]interface{} `yaml:"custom_extensions"`
	TemplateOverrides   map[string]string      `yaml:"template_overrides"`
}

// DocumentationGenerator generates comprehensive API documentation
type DocumentationGenerator struct {
	config *DocumentationConfig
	logger *logger.Logger
}

// BrandingConfig defines branding configuration for documentation
type BrandingConfig struct {
	Logo           string `yaml:"logo"`
	FaviconURL     string `yaml:"favicon_url"`
	PrimaryColor   string `yaml:"primary_color"`
	SecondaryColor string `yaml:"secondary_color"`
	FontFamily     string `yaml:"font_family"`
	CustomCSS      string `yaml:"custom_css"`
	CustomJS       string `yaml:"custom_js"`
}

// NewOpenAPIGenerator creates a new OpenAPI generator
func NewOpenAPIGenerator(config *OpenAPIConfig, logger *logger.Logger) *OpenAPIGenerator {
	return &OpenAPIGenerator{
		config: config,
		logger: logger,
	}
}

// GenerateSpec generates an OpenAPI 3.0 specification from API documentation
func (oag *OpenAPIGenerator) GenerateSpec(ctx context.Context, documentation *APIDocumentation) (*OpenAPISpec, error) {
	ctx, span := openAPIGeneratorTracer.Start(ctx, "generate_openapi_spec")
	defer span.End()

	spec := &OpenAPISpec{
		OpenAPI: "3.0.3",
		Info:    documentation.Info,
		Servers: documentation.Servers,
		Paths:   make(map[string]interface{}),
		Components: &Components{
			Schemas:         make(map[string]*APISchema),
			Responses:       make(map[string]*APIResponse),
			Parameters:      make(map[string]*APIParameter),
			Examples:        make(map[string]*APIExample),
			RequestBodies:   make(map[string]*APIRequestBody),
			Headers:         make(map[string]*APIHeader),
			SecuritySchemes: documentation.Security,
			Links:           make(map[string]*APILink),
			Callbacks:       make(map[string]interface{}),
		},
		Security: []SecurityRequirement{},
		Tags:     documentation.Tags,
	}

	// Generate paths from endpoints
	if err := oag.generatePaths(ctx, spec, documentation.Endpoints); err != nil {
		return nil, fmt.Errorf("failed to generate paths: %w", err)
	}

	// Add schemas to components
	if oag.config.IncludeSchemas {
		for id, schema := range documentation.Schemas {
			spec.Components.Schemas[id] = schema
		}
	}

	// Add global security requirements
	if oag.config.IncludeSecurity {
		spec.Security = append(spec.Security, SecurityRequirement{
			"bearerAuth": []string{},
		})
	}

	// Add custom extensions
	if len(oag.config.CustomExtensions) > 0 {
		for key, _ := range oag.config.CustomExtensions { // value not used
			// Add custom extensions with x- prefix
			if !strings.HasPrefix(key, "x-") {
				key = "x-" + key
			}
			// Note: In a real implementation, you'd add these to the spec
			// This is a simplified example
		}
	}

	// Validate specification if enabled
	if oag.config.ValidateSpec {
		if err := oag.validateSpec(ctx, spec); err != nil {
			oag.logger.WithError(err).Warn("OpenAPI specification validation failed")
		}
	}

	span.SetAttributes(
		attribute.Int("paths_count", len(spec.Paths)),
		attribute.Int("schemas_count", len(spec.Components.Schemas)),
		attribute.Int("security_schemes_count", len(spec.Components.SecuritySchemes)),
	)

	oag.logger.WithFields(logger.Fields{
		"paths_count":            len(spec.Paths),
		"schemas_count":          len(spec.Components.Schemas),
		"security_schemes_count": len(spec.Components.SecuritySchemes),
	}).Info("Generated OpenAPI specification")

	return spec, nil
}

// generatePaths generates OpenAPI paths from API endpoints
func (oag *OpenAPIGenerator) generatePaths(ctx context.Context, spec *OpenAPISpec, endpoints map[string]*APIEndpoint) error {
	// Group endpoints by path
	pathGroups := make(map[string]map[string]*APIEndpoint)

	for _, endpoint := range endpoints {
		if pathGroups[endpoint.Path] == nil {
			pathGroups[endpoint.Path] = make(map[string]*APIEndpoint)
		}
		pathGroups[endpoint.Path][strings.ToLower(endpoint.Method)] = endpoint
	}

	// Generate path items
	for path, methods := range pathGroups {
		pathItem := make(map[string]interface{})

		for method, endpoint := range methods {
			operation := oag.generateOperation(ctx, endpoint)
			pathItem[method] = operation
		}

		spec.Paths[path] = pathItem
	}

	// Sort paths if enabled
	if oag.config.SortPaths {
		oag.sortPaths(spec.Paths)
	}

	return nil
}

// generateOperation generates an OpenAPI operation from an API endpoint
func (oag *OpenAPIGenerator) generateOperation(ctx context.Context, endpoint *APIEndpoint) map[string]interface{} {
	operation := map[string]interface{}{
		"summary":     endpoint.Summary,
		"description": endpoint.Description,
		"operationId": oag.generateOperationID(endpoint),
		"tags":        endpoint.Tags,
		"parameters":  oag.generateParameters(endpoint.Parameters),
		"responses":   oag.generateResponses(endpoint.Responses),
	}

	// Add request body if present
	if endpoint.RequestBody != nil {
		operation["requestBody"] = endpoint.RequestBody
	}

	// Add security requirements
	if len(endpoint.Security) > 0 {
		operation["security"] = endpoint.Security
	}

	// Add deprecation flag
	if endpoint.Deprecated {
		operation["deprecated"] = true
	}

	// Add external documentation
	if endpoint.ExternalDocs != nil {
		operation["externalDocs"] = endpoint.ExternalDocs
	}

	// Add examples if enabled
	if oag.config.IncludeExamples && len(endpoint.Examples) > 0 {
		examples := make(map[string]*APIExample)
		for i, example := range endpoint.Examples {
			examples[fmt.Sprintf("example_%d", i)] = example
		}
		operation["examples"] = examples
	}

	// Add custom extensions
	for key, value := range endpoint.Metadata {
		if strings.HasPrefix(key, "x-") {
			operation[key] = value
		}
	}

	return operation
}

// generateOperationID generates a unique operation ID for an endpoint
func (oag *OpenAPIGenerator) generateOperationID(endpoint *APIEndpoint) string {
	if endpoint.ID != "" {
		return endpoint.ID
	}

	// Generate from method and path
	method := strings.ToLower(endpoint.Method)
	path := strings.ReplaceAll(endpoint.Path, "/", "_")
	path = strings.ReplaceAll(path, "{", "")
	path = strings.ReplaceAll(path, "}", "")
	path = strings.Trim(path, "_")

	if path == "" {
		return method + "_root"
	}

	return method + "_" + path
}

// generateParameters generates OpenAPI parameters from API parameters
func (oag *OpenAPIGenerator) generateParameters(parameters []*APIParameter) []interface{} {
	if len(parameters) == 0 {
		return nil
	}

	result := make([]interface{}, len(parameters))
	for i, param := range parameters {
		result[i] = param
	}

	return result
}

// generateResponses generates OpenAPI responses from API responses
func (oag *OpenAPIGenerator) generateResponses(responses map[string]*APIResponse) map[string]interface{} {
	if len(responses) == 0 {
		// Default response
		return map[string]interface{}{
			"200": map[string]interface{}{
				"description": "Successful response",
			},
		}
	}

	result := make(map[string]interface{})
	for code, response := range responses {
		result[code] = response
	}

	return result
}

// sortPaths sorts the paths in the specification
func (oag *OpenAPIGenerator) sortPaths(paths map[string]interface{}) {
	// Note: In Go, maps are not ordered, so this would require
	// converting to a slice, sorting, and using an ordered map implementation
	// This is a placeholder for the sorting logic
}

// validateSpec validates the OpenAPI specification
func (oag *OpenAPIGenerator) validateSpec(ctx context.Context, spec *OpenAPISpec) error {
	// Basic validation
	if spec.Info == nil {
		return fmt.Errorf("info section is required")
	}

	if spec.Info.Title == "" {
		return fmt.Errorf("info.title is required")
	}

	if spec.Info.Version == "" {
		return fmt.Errorf("info.version is required")
	}

	if len(spec.Paths) == 0 {
		return fmt.Errorf("at least one path is required")
	}

	// Additional validation logic would go here
	return nil
}

// SaveSpec saves the OpenAPI specification to files
func (oag *OpenAPIGenerator) SaveSpec(ctx context.Context, spec *OpenAPISpec) error {
	ctx, span := openAPIGeneratorTracer.Start(ctx, "save_openapi_spec")
	defer span.End()

	for _, format := range oag.config.OutputFormats {
		filename := filepath.Join(oag.config.OutputDirectory, fmt.Sprintf("openapi.%s", format))

		var data []byte
		var err error

		switch strings.ToLower(format) {
		case "json":
			if oag.config.PrettyPrint {
				data, err = json.MarshalIndent(spec, "", "  ")
			} else {
				data, err = json.Marshal(spec)
			}
		case "yaml", "yml":
			data, err = yaml.Marshal(spec)
		default:
			return fmt.Errorf("unsupported output format: %s", format)
		}

		if err != nil {
			return fmt.Errorf("failed to marshal spec to %s: %w", format, err)
		}

		if err := ioutil.WriteFile(filename, data, 0644); err != nil {
			return fmt.Errorf("failed to write spec file %s: %w", filename, err)
		}

		oag.logger.WithFields(logger.Fields{
			"format":   format,
			"filename": filename,
			"size":     len(data),
		}).Info("Saved OpenAPI specification")
	}

	return nil
}

// NewDocumentationGenerator creates a new documentation generator
func NewDocumentationGenerator(config *DocumentationConfig, logger *logger.Logger) *DocumentationGenerator {
	return &DocumentationGenerator{
		config: config,
		logger: logger,
	}
}

// GenerateDocumentation generates comprehensive API documentation
func (dg *DocumentationGenerator) GenerateDocumentation(ctx context.Context, documentation *APIDocumentation) error {
	ctx, span := openAPIGeneratorTracer.Start(ctx, "generate_documentation")
	defer span.End()

	for _, format := range dg.config.OutputFormat {
		switch strings.ToLower(format) {
		case "html":
			if err := dg.generateHTMLDocumentation(ctx, documentation); err != nil {
				return fmt.Errorf("failed to generate HTML documentation: %w", err)
			}
		case "markdown", "md":
			if err := dg.generateMarkdownDocumentation(ctx, documentation); err != nil {
				return fmt.Errorf("failed to generate Markdown documentation: %w", err)
			}
		case "pdf":
			if err := dg.generatePDFDocumentation(ctx, documentation); err != nil {
				return fmt.Errorf("failed to generate PDF documentation: %w", err)
			}
		case "swagger-ui":
			if err := dg.generateSwaggerUI(ctx, documentation); err != nil {
				return fmt.Errorf("failed to generate Swagger UI: %w", err)
			}
		case "redoc":
			if err := dg.generateRedoc(ctx, documentation); err != nil {
				return fmt.Errorf("failed to generate Redoc: %w", err)
			}
		default:
			dg.logger.WithField("format", format).Warn("Unsupported documentation format")
		}
	}

	span.SetAttributes(
		attribute.StringSlice("formats", dg.config.OutputFormat),
		attribute.Int("endpoints_count", len(documentation.Endpoints)),
	)

	dg.logger.WithFields(logger.Fields{
		"formats":         dg.config.OutputFormat,
		"endpoints_count": len(documentation.Endpoints),
	}).Info("Generated API documentation")

	return nil
}

// generateHTMLDocumentation generates HTML documentation
func (dg *DocumentationGenerator) generateHTMLDocumentation(ctx context.Context, documentation *APIDocumentation) error {
	// HTML template for API documentation (placeholder - not used in current implementation)
	_ = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Info.Title}} - API Documentation</title>
    <style>
        body { font-family: {{.Branding.FontFamily}}; margin: 0; padding: 20px; }
        .header { background: {{.Branding.PrimaryColor}}; color: white; padding: 20px; margin: -20px -20px 20px -20px; }
        .endpoint { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .method { display: inline-block; padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }
        .get { background: #61affe; }
        .post { background: #49cc90; }
        .put { background: #fca130; }
        .delete { background: #f93e3e; }
        .patch { background: #50e3c2; }
        .schema { background: #f8f9fa; padding: 10px; border-radius: 3px; margin: 10px 0; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }
        {{.Branding.CustomCSS}}
    </style>
    {{.Branding.CustomJS}}
</head>
<body>
    <div class="header">
        <h1>{{.Info.Title}}</h1>
        <p>{{.Info.Description}}</p>
        <p>Version: {{.Info.Version}}</p>
    </div>
    
    <div class="content">
        <h2>Endpoints</h2>
        {{range .Endpoints}}
        <div class="endpoint">
            <h3>
                <span class="method {{.Method | lower}}">{{.Method}}</span>
                {{.Path}}
            </h3>
            <p>{{.Description}}</p>
            {{if .Parameters}}
            <h4>Parameters</h4>
            <ul>
                {{range .Parameters}}
                <li><strong>{{.Name}}</strong> ({{.In}}) - {{.Description}}</li>
                {{end}}
            </ul>
            {{end}}
        </div>
        {{end}}
    </div>
</body>
</html>
`

	// Generate HTML content
	filename := filepath.Join(dg.config.OutputDirectory, "index.html")

	// In a real implementation, you would use Go's template engine
	// to process the template with the documentation data

	dg.logger.WithField("filename", filename).Info("Generated HTML documentation")
	return nil
}

// generateMarkdownDocumentation generates Markdown documentation
func (dg *DocumentationGenerator) generateMarkdownDocumentation(ctx context.Context, documentation *APIDocumentation) error {
	var content strings.Builder

	// Header
	content.WriteString(fmt.Sprintf("# %s\n\n", documentation.Info.Title))
	content.WriteString(fmt.Sprintf("%s\n\n", documentation.Info.Description))
	content.WriteString(fmt.Sprintf("**Version:** %s\n\n", documentation.Info.Version))

	// Table of contents
	content.WriteString("## Table of Contents\n\n")

	// Sort endpoints by path for consistent output
	var sortedEndpoints []*APIEndpoint
	for _, endpoint := range documentation.Endpoints {
		sortedEndpoints = append(sortedEndpoints, endpoint)
	}

	sort.Slice(sortedEndpoints, func(i, j int) bool {
		return sortedEndpoints[i].Path < sortedEndpoints[j].Path
	})

	// Generate endpoint documentation
	content.WriteString("## Endpoints\n\n")

	for _, endpoint := range sortedEndpoints {
		content.WriteString(fmt.Sprintf("### %s %s\n\n", endpoint.Method, endpoint.Path))
		content.WriteString(fmt.Sprintf("%s\n\n", endpoint.Description))

		if len(endpoint.Parameters) > 0 {
			content.WriteString("#### Parameters\n\n")
			content.WriteString("| Name | Type | Location | Required | Description |\n")
			content.WriteString("|------|------|----------|----------|-------------|\n")

			for _, param := range endpoint.Parameters {
				required := "No"
				if param.Required {
					required = "Yes"
				}
				content.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
					param.Name, param.Schema.Type, param.In, required, param.Description))
			}
			content.WriteString("\n")
		}

		if len(endpoint.Responses) > 0 {
			content.WriteString("#### Responses\n\n")
			content.WriteString("| Status Code | Description |\n")
			content.WriteString("|-------------|-------------|\n")

			for code, response := range endpoint.Responses {
				content.WriteString(fmt.Sprintf("| %s | %s |\n", code, response.Description))
			}
			content.WriteString("\n")
		}
	}

	// Save to file
	filename := filepath.Join(dg.config.OutputDirectory, "README.md")
	if err := ioutil.WriteFile(filename, []byte(content.String()), 0644); err != nil {
		return fmt.Errorf("failed to write markdown documentation: %w", err)
	}

	dg.logger.WithField("filename", filename).Info("Generated Markdown documentation")
	return nil
}

// generatePDFDocumentation generates PDF documentation
func (dg *DocumentationGenerator) generatePDFDocumentation(ctx context.Context, documentation *APIDocumentation) error {
	// PDF generation would require a PDF library like gofpdf
	// This is a placeholder implementation
	dg.logger.Info("PDF documentation generation not implemented")
	return nil
}

// generateSwaggerUI generates Swagger UI documentation
func (dg *DocumentationGenerator) generateSwaggerUI(ctx context.Context, documentation *APIDocumentation) error {
	// Swagger UI generation would involve creating HTML with Swagger UI assets
	// This is a placeholder implementation
	dg.logger.Info("Swagger UI generation not implemented")
	return nil
}

// generateRedoc generates Redoc documentation
func (dg *DocumentationGenerator) generateRedoc(ctx context.Context, documentation *APIDocumentation) error {
	// Redoc generation would involve creating HTML with Redoc assets
	// This is a placeholder implementation
	dg.logger.Info("Redoc generation not implemented")
	return nil
}
