package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	caslogger "github.com/apimgr/whois/src/logger"
	"github.com/apimgr/whois/src/swagger"
	"github.com/go-chi/chi/v5"
)

const mcpProtocolVersion = "2026-07-28"

const defaultMCPProjectContent = `WHOIS lookups accept a domain, IPv4 or IPv6 address, or ASN. Use whoisLookup for automatic detection, or domainLookup, ipLookup, and asnLookup when the query type is known. validateQuery checks syntax without making an upstream request. ownerSearch searches the local lookup history and does not query registries. listWhoisServers and getStats return public service data. Operator credentials also expose bulkLookup, listSchedulerTasks, and listBackups. Lookups follow the configured endpoint limits and may return cached registry data.`

type mcpHelpPageData struct {
	translatablePageData
	Name          string
	URL           string
	APIAlias      string
	RootAlias     string
	ClaudeCommand string
	ClientConfig  string
	VerifyCommand string
	Tools         []mcpTool
	Project       template.HTML
}

type mcpHelpAPIData struct {
	Enabled bool     `json:"enabled"`
	URL     string   `json:"url"`
	Aliases []string `json:"aliases"`
	Auth    struct {
		Scheme string `json:"scheme"`
	} `json:"auth"`
	Tools   []mcpTool `json:"tools"`
	Project string    `json:"project"`
}

var mcpHelpTmpl = mustParseTemplate("mcp_help", "page/mcp_help.tmpl")

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations"`
	Method      string         `json:"-"`
	Path        string         `json:"-"`
	Properties  map[string]any `json:"-"`
	PathArgs    []string       `json:"-"`
	QueryArgs   []string       `json:"-"`
	Required    []string       `json:"-"`
	Operator    bool           `json:"-"`
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.writeMCPError(w, http.StatusMethodNotAllowed, nil, -32000, "Method not allowed")
		return
	}
	if !s.mcpOriginAllowed(r) {
		s.writeMCPError(w, http.StatusForbidden, nil, -32001, "Origin not allowed")
		return
	}
	token := extractBearerToken(r)
	if token == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		s.mcpAuthFailure(w, r, nil)
		return
	}
	operator := s.isServerToken(token)
	if !operator {
		if s.database == nil || s.database.Read() == nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			s.mcpAuthFailure(w, r, nil)
			return
		}
		if _, err := s.lookupOwnerToken(r.Context(), token); err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			s.mcpAuthFailure(w, r, nil)
			return
		}
	}
	var request struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
			Meta      map[string]any `json:"_meta"`
		} `json:"params"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if decoder.Decode(&request) != nil || request.JSONRPC != "2.0" {
		s.writeMCPError(w, http.StatusBadRequest, nil, -32700, "Parse error")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		s.writeMCPError(w, http.StatusBadRequest, request.ID, -32700, "Parse error")
		return
	}
	protocol, _ := request.Params.Meta["io.modelcontextprotocol/protocolVersion"].(string)
	headerProtocol := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version"))
	if request.Method == "initialize" || headerProtocol != mcpProtocolVersion {
		s.writeMCPProtocolError(w, request.ID, headerProtocol)
		return
	}
	if protocol != mcpProtocolVersion || strings.TrimSpace(r.Header.Get("Mcp-Method")) != request.Method {
		s.writeMCPError(w, http.StatusBadRequest, request.ID, -32020, "HeaderMismatch")
		return
	}
	if request.Method != "tools/list" && request.Method != "tools/call" {
		s.writeMCPError(w, http.StatusNotFound, request.ID, -32601, "Method not found")
		return
	}
	tools := s.mcpTools(r, operator)
	if request.Method == "tools/list" {
		for i := range tools {
			tools[i].Method = ""
			tools[i].Path = ""
			tools[i].Properties = nil
			tools[i].PathArgs = nil
			tools[i].QueryArgs = nil
			tools[i].Required = nil
			tools[i].Operator = false
		}
		s.writeMCPResult(w, request.ID, map[string]any{"tools": tools})
		return
	}
	name, nameErr := decodeMCPName(r.Header.Get("Mcp-Name"))
	if nameErr != nil || name != request.Params.Name {
		s.writeMCPError(w, http.StatusBadRequest, request.ID, -32020, "HeaderMismatch")
		return
	}
	for _, tool := range tools {
		if tool.Name != request.Params.Name {
			continue
		}
		if err := validateMCPArguments(request.Params.Arguments, tool); err != nil {
			s.writeMCPError(w, http.StatusBadRequest, request.ID, -32602, "Invalid tool arguments")
			return
		}
		s.dispatchMCPTool(w, r, request.ID, tool, request.Params.Arguments)
		return
	}
	s.writeMCPError(w, http.StatusNotFound, request.ID, -32601, "Tool not found")
}

func (s *Server) mcpHelpContent(r *http.Request) (string, string, string, []mcpTool, string) {
	project := strings.TrimSpace(s.config.Pages.Help.MCP)
	if project == "" {
		project = defaultMCPProjectContent
	}
	baseURL := s.BuildURL(r, s.config.APIBasePath()+"/server/mcp")
	apiAlias := s.BuildURL(r, "/api/mcp")
	rootAlias := s.BuildURL(r, "/mcp")
	tools := s.mcpTools(r, false)
	return baseURL, apiAlias, rootAlias, tools, project
}

func (s *Server) handleMCPHelpPage(w http.ResponseWriter, r *http.Request) {
	baseURL, apiAlias, rootAlias, tools, project := s.mcpHelpContent(r)
	page := mcpHelpPageData{
		translatablePageData: s.newPageData(w, r), Name: s.brandName(), URL: baseURL, APIAlias: apiAlias, RootAlias: rootAlias,
		ClaudeCommand: fmt.Sprintf("claude mcp add --transport http %s %s --header \"Authorization: Bearer $MCP_TOKEN\"", mcpShellQuote("caswhois"), mcpShellQuote(baseURL)),
		ClientConfig:  fmt.Sprintf(`{"mcpServers":{"caswhois":{"type":"http","url":%q,"headers":{"Authorization":"Bearer $MCP_TOKEN"}}}}`, baseURL),
		VerifyCommand: fmt.Sprintf("curl -X POST %s -H \"Authorization: Bearer $MCP_TOKEN\" -H %s -H %s -H %s -H %s --data %s", mcpShellQuote(baseURL), mcpShellQuote("Content-Type: application/json"), mcpShellQuote("Accept: application/json"), mcpShellQuote("MCP-Protocol-Version: "+mcpProtocolVersion), mcpShellQuote("Mcp-Method: tools/list"), mcpShellQuote(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`)),
		Tools:         tools, Project: markdownToHTML(project),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.renderTemplate(mcpHelpTmpl, w, r, page); err != nil {
		writeRequestError(w, r, http.StatusInternalServerError)
	}
}

func mcpShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func (s *Server) handleMCPHelpAPI(w http.ResponseWriter, r *http.Request) {
	baseURL, apiAlias, rootAlias, tools, project := s.mcpHelpContent(r)
	api := mcpHelpAPIData{Enabled: true, URL: baseURL, Aliases: []string{apiAlias, rootAlias}, Tools: tools, Project: project}
	api.Auth.Scheme = "Bearer"
	SendSuccess(w, api)
}

func (s *Server) isServerToken(token string) bool {
	provided := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(provided[:], s.getServerTokenHash()) == 1
}

func (s *Server) mcpOriginAllowed(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	if mcpSameOrigin(origin, s.BuildURL(r, "/")) {
		return true
	}
	for _, allowed := range s.config.Cors.AllowedOrigins {
		if strings.TrimSpace(allowed) != "" && strings.TrimSpace(allowed) != "*" && mcpSameOrigin(origin, allowed) {
			return true
		}
	}
	return false
}

func mcpSameOrigin(origin, base string) bool {
	a, errA := url.Parse(strings.TrimSpace(origin))
	b, errB := url.Parse(strings.TrimRight(strings.TrimSpace(base), "/"))
	return errA == nil && errB == nil && a.User == nil && b.User == nil && a.Path == "" && a.RawQuery == "" && a.Fragment == "" && b.Path == "" && b.RawQuery == "" && b.Fragment == "" && strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func (s *Server) mcpTools(r *http.Request, operator bool) []mcpTool {
	spec := swagger.BuildSpecWithAPIBase(s.BuildURL(r, "/"), Version, s.config.APIBasePath())
	apiBase := s.config.APIBasePath()
	tools := make([]mcpTool, 0)
	for path, item := range spec.Paths {
		if !strings.HasPrefix(path, apiBase+"/") || strings.Contains(path, "/server/preferences") || strings.Contains(path, "/server/mcp") {
			continue
		}
		basePath := strings.TrimPrefix(path, apiBase)
		operations := []struct {
			method string
			op     *swagger.Operation
		}{{http.MethodGet, item.Get}, {http.MethodPost, item.Post}, {http.MethodPut, item.Put}, {http.MethodDelete, item.Delete}}
		for _, candidate := range operations {
			op := candidate.op
			if op == nil || op.OperationID == "" {
				continue
			}
			operatorOnly := len(op.Security) > 0
			if operatorOnly && !operator {
				continue
			}
			properties := make(map[string]any)
			var required, paths, queries []string
			for _, parameter := range op.Parameters {
				properties[parameter.Name] = mcpSchema(parameter.Schema, spec.Components.Schemas)
				if parameter.Required {
					required = append(required, parameter.Name)
				}
				switch parameter.In {
				case "path":
					paths = append(paths, parameter.Name)
				case "query":
					queries = append(queries, parameter.Name)
				}
			}
			if op.RequestBody != nil {
				for _, media := range op.RequestBody.Content {
					if media.Schema.Ref != "" {
						if bodySchema, ok := spec.Components.Schemas[strings.TrimPrefix(media.Schema.Ref, "#/components/schemas/")]; ok {
							for key, value := range bodySchema.Properties {
								properties[key] = mcpSchema(value, spec.Components.Schemas)
							}
							required = append(required, bodySchemaRequired(bodySchema)...)
						}
					} else {
						for key, value := range media.Schema.Properties {
							properties[key] = mcpSchema(value, spec.Components.Schemas)
						}
					}
				}
			}
			annotations := map[string]any{"readOnlyHint": candidate.method == http.MethodGet, "destructiveHint": candidate.method == http.MethodDelete, "idempotentHint": candidate.method == http.MethodPut || candidate.method == http.MethodDelete}
			tools = append(tools, mcpTool{Name: op.OperationID, Description: op.Description, InputSchema: map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}, Annotations: annotations, Method: candidate.method, Path: apiBase + basePath, Properties: properties, PathArgs: paths, QueryArgs: queries, Required: required, Operator: operatorOnly})
		}
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return tools
}

func (s *Server) mcpAuthFailure(w http.ResponseWriter, r *http.Request, id json.RawMessage) {
	limit := s.config.RateLimit.AuthFailures
	if s.authFailureLimiter != nil && !s.allowRateLimit(r.Context(), "auth_failure", s.authFailureLimiter, s.authFailureKey(r), limit.Requests, time.Duration(limit.Window)*time.Second, true) {
		w.Header().Set("Retry-After", strconv.Itoa(limit.Window))
		s.writeMCPError(w, http.StatusTooManyRequests, id, -32002, "Invalid credentials")
		return
	}
	s.writeMCPError(w, http.StatusUnauthorized, id, -32002, "Invalid credentials")
}

func decodeMCPName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "=?base64?") && strings.HasSuffix(value, "?=") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(value, "=?base64?"), "?="))
		return string(decoded), err
	}
	for _, char := range value {
		if char > 127 {
			return "", fmt.Errorf("MCP name must be ASCII or base64 encoded")
		}
	}
	return value, nil
}

func mcpSchema(schema swagger.Schema, components map[string]swagger.Schema) map[string]any {
	if schema.Ref != "" {
		if resolved, ok := components[strings.TrimPrefix(schema.Ref, "#/components/schemas/")]; ok {
			return mcpSchema(resolved, components)
		}
	}
	result := map[string]any{"type": schema.Type}
	if schema.Format != "" {
		result["format"] = schema.Format
	}
	if schema.Items != nil {
		result["items"] = mcpSchema(*schema.Items, components)
	}
	if len(schema.Properties) > 0 {
		properties := map[string]any{}
		for key, property := range schema.Properties {
			properties[key] = mcpSchema(property, components)
		}
		result["properties"] = properties
	}
	return result
}

func bodySchemaRequired(schema swagger.Schema) []string {
	return append([]string(nil), schema.Required...)
}

func validateMCPArguments(args map[string]any, tool mcpTool) error {
	for _, key := range tool.Required {
		if _, ok := args[key]; !ok {
			return fmt.Errorf("missing argument %s", key)
		}
	}
	for key := range args {
		if _, ok := tool.Properties[key]; !ok {
			return fmt.Errorf("unknown argument %s", key)
		}
	}
	return nil
}

func (s *Server) dispatchMCPTool(w http.ResponseWriter, source *http.Request, id json.RawMessage, tool mcpTool, args map[string]any) {
	path := tool.Path
	consumed := map[string]bool{}
	for _, key := range tool.PathArgs {
		value, _ := args[key].(string)
		path = strings.ReplaceAll(path, "{"+key+"}", url.PathEscape(value))
		consumed[key] = true
	}
	query := url.Values{}
	for _, key := range tool.QueryArgs {
		if value, ok := args[key]; ok {
			query.Set(key, fmt.Sprint(value))
			consumed[key] = true
		}
	}
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	request := source.Clone(context.WithValue(source.Context(), chi.RouteCtxKey, chi.NewRouteContext()))
	request.Method = tool.Method
	request.URL, _ = url.Parse(path)
	request.RequestURI = path
	request.Header = source.Header.Clone()
	request.Header.Del("Mcp-Name")
	request.Header.Del("Mcp-Method")
	request.Header.Del("MCP-Protocol-Version")
	request.Header.Set("Accept", "application/json")
	if tool.Method != http.MethodGet && tool.Method != http.MethodDelete {
		body := map[string]any{}
		for key, value := range args {
			if !consumed[key] {
				body[key] = value
			}
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			s.writeMCPError(w, http.StatusBadRequest, id, -32602, "Invalid tool arguments")
			return
		}
		request.Body = io.NopCloser(bytes.NewReader(encoded))
		request.ContentLength = int64(len(encoded))
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	if s.apiRouter == nil {
		s.writeMCPError(w, http.StatusInternalServerError, id, -32603, "API router unavailable")
		return
	}
	s.setupMiddleware(s.apiRouter).ServeHTTP(recorder, request)
	details, _ := json.Marshal(map[string]string{"source": "mcp", "tool": tool.Name})
	actorIP := extractClientIP(source, s.config.TrustedProxies.Additional)
	if s.database != nil && s.database.Read() != nil {
		if err := s.database.ExecWrite(source.Context(), `INSERT INTO audit_log (category, action, actor_ip, target_type, target_id, details, success) VALUES ('api', 'mcp.tool_call', ?, 'tool', ?, ?, ?)`, actorIP, tool.Name, string(details), recorder.Code < http.StatusBadRequest); err != nil {
			log.Printf("could not record MCP tool audit event")
		} else if s.logger != nil {
			s.logger.WriteAudit(caslogger.AuditEntry{Category: "api", Action: "mcp.tool_call", Source: "mcp", ActorIP: actorIP, TargetType: "tool", TargetID: tool.Name, Details: string(details), Success: recorder.Code < http.StatusBadRequest})
		}
	}
	var result any
	if json.Unmarshal(recorder.Body.Bytes(), &result) != nil {
		result = map[string]any{"message": "The API response could not be decoded"}
	}
	s.writeMCPResult(w, id, map[string]any{"content": []map[string]string{{"type": "text", "text": recorder.Body.String()}}, "structuredContent": result, "isError": recorder.Code >= http.StatusBadRequest})
}

func (s *Server) writeMCPResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func (s *Server) writeMCPError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}})
}

func (s *Server) writeMCPProtocolError(w http.ResponseWriter, id json.RawMessage, requested string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32022, "message": "Unsupported protocol version", "data": map[string]any{"supported": []string{mcpProtocolVersion}, "requested": requested}}})
}
