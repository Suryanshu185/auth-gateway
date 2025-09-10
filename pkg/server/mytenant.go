// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/go-core-stack/auth-gateway/api"
	"github.com/go-core-stack/auth-gateway/pkg/keycloak"
	"github.com/go-core-stack/auth-gateway/pkg/model"
	"github.com/go-core-stack/auth-gateway/pkg/table"
	auth "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type MyTenantServer struct {
	api.UnimplementedMyTenantServer
	client   *keycloak.Client
	idpTable *table.IdentityProviderTable
}

func (s *MyTenantServer) GetMyPasswordPolicy(ctx context.Context, req *api.MyPasswordPolicyGetReq) (*api.MyPasswordPolicyGetResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	token, _ := s.client.GetAccessToken()
	realm, err := s.client.GetRealm(ctx, token, authInfo.Realm)
	if err != nil {
		// sanity check
		log.Printf("failed to get realm %s: %s", authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}
	resp := &api.MyPasswordPolicyGetResp{}
	tokens := strings.Split(gocloak.PString(realm.PasswordPolicy), " and ")
	for _, t := range tokens {
		var value int32
		re := regexp.MustCompile(`^([a-zA-Z_]\w*)\(([^)]+)\)$`)
		matches := re.FindStringSubmatch(t)
		if len(matches) != 3 {
			continue
		}

		key := matches[1]
		val, _ := strconv.Atoi(matches[2])
		value = int32(val)

		switch key {
		case "length":
			resp.MinLength = value
		case "maxLength":
			resp.MaxLength = value
		case "digits":
			resp.MinDigits = value
		case "lowerCase":
			resp.MinLower = value
		case "upperCase":
			resp.MinUpper = value
		case "specialChars":
			resp.MinSpecial = value
		case "passwordHistory":
			resp.RecentlyUsed = value
		case "passwordAge":
			resp.PasswordAge = value
		case "forceExpiredPasswordChange":
			resp.ForceExpirePasswordChange = value
		default:
			// ignore unknown keys
		}
	}
	return resp, nil
}

func (s *MyTenantServer) UpdateMyPasswordPolicy(ctx context.Context, req *api.MyPasswordPolicyUpdateReq) (*api.MyPasswordPolicyUpdateResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	if req.MinLength < 4 {
		return nil, status.Errorf(codes.InvalidArgument, "minimum length should be at least 4")
	}

	if req.MaxLength > 40 {
		return nil, status.Errorf(codes.InvalidArgument, "maximum password length can not be more than 40")
	}

	if (req.MaxLength < req.MinLength) || (req.MinDigits+req.MinLower+req.MinSpecial+req.MinUpper > req.MaxLength) {
		return nil, status.Errorf(codes.InvalidArgument, "maximum length can not be less than minimum length")
	}

	// policy string would look like
	// forceExpiredPasswordChange(365) and passwordHistory(3) and length(8) and notUsername(undefined) and notEmail(undefined) and passwordAge(30) and notContainsUsername(undefined) and specialChars(1) and upperCase(1) and lowerCase(1) and digits(1) and maxLength(64)
	// by default always ensure notUsername, notEmail and notContainsUsername is present
	policy := fmt.Sprintf("length(%d) and maxLength(%d) and notUsername(undefined) and notEmail(undefined) and notContainsUsername(undefined)", req.MinLength, req.MaxLength)

	if req.MinDigits > 0 {
		policy += fmt.Sprintf(" and digits(%d)", req.MinDigits)
	}

	if req.MinLower > 0 {
		policy += fmt.Sprintf(" and lowerCase(%d)", req.MinLower)
	}

	if req.MinUpper > 0 {
		policy += fmt.Sprintf(" and upperCase(%d)", req.MinUpper)
	}

	if req.MinSpecial > 0 {
		policy += fmt.Sprintf(" and specialChars(%d)", req.MinSpecial)
	}

	if req.RecentlyUsed > 0 {
		policy += fmt.Sprintf(" and passwordHistory(%d)", req.RecentlyUsed)
	}

	if req.PasswordAge > 0 {
		policy += fmt.Sprintf(" and passwordAge(%d)", req.PasswordAge)
	}

	if req.ForceExpirePasswordChange > 0 {
		policy += fmt.Sprintf(" and forceExpiredPasswordChange(%d)", req.ForceExpirePasswordChange)
	}

	token, _ := s.client.GetAccessToken()
	_, err := s.client.GetRealm(ctx, token, authInfo.Realm)
	if err != nil {
		// sanity check
		log.Printf("failed to get realm %s: %s", authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}
	update := gocloak.RealmRepresentation{
		Realm:          gocloak.StringP(authInfo.Realm),
		PasswordPolicy: gocloak.StringP(policy),
	}

	err = s.client.UpdateRealm(ctx, token, update)
	if err != nil {
		log.Printf("failed to update password policy for realm %s: %s", authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	return &api.MyPasswordPolicyUpdateResp{}, nil
}

// Identity Provider Management Methods

func (s *MyTenantServer) GetIdentityProviderTypes(ctx context.Context, req *api.IdpProvidersReq) (*api.IdpProvidersResp, error) {
	// Return available provider types metadata
	allProviders := []*api.IdpProviderMetadata{
		{
			ProviderType: api.IdpProviderType_IDP_PROVIDER_GOOGLE,
			DisplayName:  "Google OAuth2",
			Description:  "Google OAuth2 identity provider for Gmail and Google Workspace accounts",
			ConfigFields: []*api.IdpConfigField{
				{
					Name:        "client_id",
					Type:        "string",
					Required:    true,
					Sensitive:   false,
					Description: "OAuth2 client ID from Google Console",
				},
				{
					Name:        "client_secret",
					Type:        "string",
					Required:    true,
					Sensitive:   true,
					Description: "OAuth2 client secret from Google Console",
				},
			},
			SupportedScopes: []string{"openid", "email", "profile"},
			DefaultScopes:   []string{"openid", "email", "profile"},
			Documentation:   "https://developers.google.com/identity/protocols/oauth2",
		},
		{
			ProviderType: api.IdpProviderType_IDP_PROVIDER_MICROSOFT,
			DisplayName:  "Microsoft OAuth2",
			Description:  "Microsoft OAuth2 identity provider for Azure AD and Office 365 accounts",
			ConfigFields: []*api.IdpConfigField{
				{
					Name:        "client_id",
					Type:        "string",
					Required:    true,
					Sensitive:   false,
					Description: "Application (client) ID from Azure portal",
				},
				{
					Name:        "client_secret",
					Type:        "string",
					Required:    true,
					Sensitive:   true,
					Description: "Client secret from Azure portal",
				},
				{
					Name:         "tenant_id",
					Type:         "string",
					Required:     false,
					Sensitive:    false,
					Description:  "Azure AD tenant ID (optional, defaults to common)",
					DefaultValue: "common",
				},
			},
			SupportedScopes: []string{"openid", "email", "profile", "User.Read"},
			DefaultScopes:   []string{"openid", "email", "profile"},
			Documentation:   "https://docs.microsoft.com/en-us/azure/active-directory/develop/",
		},
		{
			ProviderType: api.IdpProviderType_IDP_PROVIDER_OIDC,
			DisplayName:  "OpenID Connect",
			Description:  "Generic OpenID Connect identity provider",
			ConfigFields: []*api.IdpConfigField{
				{
					Name:        "issuer_url",
					Type:        "string",
					Required:    true,
					Sensitive:   false,
					Description: "OpenID Connect issuer URL",
				},
				{
					Name:        "client_id",
					Type:        "string",
					Required:    true,
					Sensitive:   false,
					Description: "OpenID Connect client ID",
				},
				{
					Name:        "client_secret",
					Type:        "string",
					Required:    true,
					Sensitive:   true,
					Description: "OpenID Connect client secret",
				},
			},
			SupportedScopes: []string{"openid", "email", "profile"},
			DefaultScopes:   []string{"openid", "email", "profile"},
			Documentation:   "https://openid.net/connect/",
		},
		{
			ProviderType: api.IdpProviderType_IDP_PROVIDER_SAML,
			DisplayName:  "SAML 2.0",
			Description:  "SAML 2.0 identity provider",
			ConfigFields: []*api.IdpConfigField{
				{
					Name:        "sso_url",
					Type:        "string",
					Required:    true,
					Sensitive:   false,
					Description: "SAML SSO URL",
				},
				{
					Name:        "entity_id",
					Type:        "string",
					Required:    true,
					Sensitive:   false,
					Description: "SAML entity ID",
				},
				{
					Name:        "certificate",
					Type:        "string",
					Required:    true,
					Sensitive:   false,
					Description: "X.509 certificate for signature verification",
				},
			},
			SupportedScopes: []string{},
			DefaultScopes:   []string{},
			Documentation:   "https://en.wikipedia.org/wiki/SAML_2.0",
		},
	}

	// Filter providers if a specific type is requested
	var providers []*api.IdpProviderMetadata
	if req.GetProviderType() != api.IdpProviderType_IDP_PROVIDER_UNSPECIFIED {
		// Find the specific provider type
		for _, provider := range allProviders {
			if provider.ProviderType == req.GetProviderType() {
				providers = append(providers, provider)
				break
			}
		}
	} else {
		// Return all providers if no filter specified
		providers = allProviders
	}

	return &api.IdpProvidersResp{
		Providers: providers,
	}, nil
}

func (s *MyTenantServer) GetIdentityProviderInstance(ctx context.Context, req *api.IdpInstanceGetReq) (*api.IdpInstanceGetResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	if strings.TrimSpace(req.Alias) == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Identity provider alias is required")
	}

	key := &table.IdentityProviderKey{
		Tenant: authInfo.Realm,
		Alias:  req.Alias,
	}

	provider, err := s.idpTable.Find(ctx, key)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Identity provider %s not found", req.Alias)
		}
		log.Printf("failed to get identity provider %s for tenant %s: %s", req.Alias, authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Failed to retrieve identity provider")
	}

	// Convert configuration to JSON (excluding sensitive fields)
	configJSON, err := s.sanitizeConfiguration(provider.Configuration)
	if err != nil {
		log.Printf("failed to sanitize configuration for provider %s: %s", req.Alias, err)
		return nil, status.Errorf(codes.Internal, "Failed to process configuration")
	}

	return &api.IdpInstanceGetResp{
		Alias:         provider.Key.Alias,
		DisplayName:   provider.DisplayName,
		ProviderType:  s.convertTableProviderType(provider.ProviderType),
		Enabled:       provider.Enabled,
		DisplayOrder:  int32(provider.DisplayOrder),
		Configuration: configJSON,
		Created:       provider.Created,
		Updated:       provider.Updated,
		CreatedBy:     provider.CreatedBy,
		UpdatedBy:     provider.UpdatedBy,
	}, nil
}

func (s *MyTenantServer) CreateIdentityProviderInstance(ctx context.Context, req *api.IdpInstanceCreateReq) (*api.IdpInstanceCreateResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}

	// Ensure we have a valid user ID for audit trail
	userID := authInfo.UserName
	if userID == "" {
		return nil, status.Error(codes.Unauthenticated, "user ID missing from authentication context")
	}

	// Check tenant admin privileges
	if authInfo.Roles == nil || !slices.Contains(authInfo.Roles, "admin") {
		return nil, status.Errorf(codes.PermissionDenied, "tenant admin privileges required")
	}

	// Create the provider key
	key := &table.IdentityProviderKey{
		Tenant: authInfo.Realm,
		Alias:  req.Alias,
	}

	// Parse and validate configuration
	var config map[string]interface{}
	var secrets *table.ProviderSecrets

	// Convert and validate provider type first
	tableProviderType, err := s.convertProtoProviderType(req.ProviderType)
	if err != nil {
		return nil, err
	}

	if req.Configuration != "" {
		// First validate the original configuration before extracting secrets
		var originalConfig map[string]interface{}
		if err := json.Unmarshal([]byte(req.Configuration), &originalConfig); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration JSON: %v", err)
		}

		// Validate configuration with all fields present
		if err := s.idpTable.ValidateConfiguration(ctx, tableProviderType, originalConfig); err != nil {
			formattedDetails := s.formatValidationError(err)
			return nil, status.Errorf(codes.InvalidArgument, "invalid provider configuration for %s: %s", req.ProviderType, formattedDetails)
		}

		config, secrets, err = s.parseConfiguration(req.ProviderType, req.Configuration)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration JSON: %v", err)
		}
	}

	// Create the provider entry
	entry := &table.IdentityProviderEntry{
		Key:           key,
		ProviderType:  tableProviderType,
		DisplayName:   req.DisplayName,
		DisplayOrder:  int(req.DisplayOrder),
		Enabled:       req.Enabled,
		Configuration: config,
		Secrets:       secrets,
		Created:       time.Now().Unix(),
		Updated:       time.Now().Unix(),
		CreatedBy:     userID, // Use actual user ID from authentication context
		UpdatedBy:     userID, // Use actual user ID from authentication context
	}

	// Insert the provider
	if err := s.idpTable.Locate(ctx, key, entry); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return nil, status.Error(codes.AlreadyExists, "identity provider with this alias already exists")
		}
		return nil, status.Errorf(codes.Internal, "failed to create identity provider: %v", err)
	}

	return &api.IdpInstanceCreateResp{
		Alias:   req.Alias,
		Message: "Identity provider created successfully",
	}, nil
}

func (s *MyTenantServer) UpdateIdentityProviderInstance(ctx context.Context, req *api.IdpInstanceUpdateReq) (*api.IdpInstanceUpdateResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Ensure we have a valid user ID for audit trail
	userID := authInfo.UserName
	if userID == "" {
		return nil, status.Error(codes.Unauthenticated, "user ID missing from authentication context")
	}

	// Check tenant admin privileges
	if authInfo.Roles == nil || !slices.Contains(authInfo.Roles, "admin") {
		return nil, status.Errorf(codes.PermissionDenied, "tenant admin privileges required")
	}

	if strings.TrimSpace(req.Alias) == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Identity provider alias is required")
	}

	key := &table.IdentityProviderKey{
		Tenant: authInfo.Realm,
		Alias:  req.Alias,
	}

	// Get existing provider
	existing, err := s.idpTable.Find(ctx, key)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Identity provider %s not found", req.Alias)
		}
		log.Printf("failed to get identity provider %s for tenant %s: %s", req.Alias, authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Failed to retrieve identity provider")
	}

	// Parse and validate new configuration if provided
	var config map[string]interface{}
	var secrets *table.ProviderSecrets

	if req.Configuration != "" {
		// First, reconstruct the full existing configuration by merging existing config and secrets
		fullExistingConfig := make(map[string]interface{})

		// Copy existing non-sensitive configuration
		for k, v := range existing.Configuration {
			fullExistingConfig[k] = v
		}

		// Add back sensitive fields from existing secrets
		if existing.Secrets != nil {
			if existing.Secrets.ClientSecret != "" {
				fullExistingConfig["client_secret"] = existing.Secrets.ClientSecret
			}
			if existing.Secrets.PrivateKey != "" {
				fullExistingConfig["private_key"] = existing.Secrets.PrivateKey
			}
			if existing.Secrets.Certificate != "" {
				fullExistingConfig["signing_certificate"] = existing.Secrets.Certificate
			}
			// Add any additional secrets
			for k, v := range existing.Secrets.AdditionalSecrets {
				fullExistingConfig[k] = v
			}
		}

		// Parse incoming configuration
		var incomingConfig map[string]interface{}
		if err := json.Unmarshal([]byte(req.Configuration), &incomingConfig); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration JSON: %v", err)
		}

		// Merge incoming configuration with existing (incoming takes precedence)
		for k, v := range incomingConfig {
			fullExistingConfig[k] = v
		}

		// Validate the merged full configuration
		if err := s.idpTable.ValidateConfiguration(ctx, existing.ProviderType, fullExistingConfig); err != nil {
			formattedDetails := s.formatValidationError(err)
			return nil, status.Errorf(codes.InvalidArgument, "invalid provider configuration for %s: %s", s.convertTableProviderTypeToProto(existing.ProviderType), formattedDetails)
		}

		// Convert merged config back to JSON for parsing
		mergedConfigBytes, err := json.Marshal(fullExistingConfig)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to serialize merged configuration")
		}

		// Parse the merged configuration to extract secrets
		config, secrets, err = s.parseConfiguration(s.convertTableProviderTypeToProto(existing.ProviderType), string(mergedConfigBytes))
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid configuration: %s", err)
		}
	} else {
		config = existing.Configuration
		secrets = existing.Secrets
	}

	// Update entry
	update := &table.IdentityProviderEntry{
		Key:           existing.Key,
		ProviderType:  existing.ProviderType,
		DisplayName:   req.DisplayName,
		DisplayOrder:  int(req.DisplayOrder),
		Enabled:       req.Enabled,
		Configuration: config,
		Secrets:       secrets,
		Created:       existing.Created,
		Updated:       time.Now().Unix(),
		CreatedBy:     existing.CreatedBy,
		UpdatedBy:     userID, // Use actual user ID from authentication context
	}

	err = s.idpTable.Update(ctx, key, update)
	if err != nil {
		log.Printf("failed to update identity provider %s for tenant %s: %s", req.Alias, authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Failed to update identity provider")
	}

	return &api.IdpInstanceUpdateResp{
		Message: "Identity provider updated successfully",
	}, nil
}

func (s *MyTenantServer) DeleteIdentityProviderInstance(ctx context.Context, req *api.IdpInstanceDeleteReq) (*api.IdpInstanceDeleteResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Ensure we have a valid user ID for audit trail
	userID := authInfo.UserName
	if userID == "" {
		return nil, status.Error(codes.Unauthenticated, "user ID missing from authentication context")
	}

	// Check tenant admin privileges
	if authInfo.Roles == nil || !slices.Contains(authInfo.Roles, "admin") {
		return nil, status.Errorf(codes.PermissionDenied, "tenant admin privileges required")
	}

	if strings.TrimSpace(req.Alias) == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Identity provider alias is required")
	}

	key := &table.IdentityProviderKey{
		Tenant: authInfo.Realm,
		Alias:  req.Alias,
	}

	// Check if provider exists
	_, err := s.idpTable.Find(ctx, key)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Identity provider %s not found", req.Alias)
		}
		log.Printf("failed to get identity provider %s for tenant %s: %s", req.Alias, authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Failed to retrieve identity provider")
	}

	// Delete the provider
	err = s.idpTable.DeleteKey(ctx, key)
	if err != nil {
		log.Printf("failed to delete identity provider %s for tenant %s: %s", req.Alias, authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Failed to delete identity provider")
	}

	return &api.IdpInstanceDeleteResp{
		Message: "Identity provider deleted successfully",
	}, nil
}

// Helper methods for Identity Provider Management

// convertProtoProviderType converts protobuf provider type to table provider type
func (s *MyTenantServer) convertProtoProviderType(providerType api.IdpProviderType) (table.ProviderType, error) {
	switch providerType {
	case api.IdpProviderType_IDP_PROVIDER_GOOGLE:
		return table.ProviderTypeGoogle, nil
	case api.IdpProviderType_IDP_PROVIDER_MICROSOFT:
		return table.ProviderTypeMicrosoft, nil
	case api.IdpProviderType_IDP_PROVIDER_OIDC:
		return table.ProviderTypeOIDC, nil
	case api.IdpProviderType_IDP_PROVIDER_SAML:
		return table.ProviderTypeSAML, nil
	default:
		return table.ProviderTypeUnspecified, status.Errorf(codes.InvalidArgument, "unsupported provider type: %v", providerType)
	}
}

// convertTableProviderType converts table provider type to protobuf provider type
func (s *MyTenantServer) convertTableProviderType(providerType table.ProviderType) api.IdpProviderType {
	switch providerType {
	case table.ProviderTypeGoogle:
		return api.IdpProviderType_IDP_PROVIDER_GOOGLE
	case table.ProviderTypeMicrosoft:
		return api.IdpProviderType_IDP_PROVIDER_MICROSOFT
	case table.ProviderTypeOIDC:
		return api.IdpProviderType_IDP_PROVIDER_OIDC
	case table.ProviderTypeSAML:
		return api.IdpProviderType_IDP_PROVIDER_SAML
	case table.ProviderTypeUnspecified:
		return api.IdpProviderType_IDP_PROVIDER_UNSPECIFIED
	default:
		return api.IdpProviderType_IDP_PROVIDER_UNSPECIFIED
	}
}

// convertTableProviderTypeToProto converts table provider type to protobuf (helper for consistency)
func (s *MyTenantServer) convertTableProviderTypeToProto(providerType table.ProviderType) api.IdpProviderType {
	return s.convertTableProviderType(providerType)
}

// parseConfiguration parses the JSON configuration and extracts sensitive fields
func (s *MyTenantServer) parseConfiguration(providerType api.IdpProviderType, configJSON string) (map[string]interface{}, *table.ProviderSecrets, error) {
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return nil, nil, fmt.Errorf("invalid JSON configuration: %w", err)
	}

	// Extract sensitive fields based on provider type
	secrets := &table.ProviderSecrets{
		AdditionalSecrets: make(map[string]string),
	}

	// Extract client_secret (common to all OAuth2-based providers)
	if clientSecret, exists := config["client_secret"]; exists {
		if secretStr, ok := clientSecret.(string); ok && secretStr != "" {
			secrets.ClientSecret = secretStr
			delete(config, "client_secret") // Remove from non-sensitive config
		}
	}

	// Provider-specific sensitive field extraction
	switch providerType {
	case api.IdpProviderType_IDP_PROVIDER_SAML:
		// Extract SAML-specific sensitive fields
		if privateKey, exists := config["private_key"]; exists {
			if keyStr, ok := privateKey.(string); ok && keyStr != "" {
				secrets.PrivateKey = keyStr
				delete(config, "private_key")
			}
		}
		if cert, exists := config["signing_certificate"]; exists {
			if certStr, ok := cert.(string); ok && certStr != "" {
				secrets.Certificate = certStr
				delete(config, "signing_certificate")
			}
		}
	}

	return config, secrets, nil
}

// sanitizeConfiguration removes sensitive fields from configuration for display
func (s *MyTenantServer) sanitizeConfiguration(config map[string]interface{}) (string, error) {
	// Create a copy to avoid modifying the original
	sanitized := make(map[string]interface{})
	for k, v := range config {
		// Skip sensitive fields
		if k != "client_secret" && k != "private_key" && k != "signing_certificate" {
			sanitized[k] = v
		}
	}

	configBytes, err := json.Marshal(sanitized)
	if err != nil {
		return "", fmt.Errorf("failed to marshal configuration: %w", err)
	}

	return string(configBytes), nil
}

// formatValidationError formats validation errors with field-level details
func (s *MyTenantServer) formatValidationError(err error) string {
	// Check if this is a structured ValidationError
	if validationErr, ok := err.(*table.ValidationError); ok {
		return fmt.Sprintf("field '%s': %s", validationErr.Field, validationErr.Message)
	}

	// Fallback to the original error message for unstructured errors
	return err.Error()
}

func NewMyTenantServer(ctx *model.GrpcServerContext, client *keycloak.Client, ep string) *MyTenantServer {
	idpTbl, err := table.GetIdentityProviderTable()
	if err != nil {
		log.Panicf("failed to get identity provider table: %s", err)
	}

	srv := &MyTenantServer{
		client:   client,
		idpTable: idpTbl,
	}
	api.RegisterMyTenantServer(ctx.Server, srv)
	err = api.RegisterMyTenantHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	tbl, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("failed to get route table: %s", err)
	}
	for _, r := range api.RoutesMyTenant {
		key := &route.Key{
			Url:    r.Url,
			Method: r.Method,
		}
		entry := &route.Route{
			Key:      key,
			Endpoint: ep,
			Resource: r.Resource,
			Verb:     r.Verb,
		}
		if err := tbl.Locate(context.Background(), key, entry); err != nil {
			log.Panicf("failed to register route %d %s: %s", r.Method, r.Url, err)
		}
	}
	return srv
}
