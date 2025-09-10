// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/go-core-stack/core/db"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/table"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
)

var identityProviderTable *IdentityProviderTable

// ProviderType represents the type of identity provider
type ProviderType string

const (
	ProviderTypeUnspecified ProviderType = ""
	ProviderTypeGoogle      ProviderType = "google"
	ProviderTypeMicrosoft   ProviderType = "microsoft"
	ProviderTypeOIDC        ProviderType = "oidc"
	ProviderTypeSAML        ProviderType = "saml"
)

// IdentityProviderKey represents the composite key for identity providers
type IdentityProviderKey struct {
	Tenant string `bson:"tenant"`
	Alias  string `bson:"alias"`
}

// ProviderSecrets contains encrypted sensitive configuration data
type ProviderSecrets struct {
	ClientSecret      string            `bson:"clientSecret,omitempty"`
	PrivateKey        string            `bson:"privateKey,omitempty"`
	Certificate       string            `bson:"certificate,omitempty"`
	AdditionalSecrets map[string]string `bson:"additionalSecrets,omitempty"`
}

// MarshalBSON implements custom BSON marshaling for encryption
func (s *ProviderSecrets) MarshalBSON() ([]byte, error) {
	type Alias ProviderSecrets
	// Create a value copy of the receiver to avoid mutating the original
	secrets := Alias(*s)

	// Encrypt sensitive data before storing
	if s.ClientSecret != "" {
		encrypted, err := encryptor.EncryptString(s.ClientSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt client secret: %w", err)
		}
		secrets.ClientSecret = encrypted
	}

	if s.PrivateKey != "" {
		encrypted, err := encryptor.EncryptString(s.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key: %w", err)
		}
		secrets.PrivateKey = encrypted
	}

	if s.Certificate != "" {
		encrypted, err := encryptor.EncryptString(s.Certificate)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt certificate: %w", err)
		}
		secrets.Certificate = encrypted
	}

	// Encrypt additional secrets
	if s.AdditionalSecrets != nil {
		encryptedSecrets := make(map[string]string, len(s.AdditionalSecrets))
		for key, value := range s.AdditionalSecrets {
			encrypted, err := encryptor.EncryptString(value)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt additional secret '%s': %w", key, err)
			}
			encryptedSecrets[key] = encrypted
		}
		secrets.AdditionalSecrets = encryptedSecrets
	}

	return bson.Marshal(secrets)
}

// UnmarshalBSON implements custom BSON unmarshaling for decryption
func (s *ProviderSecrets) UnmarshalBSON(data []byte) error {
	type Alias ProviderSecrets
	secrets := &Alias{}

	if err := bson.Unmarshal(data, secrets); err != nil {
		return err
	}

	// Decrypt sensitive data after loading
	if secrets.ClientSecret != "" {
		decrypted, err := encryptor.DecryptString(secrets.ClientSecret)
		if err != nil {
			return fmt.Errorf("failed to decrypt client secret: %w", err)
		}
		s.ClientSecret = decrypted
	}

	if secrets.PrivateKey != "" {
		decrypted, err := encryptor.DecryptString(secrets.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt private key: %w", err)
		}
		s.PrivateKey = decrypted
	}

	if secrets.Certificate != "" {
		decrypted, err := encryptor.DecryptString(secrets.Certificate)
		if err != nil {
			return fmt.Errorf("failed to decrypt certificate: %w", err)
		}
		s.Certificate = decrypted
	}

	// Decrypt additional secrets
	if secrets.AdditionalSecrets != nil {
		decryptedSecrets := make(map[string]string, len(secrets.AdditionalSecrets))
		for key, value := range secrets.AdditionalSecrets {
			decrypted, err := encryptor.DecryptString(value)
			if err != nil {
				return fmt.Errorf("failed to decrypt additional secret '%s': %w", key, err)
			}
			decryptedSecrets[key] = decrypted
		}
		s.AdditionalSecrets = decryptedSecrets
	}

	return nil
}

// IdentityProviderEntry represents a complete identity provider configuration
type IdentityProviderEntry struct {
	Key           *IdentityProviderKey   `bson:"key,omitempty"`
	ProviderType  ProviderType           `bson:"providerType,omitempty"`
	DisplayName   string                 `bson:"displayName,omitempty"`
	DisplayOrder  int                    `bson:"displayOrder,omitempty"`
	Enabled       bool                   `bson:"enabled,omitempty"`
	Configuration map[string]interface{} `bson:"configuration,omitempty"`
	Secrets       *ProviderSecrets       `bson:"secrets,omitempty"`
	Created       int64                  `bson:"created,omitempty"`
	Updated       int64                  `bson:"updated,omitempty"`
	CreatedBy     string                 `bson:"createdBy,omitempty"`
	UpdatedBy     string                 `bson:"updatedBy,omitempty"`
}

// IdentityProviderTable implements the table interface for identity providers
type IdentityProviderTable struct {
	table.Table[IdentityProviderKey, IdentityProviderEntry]
	col db.StoreCollection
}

// GoogleOAuth2Config represents Google OAuth2 provider configuration
type GoogleOAuth2Config struct {
	ClientID             string `json:"client_id" validate:"required"`
	ClientSecret         string `json:"client_secret" validate:"required"`
	RedirectURI          string `json:"redirect_uri,omitempty"`
	HostedDomain         string `json:"hosted_domain,omitempty"`
	Prompt               string `json:"prompt,omitempty"`
	UseUserIPParam       bool   `json:"use_userip_param"`
	RequestRefreshToken  bool   `json:"request_refresh_token"`
	AdditionalScopes     string `json:"additional_scopes,omitempty"`
	LoginHint            string `json:"login_hint,omitempty"`
	IncludeGrantedScopes bool   `json:"include_granted_scopes"`
}

// MicrosoftOAuth2Config represents Microsoft OAuth2 provider configuration
type MicrosoftOAuth2Config struct {
	ClientID         string `json:"client_id" validate:"required"`
	ClientSecret     string `json:"client_secret" validate:"required"`
	RedirectURI      string `json:"redirect_uri,omitempty"`
	TenantID         string `json:"tenant_id,omitempty"`
	Prompt           string `json:"prompt,omitempty"`
	AdditionalScopes string `json:"additional_scopes,omitempty"`
	DomainHint       string `json:"domain_hint,omitempty"`
	LoginHint        string `json:"login_hint,omitempty"`
}

// OIDCConfig represents OpenID Connect provider configuration
type OIDCConfig struct {
	ClientID                          string `json:"client_id" validate:"required"`
	ClientSecret                      string `json:"client_secret" validate:"required"`
	DiscoveryEndpoint                 string `json:"discovery_endpoint" validate:"required"`
	RedirectURI                       string `json:"redirect_uri,omitempty"`
	UseDiscoveryEndpoint              bool   `json:"use_discovery_endpoint"`
	ClientAuthentication              string `json:"client_authentication,omitempty"`
	ClientAssertionSignatureAlgorithm string `json:"client_assertion_signature_algorithm,omitempty"`
	AdditionalScopes                  string `json:"additional_scopes,omitempty"`
	ValidateSignatures                bool   `json:"validate_signatures"`
	UseJWKSURL                        bool   `json:"use_jwks_url"`
	JWKSURL                           string `json:"jwks_url,omitempty"`
}

// SAMLConfig represents SAML provider configuration
type SAMLConfig struct {
	ServiceProviderEntityID  string `json:"service_provider_entity_id" validate:"required"`
	SAMLEntityDescriptor     string `json:"saml_entity_descriptor" validate:"required"`
	SSOServiceURL            string `json:"sso_service_url" validate:"required"`
	RedirectURI              string `json:"redirect_uri,omitempty"`
	IdentityProviderEntityID string `json:"identity_provider_entity_id,omitempty"`
	SingleLogoutServiceURL   string `json:"single_logout_service_url,omitempty"`
	NameIDPolicyFormat       string `json:"nameid_policy_format,omitempty"`
	WantAuthnRequestsSigned  bool   `json:"want_authn_requests_signed"`
	ValidateSignatures       bool   `json:"validate_signatures"`
	SigningCertificate       string `json:"signing_certificate,omitempty"`
	EncryptionCertificate    string `json:"encryption_certificate,omitempty"`
	ForceAuthentication      bool   `json:"force_authentication"`
	PostBindingResponse      bool   `json:"post_binding_response"`
	PostBindingLogout        bool   `json:"post_binding_logout"`
	WantAssertionsSigned     bool   `json:"want_assertions_signed"`
	WantAssertionsEncrypted  bool   `json:"want_assertions_encrypted"`
	SignatureAlgorithm       string `json:"signature_algorithm,omitempty"`
	SAMLSignatureKeyName     string `json:"saml_signature_key_name,omitempty"`
	CanonalizationMethod     string `json:"canonicalization_method,omitempty"`
}

// ProviderConfigField represents metadata about configuration fields
type ProviderConfigField struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Required     bool        `json:"required"`
	Sensitive    bool        `json:"sensitive"`
	Description  string      `json:"description"`
	DefaultValue interface{} `json:"default_value,omitempty"`
	Validation   string      `json:"validation,omitempty"`
}

// ProviderMetadata contains metadata about each provider type
type ProviderMetadata struct {
	ProviderType    ProviderType          `json:"provider_type"`
	DisplayName     string                `json:"display_name"`
	Description     string                `json:"description"`
	ConfigFields    []ProviderConfigField `json:"config_fields"`
	SupportedScopes []string              `json:"supported_scopes,omitempty"`
	DefaultScopes   []string              `json:"default_scopes,omitempty"`
	Documentation   string                `json:"documentation,omitempty"`
}

// GetIdentityProviderTable returns the identity provider table instance
func GetIdentityProviderTable() (*IdentityProviderTable, error) {
	if identityProviderTable != nil {
		return identityProviderTable, nil
	}

	return nil, errors.Wrapf(errors.NotFound, "identity provider table not found")
}

// LocateIdentityProviderTable locates and initializes the identity provider table
func LocateIdentityProviderTable(client db.StoreClient) (*IdentityProviderTable, error) {
	if identityProviderTable != nil {
		return identityProviderTable, nil
	}

	col := client.GetCollection(AuthDatabaseName, IdentityProviderCollectionName)
	tbl := &IdentityProviderTable{
		col: col,
	}

	// Initialize the embedded Table with the same collection
	err := tbl.Initialize(col)
	if err != nil {
		return nil, err
	}

	log.Printf("DEBUG: LocateIdentityProviderTable - initialized table with collection")

	identityProviderTable = tbl

	return identityProviderTable, nil
}

// GetProviderMetadata returns metadata for all supported provider types
func GetProviderMetadata() map[ProviderType]ProviderMetadata {
	return map[ProviderType]ProviderMetadata{
		ProviderTypeGoogle: {
			ProviderType: ProviderTypeGoogle,
			DisplayName:  "Google",
			Description:  "Google OAuth2 authentication provider",
			ConfigFields: []ProviderConfigField{
				{Name: "client_id", Type: "string", Required: true, Description: "Google OAuth2 Client ID"},
				{Name: "client_secret", Type: "string", Required: true, Sensitive: true, Description: "Google OAuth2 Client Secret"},
				{Name: "redirect_uri", Type: "url", Required: false, Description: "OAuth2 redirect URI"},
				{Name: "hosted_domain", Type: "string", Required: false, Description: "Google Workspace domain restriction"},
				{Name: "prompt", Type: "string", Required: false, Description: "OAuth2 prompt parameter"},
				{Name: "use_userip_param", Type: "boolean", Required: false, DefaultValue: false, Description: "Include user IP in requests"},
				{Name: "request_refresh_token", Type: "boolean", Required: false, DefaultValue: false, Description: "Request refresh token"},
			},
			SupportedScopes: []string{"openid", "email", "profile"},
			DefaultScopes:   []string{"openid", "email", "profile"},
			Documentation:   "https://developers.google.com/identity/protocols/oauth2",
		},
		ProviderTypeMicrosoft: {
			ProviderType: ProviderTypeMicrosoft,
			DisplayName:  "Microsoft",
			Description:  "Microsoft OAuth2 authentication provider",
			ConfigFields: []ProviderConfigField{
				{Name: "client_id", Type: "string", Required: true, Description: "Microsoft Application (client) ID"},
				{Name: "client_secret", Type: "string", Required: true, Sensitive: true, Description: "Microsoft Client Secret"},
				{Name: "redirect_uri", Type: "url", Required: false, Description: "OAuth2 redirect URI"},
				{Name: "tenant_id", Type: "string", Required: false, DefaultValue: "common", Description: "Microsoft tenant ID"},
				{Name: "prompt", Type: "string", Required: false, Description: "OAuth2 prompt parameter"},
				{Name: "domain_hint", Type: "string", Required: false, Description: "Domain hint for faster login"},
			},
			SupportedScopes: []string{"openid", "email", "profile", "User.Read"},
			DefaultScopes:   []string{"openid", "email", "profile"},
			Documentation:   "https://docs.microsoft.com/en-us/azure/active-directory/develop/",
		},
		ProviderTypeOIDC: {
			ProviderType: ProviderTypeOIDC,
			DisplayName:  "OpenID Connect",
			Description:  "Generic OpenID Connect authentication provider",
			ConfigFields: []ProviderConfigField{
				{Name: "client_id", Type: "string", Required: true, Description: "OIDC Client ID"},
				{Name: "client_secret", Type: "string", Required: true, Sensitive: true, Description: "OIDC Client Secret"},
				{Name: "discovery_endpoint", Type: "url", Required: true, Description: "OIDC discovery endpoint"},
				{Name: "redirect_uri", Type: "url", Required: false, Description: "OAuth2 redirect URI"},
				{Name: "use_discovery_endpoint", Type: "boolean", Required: false, DefaultValue: true, Description: "Use discovery endpoint"},
				{Name: "client_authentication", Type: "string", Required: false, DefaultValue: "client_secret_post", Description: "Client authentication method"},
			},
			SupportedScopes: []string{"openid", "email", "profile"},
			DefaultScopes:   []string{"openid", "email", "profile"},
			Documentation:   "https://openid.net/connect/",
		},
		ProviderTypeSAML: {
			ProviderType: ProviderTypeSAML,
			DisplayName:  "SAML",
			Description:  "SAML 2.0 authentication provider",
			ConfigFields: []ProviderConfigField{
				{Name: "service_provider_entity_id", Type: "string", Required: true, Description: "Service Provider Entity ID"},
				{Name: "saml_entity_descriptor", Type: "text", Required: true, Description: "SAML Entity Descriptor XML"},
				{Name: "sso_service_url", Type: "url", Required: true, Description: "SSO Service URL"},
				{Name: "identity_provider_entity_id", Type: "string", Required: false, Description: "Identity Provider Entity ID"},
				{Name: "single_logout_service_url", Type: "url", Required: false, Description: "Single Logout Service URL"},
				{Name: "nameid_policy_format", Type: "string", Required: false, DefaultValue: "persistent", Description: "NameID Policy Format"},
				{Name: "want_authn_requests_signed", Type: "boolean", Required: false, DefaultValue: false, Description: "Sign authentication requests"},
				{Name: "validate_signatures", Type: "boolean", Required: false, DefaultValue: false, Description: "Validate SAML signatures"},
			},
			Documentation: "https://docs.oasis-open.org/security/saml/v2.0/",
		},
	}
}

// ValidateConfiguration validates provider configuration based on type
func (t *IdentityProviderTable) ValidateConfiguration(ctx context.Context, providerType ProviderType, config map[string]interface{}) error {
	metadata := GetProviderMetadata()
	providerMeta, exists := metadata[providerType]
	if !exists {
		return ErrUnsupportedProviderType
	}

	// Validate required fields
	for _, field := range providerMeta.ConfigFields {
		if field.Required {
			if _, exists := config[field.Name]; !exists {
				return &ValidationError{
					Field:   field.Name,
					Message: "required field is missing",
				}
			}
		}
	}

	// Type-specific validation
	switch providerType {
	case ProviderTypeUnspecified:
		return ErrUnsupportedProviderType
	case ProviderTypeGoogle:
		return t.validateGoogleConfig(config)
	case ProviderTypeMicrosoft:
		return t.validateMicrosoftConfig(config)
	case ProviderTypeOIDC:
		return t.validateOIDCConfig(config)
	case ProviderTypeSAML:
		return t.validateSAMLConfig(config)
	}

	return nil
}

// validateGoogleConfig validates Google OAuth2 configuration
func (t *IdentityProviderTable) validateGoogleConfig(config map[string]interface{}) error {
	var googleConfig GoogleOAuth2Config
	configBytes, _ := json.Marshal(config)
	if err := json.Unmarshal(configBytes, &googleConfig); err != nil {
		return &ValidationError{Field: "configuration", Message: "invalid configuration format"}
	}

	if googleConfig.ClientID == "" {
		return &ValidationError{Field: "client_id", Message: "client_id is required"}
	}
	if googleConfig.ClientSecret == "" {
		return &ValidationError{Field: "client_secret", Message: "client_secret is required"}
	}

	// Validate hosted domain format if provided
	if googleConfig.HostedDomain != "" {
		if err := validateDomain(googleConfig.HostedDomain); err != nil {
			return &ValidationError{Field: "hosted_domain", Message: fmt.Sprintf("invalid domain format: %v", err)}
		}
	}

	// Validate redirect URI if provided
	if googleConfig.RedirectURI != "" {
		if err := validateURL(googleConfig.RedirectURI); err != nil {
			return &ValidationError{Field: "redirect_uri", Message: fmt.Sprintf("invalid redirect URI: %v", err)}
		}
	}

	return nil
}

// validateMicrosoftConfig validates Microsoft OAuth2 configuration
func (t *IdentityProviderTable) validateMicrosoftConfig(config map[string]interface{}) error {
	var msConfig MicrosoftOAuth2Config
	configBytes, _ := json.Marshal(config)
	if err := json.Unmarshal(configBytes, &msConfig); err != nil {
		return &ValidationError{Field: "configuration", Message: "invalid configuration format"}
	}

	if msConfig.ClientID == "" {
		return &ValidationError{Field: "client_id", Message: "client_id is required"}
	}
	if msConfig.ClientSecret == "" {
		return &ValidationError{Field: "client_secret", Message: "client_secret is required"}
	}

	// Validate tenant ID format if provided
	if msConfig.TenantID != "" && msConfig.TenantID != "common" && msConfig.TenantID != "organizations" && msConfig.TenantID != "consumers" {
		if err := validateUUID(msConfig.TenantID); err != nil {
			return &ValidationError{Field: "tenant_id", Message: fmt.Sprintf("invalid tenant_id format: %v", err)}
		}
	}

	// Validate redirect URI if provided
	if msConfig.RedirectURI != "" {
		if err := validateURL(msConfig.RedirectURI); err != nil {
			return &ValidationError{Field: "redirect_uri", Message: fmt.Sprintf("invalid redirect URI: %v", err)}
		}
	}

	return nil
}

// validateOIDCConfig validates OIDC configuration
func (t *IdentityProviderTable) validateOIDCConfig(config map[string]interface{}) error {
	var oidcConfig OIDCConfig
	configBytes, _ := json.Marshal(config)
	if err := json.Unmarshal(configBytes, &oidcConfig); err != nil {
		return &ValidationError{Field: "configuration", Message: "invalid configuration format"}
	}

	if oidcConfig.ClientID == "" {
		return &ValidationError{Field: "client_id", Message: "client_id is required"}
	}
	if oidcConfig.ClientSecret == "" {
		return &ValidationError{Field: "client_secret", Message: "client_secret is required"}
	}
	if oidcConfig.DiscoveryEndpoint == "" {
		return &ValidationError{Field: "discovery_endpoint", Message: "discovery_endpoint is required"}
	}

	// Validate discovery endpoint URL
	if err := validateURL(oidcConfig.DiscoveryEndpoint); err != nil {
		return &ValidationError{Field: "discovery_endpoint", Message: fmt.Sprintf("invalid discovery endpoint URL: %v", err)}
	}

	// Require HTTPS for discovery endpoint security
	parsedURL, err := url.Parse(oidcConfig.DiscoveryEndpoint)
	if err != nil {
		return &ValidationError{Field: "discovery_endpoint", Message: "invalid discovery endpoint URL format"}
	}
	if parsedURL.Scheme != "https" {
		return &ValidationError{Field: "discovery_endpoint", Message: "discovery endpoint must use https"}
	}

	// Validate redirect URI if provided
	if oidcConfig.RedirectURI != "" {
		if err := validateURL(oidcConfig.RedirectURI); err != nil {
			return &ValidationError{Field: "redirect_uri", Message: fmt.Sprintf("invalid redirect URI: %v", err)}
		}
	}

	// Validate JWKS URL if provided
	if oidcConfig.JWKSURL != "" {
		if err := validateURL(oidcConfig.JWKSURL); err != nil {
			return &ValidationError{Field: "jwks_url", Message: fmt.Sprintf("invalid JWKS URL: %v", err)}
		}
	}

	return nil
}

// validateSAMLConfig validates SAML configuration
func (t *IdentityProviderTable) validateSAMLConfig(config map[string]interface{}) error {
	var samlConfig SAMLConfig
	configBytes, _ := json.Marshal(config)
	if err := json.Unmarshal(configBytes, &samlConfig); err != nil {
		return &ValidationError{Field: "configuration", Message: "invalid configuration format"}
	}

	if samlConfig.ServiceProviderEntityID == "" {
		return &ValidationError{Field: "service_provider_entity_id", Message: "service_provider_entity_id is required"}
	}
	if samlConfig.SAMLEntityDescriptor == "" {
		return &ValidationError{Field: "saml_entity_descriptor", Message: "saml_entity_descriptor is required"}
	}
	if samlConfig.SSOServiceURL == "" {
		return &ValidationError{Field: "sso_service_url", Message: "sso_service_url is required"}
	}

	// Validate SSO service URL
	if err := validateURL(samlConfig.SSOServiceURL); err != nil {
		return &ValidationError{Field: "sso_service_url", Message: fmt.Sprintf("invalid SSO service URL: %v", err)}
	}

	// Require HTTPS for SSO service URL security
	parsedURL, err := url.Parse(samlConfig.SSOServiceURL)
	if err != nil {
		return &ValidationError{Field: "sso_service_url", Message: "invalid SSO service URL format"}
	}
	if parsedURL.Scheme != "https" {
		return &ValidationError{Field: "sso_service_url", Message: "SSO service URL must use HTTPS"}
	}

	// Validate SingleLogoutServiceURL if provided
	if samlConfig.SingleLogoutServiceURL != "" {
		if err := validateURL(samlConfig.SingleLogoutServiceURL); err != nil {
			return &ValidationError{Field: "single_logout_service_url", Message: fmt.Sprintf("invalid single logout service URL: %v", err)}
		}

		// Require HTTPS for Single Logout Service URL security
		parsedURL, err := url.Parse(samlConfig.SingleLogoutServiceURL)
		if err != nil {
			return &ValidationError{Field: "single_logout_service_url", Message: "invalid single logout service URL format"}
		}
		if parsedURL.Scheme != "https" {
			return &ValidationError{Field: "single_logout_service_url", Message: "single logout service URL must use HTTPS"}
		}
	}

	// Validate redirect URI if provided
	if samlConfig.RedirectURI != "" {
		if err := validateURL(samlConfig.RedirectURI); err != nil {
			return &ValidationError{Field: "redirect_uri", Message: fmt.Sprintf("invalid redirect URI: %v", err)}
		}
	}

	return nil
}

// Custom error types
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

var (
	ErrUnsupportedProviderType = fmt.Errorf("unsupported provider type")
	ErrProviderNotFound        = fmt.Errorf("identity provider not found")
	ErrDuplicateAlias          = fmt.Errorf("identity provider with this alias already exists")
)

// Enhanced validation functions that return detailed errors
func validateDomain(domain string) error {
	if len(domain) == 0 {
		return fmt.Errorf("domain cannot be empty")
	}
	if len(domain) >= 253 {
		return fmt.Errorf("domain length cannot exceed 252 characters")
	}
	if strings.Contains(domain, " ") {
		return fmt.Errorf("domain cannot contain spaces")
	}
	return nil
}

func validateUUID(uuidStr string) error {
	if uuidStr == "" {
		return fmt.Errorf("UUID cannot be empty")
	}
	_, err := uuid.Parse(uuidStr)
	if err != nil {
		return fmt.Errorf("invalid UUID format: %w", err)
	}
	return nil
}

func validateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL cannot be empty")
	}
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}
	if parsedURL.Scheme == "" {
		return fmt.Errorf("URL must include a scheme (http:// or https://)")
	}
	if parsedURL.Host == "" {
		return fmt.Errorf("URL must include a host")
	}
	return nil
}
