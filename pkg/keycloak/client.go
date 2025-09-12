// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package keycloak

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v13"

	"github.com/go-core-stack/core/errors"
)

const (
	// Master realm name - typically named as master
	MasterRealmName = "master"

	// AdminClientID - client id to be used for creating Admin Client
	AdminClientID = "admin-cli"
)

var (
	// TokenExpiry safegaurd time ensures refreshing the token within
	// reasonable time ahead of actual expiry, in seconds
	tokenExpirySafeGuard = 10
)

type Client struct {
	// client cancel function
	cancel context.CancelFunc

	// gocloak lib handle
	gocloak.GoCloak

	// base url of the client
	url string

	// Realm where the user will be authenticated
	userRealm string

	// Client ID where user is being authenticated
	clientID string

	// token to be used for transaction with keycloak
	token *gocloak.JWT

	// mutex for token access
	tokenMu sync.RWMutex

	// isAdmin indicates if the client is admin client
	isAdmin bool
}

// create a new keycloak client for given endpoint
// and credentials
func New(url string) (*Client, error) {
	client := &Client{
		GoCloak:   *(gocloak.NewClient(url)),
		userRealm: MasterRealmName,
		clientID:  AdminClientID,
		url:       url,
		isAdmin:   true,
	}

	// perform adming login using the provided login credentials and user realm
	token, err := client.LoginAdmin(context.Background(), getKeycloakUsername(),
		getKeycloakPassword(), client.userRealm)
	if err != nil {
		return nil, err
	}

	client.token = token

	// starts the loop to keep the access token active all the time
	go client.refreshToken()

	return client, nil
}

// create a new keycloak client for given endpoint
// and user credentials
// This requires direct flow validations enabled, which
// typically is not considered secure and is not
// recommended for production scenarios, more to be used
// in development environment.
// where direct flow enablement needs to be done manually
func NewUserClient(url, realm, user, password string, skipTlsVerify bool) (*Client, error) {
	client := &Client{
		GoCloak:   *(gocloak.NewClient(url)),
		userRealm: realm,
		clientID:  "controller",
		url:       url,
	}

	// most of the time clients are going to be external and will require
	// SSL Validation, and since we are using internal keycloak deployment
	// provide a construct to skip SSL verification
	// this will typically not required in production scenarios and will be
	// used mostly in development environments
	if skipTlsVerify {
		restyClient := client.RestyClient()

		// skip ssl verify as we are always going to connect to internal deployment
		// of keycloak
		restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	}

	// perform adming login using the provided login credentials and user realm
	token, err := client.Login(context.Background(), client.clientID, "", client.userRealm, user, password)
	if err != nil {
		return nil, err
	}

	client.token = token

	// starts the loop to keep the access token active all the time
	go client.refreshToken()

	return client, nil
}

// create a new unauthenticated public keycloak client for given endpoint
// typically will be consumed by public authentication validators
//
// Public client is required only to be consumed by OIDC verifier for
// validating the provided token and usage is expected to be restricted
// to auth gateway internal use only
func NewPublicClient(url string) *Client {
	client := &Client{
		GoCloak: *(gocloak.NewClient(url)),
	}

	restyClient := client.RestyClient()
	// skip ssl verify as we are always going to connect to internal url of the keycloak
	restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	return client
}

// Gets the current access token from the client
func (c *Client) GetAccessToken() (string, error) {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	if c.token != nil {
		return c.token.AccessToken, nil
	}
	return "", errors.Wrapf(errors.InvalidArgument, "no current active session")
}

func (c *Client) refreshToken() {
	var ctx context.Context
	ctx, c.cancel = context.WithCancel(context.Background())
	defer c.cancel()
	interval := max(c.token.ExpiresIn-tokenExpirySafeGuard, 1)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := func() error {
				c.tokenMu.Lock()
				defer c.tokenMu.Unlock()
				token, err := c.RefreshToken(context.Background(), c.token.RefreshToken, c.clientID, "", c.userRealm)
				if err != nil {
					// failed to refresh token
					log.Printf("failed to refresh the token, got error: %s", err)
					if c.isAdmin {
						// for admin client try to re-login
						// perform adming login using the provided login credentials and user realm
						token, err = c.LoginAdmin(context.Background(), getKeycloakUsername(),
							getKeycloakPassword(), c.userRealm)
						if err != nil {
							log.Panicf("failed to re-login admin client, got error: %s", err)
							return err
						}
					} else {
						c.token = nil
						return err
					}
				}
				c.token = token
				interval := max(c.token.ExpiresIn-tokenExpirySafeGuard, 1)
				ticker.Reset(time.Duration(interval) * time.Second)
				return nil
			}()
			if err != nil {
				// return from the for loop upon encountering an error
				return
			}
		}
	}
}

// Logout and Close the existing Keycloak Client and session
func (c *Client) Logout(ctx context.Context) error {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	err := c.GoCloak.Logout(ctx, c.clientID, "", c.userRealm, c.token.RefreshToken)
	if err != nil {
		return err
	}

	if c.cancel != nil {
		c.cancel()
	}
	c.token = nil

	return nil
}

func (c *Client) getAdminRealmURL(basePath, realm string, path ...string) string {
	path = append([]string{basePath, "admin", "realms", realm}, path...)
	return strings.Join(path, "/")
}

// sessionCount Contains count of number of session in domain
type sessionCount struct {
	Count int `json:"count,omitempty"`
}

// GetClientUserSessions returns user sessions associated with the client
func (c *Client) GetClientUserSessionsCount(ctx context.Context, token, realm, idOfClient string) (int, error) {
	var result sessionCount
	resp, err := c.GetRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.getAdminRealmURL(c.url, realm, "clients", idOfClient, "session-count"))
	if resp == nil || resp.IsError() || err != nil {
		return -1, err
	}

	return result.Count, nil
}

// SessionLimitConfig represents the configuration for User session count limiter authenticator
type SessionLimitConfig struct {
	// Maximum concurrent sessions per user within the realm
	MaxConcurrentSessions int `json:"maxConcurrentSessions"`

	// Behavior when limit is exceeded: "deny" (reject login) or "terminate" (kill oldest session)
	BehaviorWhenLimitExceeded string `json:"behaviorWhenLimitExceeded"`
}

// AuthenticationFlow represents a Keycloak authentication flow
type AuthenticationFlow struct {
	ID          string `json:"id,omitempty"`
	Alias       string `json:"alias,omitempty"`
	Description string `json:"description,omitempty"`
	TopLevel    bool   `json:"topLevel,omitempty"`
	BuiltIn     bool   `json:"builtIn,omitempty"`
}

// AuthenticationExecution represents an execution in a Keycloak authentication flow
type AuthenticationExecution struct {
	ID            string `json:"id,omitempty"`
	Alias         string `json:"alias,omitempty"`
	Requirement   string `json:"requirement,omitempty"`
	Priority      int    `json:"priority,omitempty"`
	Authenticator string `json:"authenticator,omitempty"`
	FlowID        string `json:"flowId,omitempty"`
	ParentFlow    string `json:"parentFlow,omitempty"`
}

// AuthenticatorConfig represents the configuration for an authenticator execution
type AuthenticatorConfig struct {
	ID     string            `json:"id,omitempty"`
	Alias  string            `json:"alias,omitempty"`
	Config map[string]string `json:"config,omitempty"`
}

// ConfigureSessionLimitsInRealm fully automates the configuration of session limits in Keycloak
// This creates a copy of the Browser flow, adds the User session count limiter execution, and sets it as the realm's Browser flow
func (c *Client) ConfigureSessionLimitsInRealm(ctx context.Context, token, realm string, config SessionLimitConfig) error {
	log.Printf("Starting automated session limits configuration for realm %s", realm)

	// Get admin token for the target realm using admin-cli client
	adminToken, err := c.getRootRealmAdminToken(ctx, realm)
	if err != nil {
		return errors.Wrapf(errors.InvalidArgument, "failed to get admin token: %v", err)
	}

	// Step 1: Get existing Browser flow
	browserFlow, err := c.getAuthenticationFlow(ctx, adminToken, realm, "browser")
	if err != nil {
		return errors.Wrapf(errors.InvalidArgument, "failed to get browser flow: %v", err)
	}

	// Step 2: Create a copy of the Browser flow
	newFlowAlias := "browser-with-session-limits"
	newFlow, err := c.copyAuthenticationFlow(ctx, adminToken, realm, browserFlow.Alias, newFlowAlias)
	if err != nil {
		return errors.Wrapf(errors.InvalidArgument, "failed to copy browser flow: %v", err)
	}

	// Step 3: Add User session count limiter execution to the copied flow
	execution, err := c.addUserSessionLimiterExecution(ctx, adminToken, realm, newFlow.Alias)
	if err != nil {
		return errors.Wrapf(errors.InvalidArgument, "failed to add session limiter execution: %v", err)
	}

	// Step 4: Configure the execution with session limits
	err = c.configureSessionLimiterExecution(ctx, adminToken, realm, execution.ID, config)
	if err != nil {
		return errors.Wrapf(errors.InvalidArgument, "failed to configure session limiter execution: %v", err)
	}

	// Step 5: Set the new flow as the realm's Browser flow
	err = c.setRealmBrowserFlow(ctx, adminToken, realm, newFlowAlias)
	if err != nil {
		return errors.Wrapf(errors.InvalidArgument, "failed to set realm browser flow: %v", err)
	}

	log.Printf("Successfully configured automated session limits for realm %s with flow %s", realm, newFlowAlias)
	return nil
}

// getRootRealmAdminToken gets an admin token specifically for the target realm using admin-cli
func (c *Client) getRootRealmAdminToken(ctx context.Context, realm string) (string, error) {
	// Use admin-cli client which has full admin permissions
	token, err := c.Login(ctx, "admin-cli", "", realm, getKeycloakUsername(), getKeycloakPassword())
	if err != nil {
		return "", fmt.Errorf("failed to get %s realm admin token: %v", realm, err)
	}
	return token.AccessToken, nil
}

// getAuthenticationFlow retrieves an authentication flow by alias
func (c *Client) getAuthenticationFlow(ctx context.Context, token, realm, alias string) (*AuthenticationFlow, error) {
	var flows []AuthenticationFlow
	resp, err := c.GetRequestWithBearerAuth(ctx, token).
		SetResult(&flows).
		Get(c.getAdminRealmURL(c.url, realm, "authentication", "flows"))

	if resp == nil || err != nil {
		return nil, fmt.Errorf("failed to get authentication flows: %v", err)
	}

	if resp.IsError() {
		return nil, fmt.Errorf("failed to get authentication flows: HTTP %d - %s", resp.StatusCode(), string(resp.Body()))
	}

	for _, flow := range flows {
		if flow.Alias == alias {
			log.Printf("Found authentication flow: %s (ID: %s)", flow.Alias, flow.ID)
			return &flow, nil
		}
	}

	return nil, fmt.Errorf("authentication flow '%s' not found", alias)
}

// copyAuthenticationFlow creates a copy of an existing authentication flow
func (c *Client) copyAuthenticationFlow(ctx context.Context, token, realm, sourceAlias, newAlias string) (*AuthenticationFlow, error) {
	copyRequest := map[string]string{
		"newName": newAlias,
	}

	resp, err := c.GetRequestWithBearerAuth(ctx, token).
		SetHeader("Content-Type", "application/json").
		SetBody(copyRequest).
		Post(c.getAdminRealmURL(c.url, realm, "authentication", "flows", sourceAlias, "copy"))

	if resp == nil || err != nil {
		return nil, fmt.Errorf("failed to copy authentication flow: %v", err)
	}

	if resp.IsError() {
		return nil, fmt.Errorf("failed to copy authentication flow: HTTP %d - %s", resp.StatusCode(), string(resp.Body()))
	}

	log.Printf("Successfully copied authentication flow '%s' to '%s'", sourceAlias, newAlias)

	// Get the newly created flow
	return c.getAuthenticationFlow(ctx, token, realm, newAlias)
}

// addUserSessionLimiterExecution adds a User session count limiter execution to a flow
func (c *Client) addUserSessionLimiterExecution(ctx context.Context, token, realm, flowAlias string) (*AuthenticationExecution, error) {
	executionRequest := map[string]string{
		"provider": "user-session-limits",
	}

	resp, err := c.GetRequestWithBearerAuth(ctx, token).
		SetBody(executionRequest).
		Post(c.getAdminRealmURL(c.url, realm, "authentication", "flows", flowAlias, "executions", "execution"))

	if resp == nil || resp.IsError() || err != nil {
		return nil, fmt.Errorf("failed to add user session limiter execution: %v", err)
	}

	// Get the executions for the flow to find the newly added one
	executions, err := c.getFlowExecutions(ctx, token, realm, flowAlias)
	if err != nil {
		return nil, fmt.Errorf("failed to get flow executions: %v", err)
	}

	// Find the user-session-limits execution
	for _, execution := range executions {
		if execution.Authenticator == "user-session-limits" {
			return &execution, nil
		}
	}

	return nil, fmt.Errorf("failed to find newly created user session limiter execution")
}

// getFlowExecutions retrieves all executions for a given flow
func (c *Client) getFlowExecutions(ctx context.Context, token, realm, flowAlias string) ([]AuthenticationExecution, error) {
	var executions []AuthenticationExecution
	resp, err := c.GetRequestWithBearerAuth(ctx, token).
		SetResult(&executions).
		Get(c.getAdminRealmURL(c.url, realm, "authentication", "flows", flowAlias, "executions"))

	if resp == nil || resp.IsError() || err != nil {
		return nil, fmt.Errorf("failed to get flow executions: %v", err)
	}

	return executions, nil
}

// configureSessionLimiterExecution configures the User session count limiter execution
func (c *Client) configureSessionLimiterExecution(ctx context.Context, token, realm, executionID string, config SessionLimitConfig) error {
	configRequest := AuthenticatorConfig{
		Alias: "session-limits-config",
		Config: map[string]string{
			"max-sessions":         fmt.Sprintf("%d", config.MaxConcurrentSessions),
			"session-limit-action": config.BehaviorWhenLimitExceeded,
		},
	}

	resp, err := c.GetRequestWithBearerAuth(ctx, token).
		SetBody(configRequest).
		Post(c.getAdminRealmURL(c.url, realm, "authentication", "executions", executionID, "config"))

	if resp == nil || resp.IsError() || err != nil {
		return fmt.Errorf("failed to configure session limiter execution: %v", err)
	}

	// Set the execution requirement to REQUIRED
	updateRequest := map[string]string{
		"requirement": "REQUIRED",
	}

	resp, err = c.GetRequestWithBearerAuth(ctx, token).
		SetBody(updateRequest).
		Put(c.getAdminRealmURL(c.url, realm, "authentication", "flows", "executions"))

	if resp != nil && resp.IsError() {
		log.Printf("Warning: failed to set execution requirement to REQUIRED: %v", err)
	}

	return nil
}

// setRealmBrowserFlow sets the realm's Browser flow to the specified flow
func (c *Client) setRealmBrowserFlow(ctx context.Context, token, realm, flowAlias string) error {
	// Get current realm settings
	realmRep, err := c.GetRealm(ctx, token, realm)
	if err != nil {
		return fmt.Errorf("failed to get realm: %v", err)
	}

	// Update the Browser flow
	realmRep.BrowserFlow = gocloak.StringP(flowAlias)

	// Update the realm
	err = c.UpdateRealm(ctx, token, *realmRep)
	if err != nil {
		return fmt.Errorf("failed to update realm browser flow: %v", err)
	}

	return nil
}

// GetCurrentSessionLimitsConfig retrieves the current session limits configuration from Keycloak
func (c *Client) GetCurrentSessionLimitsConfig(ctx context.Context, token, realm string) (*SessionLimitConfig, error) {
	// Get the realm's current browser flow
	realmRep, err := c.GetRealm(ctx, token, realm)
	if err != nil {
		return nil, fmt.Errorf("failed to get realm: %v", err)
	}

	browserFlowAlias := "browser"
	if realmRep.BrowserFlow != nil {
		browserFlowAlias = *realmRep.BrowserFlow
	}

	// Get executions for the browser flow
	executions, err := c.getFlowExecutions(ctx, token, realm, browserFlowAlias)
	if err != nil {
		return nil, fmt.Errorf("failed to get flow executions: %v", err)
	}

	// Look for user-session-limits execution
	for _, execution := range executions {
		if execution.Authenticator == "user-session-limits" {
			// Get the configuration for this execution
			config, err := c.getExecutionConfig(ctx, token, realm, execution.ID)
			if err != nil {
				log.Printf("Warning: failed to get execution config for %s: %v", execution.ID, err)
				continue
			}

			if config != nil && config.Config != nil {
				sessionConfig := &SessionLimitConfig{}
				
				// Parse max sessions
				if maxSessions, exists := config.Config["max-sessions"]; exists {
					if val, err := strconv.Atoi(maxSessions); err == nil {
						sessionConfig.MaxConcurrentSessions = val
					}
				}
				
				// Parse behavior
				if behavior, exists := config.Config["session-limit-action"]; exists {
					sessionConfig.BehaviorWhenLimitExceeded = behavior
				}

				return sessionConfig, nil
			}
		}
	}

	// No session limits configured
	return nil, fmt.Errorf("no session limits configured for realm %s", realm)
}

// getExecutionConfig retrieves the configuration for an execution
func (c *Client) getExecutionConfig(ctx context.Context, token, realm, executionID string) (*AuthenticatorConfig, error) {
	var config AuthenticatorConfig
	resp, err := c.GetRequestWithBearerAuth(ctx, token).
		SetResult(&config).
		Get(c.getAdminRealmURL(c.url, realm, "authentication", "executions", executionID, "config"))

	if resp == nil || err != nil {
		return nil, fmt.Errorf("failed to get execution config: %v", err)
	}

	if resp.IsError() {
		if resp.StatusCode() == 404 {
			// No config exists for this execution
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get execution config: HTTP %d - %s", resp.StatusCode(), string(resp.Body()))
	}

	return &config, nil
}
