// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/go-core-stack/auth-gateway/api"
	"github.com/go-core-stack/auth-gateway/pkg/keycloak"
	"github.com/go-core-stack/auth-gateway/pkg/model"
	"github.com/go-core-stack/auth-gateway/pkg/table"
	auth "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type MyTenantServer struct {
	api.UnimplementedMyTenantServer
	client    *keycloak.Client
	tenantTbl *table.TenantTable
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

func (s *MyTenantServer) GetKeycloakSessionLimitsInstructions(ctx context.Context, req *api.GetKeycloakSessionLimitsInstructionsReq) (*api.GetKeycloakSessionLimitsInstructionsResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Get admin token and query current session limits configuration from Keycloak
	token, err := s.client.GetAccessToken()
	if err != nil {
		log.Printf("failed to get Keycloak access token: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	// Get current session limits configuration from Keycloak
	sessionConfig, err := s.client.GetCurrentSessionLimitsConfig(ctx, token, authInfo.Realm)
	if err != nil {
		log.Printf("failed to get current session limits config for realm %s: %s", authInfo.Realm, err)
		return nil, status.Errorf(codes.NotFound, "No session limits configured for realm %s", authInfo.Realm)
	}

	// Convert to API format
	config := &api.KeycloakSessionLimitsConfig{
		MaxConcurrentSessions: int32(sessionConfig.MaxConcurrentSessions),
	}

	switch sessionConfig.BehaviorWhenLimitExceeded {
	case "terminate":
		config.BehaviorWhenLimitExceeded = api.SessionLimitBehavior_TERMINATE
	default:
		config.BehaviorWhenLimitExceeded = api.SessionLimitBehavior_DENY
	}

	return &api.GetKeycloakSessionLimitsInstructionsResp{
		Config: config,
		Realm:  authInfo.Realm,
	}, nil
}

func (s *MyTenantServer) ConfigureKeycloakSessionLimits(ctx context.Context, req *api.ConfigureKeycloakSessionLimitsReq) (*api.ConfigureKeycloakSessionLimitsResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	if req.Config == nil {
		return nil, status.Errorf(codes.InvalidArgument, "session limits config is required")
	}

	// Validate input parameters
	if req.Config.MaxConcurrentSessions <= 0 {
		return nil, status.Errorf(codes.InvalidArgument, "max concurrent sessions must be > 0")
	}

	// Convert API config to Keycloak config
	config := keycloak.SessionLimitConfig{
		MaxConcurrentSessions: int(req.Config.MaxConcurrentSessions),
	}

	switch req.Config.BehaviorWhenLimitExceeded {
	case api.SessionLimitBehavior_TERMINATE:
		config.BehaviorWhenLimitExceeded = "terminate"
	default:
		config.BehaviorWhenLimitExceeded = "deny"
	}

	// Get admin token and configure session limits
	token, err := s.client.GetAccessToken()
	if err != nil {
		log.Printf("failed to get Keycloak access token: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	err = s.client.ConfigureSessionLimitsInRealm(ctx, token, authInfo.Realm, config)
	if err != nil {
		log.Printf("failed to configure session limits for realm %s: %s", authInfo.Realm, err)
		return nil, status.Errorf(codes.Internal, "Failed to configure session limits: %s", err.Error())
	}

	return &api.ConfigureKeycloakSessionLimitsResp{
		Message:      fmt.Sprintf("Session limits successfully configured for realm %s. The 'browser-with-session-limits' authentication flow has been created and set as the realm's Browser flow with %d max sessions and '%s' behavior.", authInfo.Realm, config.MaxConcurrentSessions, config.BehaviorWhenLimitExceeded),
		Instructions: fmt.Sprintf("Session limits are now active for realm '%s'. Users will be limited to %d concurrent sessions with '%s' behavior when the limit is exceeded.", authInfo.Realm, config.MaxConcurrentSessions, config.BehaviorWhenLimitExceeded),
	}, nil
}

func NewMyTenantServer(ctx *model.GrpcServerContext, client *keycloak.Client, ep string) *MyTenantServer {
	tenantTbl, err := table.GetTenantTable()
	if err != nil {
		log.Panicf("failed to get tenant table: %s", err)
	}

	srv := &MyTenantServer{
		client:    client,
		tenantTbl: tenantTbl,
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
