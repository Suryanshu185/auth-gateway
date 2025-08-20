// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	auth "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/utils"

	"github.com/go-core-stack/auth-gateway/api"
	"github.com/go-core-stack/auth-gateway/pkg/keycloak"
	"github.com/go-core-stack/auth-gateway/pkg/model"
	"github.com/go-core-stack/auth-gateway/pkg/table"
)

type TenantUserApiServer struct {
	api.UnimplementedTenantUserServer
	tenantTbl      *table.TenantTable
	userTbl        *table.UserTable
	orgUnitTbl     *table.OrgUnitTable
	orgUnitUserTbl *table.OrgUnitUserTable
	orgUnitRoleTbl *table.OrgUnitCustomRoleTable
	client         *keycloak.Client
}

func (s *TenantUserApiServer) getTenant(ctx context.Context, name string) (*table.TenantEntry, error) {
	tKey := table.TenantKey{
		Name: name,
	}

	tEntry, err := s.tenantTbl.Find(ctx, &tKey)
	if err != nil {
		log.Printf("failed to find the tenant entry: %s", err)
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Tenant %s not found", name)
		}
		return nil, status.Errorf(codes.Internal, "Somthing went wrong, Please try again later")
	}

	if tEntry.KCStatus == nil || tEntry.KCStatus.RealmName == "" {
		return nil, status.Errorf(codes.Unavailable, "Tenant %s setup not completed", name)
	}
	return tEntry, nil
}

func (s *TenantUserApiServer) GetUsers(ctx context.Context, req *api.TenantUsersListReq) (*api.TenantUsersListResp, error) {
	_, err := auth.GetAuthInfoFromContext(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Authentication required: %s", err.Error())
	}

	count, err := s.userTbl.CountByTenant(ctx, req.Tenant)
	if err != nil {
		log.Printf("failed to count users for tenant %s: %s", req.Tenant, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	resp := &api.TenantUsersListResp{
		Count: int32(count),
		Items: []*api.TenantUserListEntry{},
	}

	users, err := s.userTbl.GetByTenant(ctx, req.Tenant, req.Offset, req.Limit)
	if err != nil && !errors.IsNotFound(err) {
		log.Printf("failed to fetch users for tenant %s: %s", req.Tenant, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	for _, user := range users {
		item := &api.TenantUserListEntry{
			Username:   user.Key.Username,
			Email:      user.Info.Email,
			FirstName:  user.Info.FirstName,
			LastName:   user.Info.LastName,
			Enabled:    !utils.PBool(user.Disabled),
			Created:    user.Created,
			LastAccess: user.LastAccess,
		}
		resp.Items = append(resp.Items, item)
	}

	return resp, nil
}

func (s *TenantUserApiServer) CreateUser(ctx context.Context, req *api.TenantUserCreateReq) (*api.TenantUserCreateResp, error) {
	_, err := s.getTenant(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	uEntry := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   req.Tenant,
			Username: req.Username,
		},
		Info: &table.UserInfo{
			FirstName: req.Firstname,
			LastName:  req.Lastname,
			Email:     req.Email,
		},
		Created:  now,
		Updated:  now,
		Disabled: gocloak.BoolP(req.Disabled),
	}
	if req.Password != "" {
		uEntry.Password = &table.UserTempPassword{
			Value: req.Password,
		}
	}
	err = s.userTbl.Insert(ctx, uEntry.Key, uEntry)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return nil, status.Errorf(codes.InvalidArgument, "failed to create user: %s", err.Error())
		}
	}

	resp := &api.TenantUserCreateResp{
		Username:  req.Username,
		Email:     req.Email,
		FirstName: req.Firstname,
		LastName:  req.Lastname,
		Enabled:   !req.Disabled,
	}
	return resp, nil
}

func (s *TenantUserApiServer) GetUser(ctx context.Context, req *api.TenantUserGetReq) (*api.TenantUserGetResp, error) {
	uKey := &table.UserKey{
		Tenant:   req.Tenant,
		Username: req.Username,
	}
	uEntry, err := s.userTbl.Find(ctx, uKey)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "User %s not found in tenant %s", req.Username, req.Tenant)
		}
		log.Printf("failed to find user entry: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	resp := &api.TenantUserGetResp{
		Username:   uEntry.Key.Username,
		Email:      uEntry.Info.Email,
		FirstName:  uEntry.Info.FirstName,
		LastName:   uEntry.Info.LastName,
		Enabled:    !utils.PBool(uEntry.Disabled),
		Created:    uEntry.Created,
		LastAccess: uEntry.LastAccess,
	}
	return resp, nil
}

func (s *TenantUserApiServer) EnableUser(ctx context.Context, req *api.TenantUserEnableReq) (*api.TenantUserEnableResp, error) {
	tEntry, err := s.getTenant(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}

	if tEntry.Config.DefaultAdmin.UserID == req.Username {
		return nil, status.Errorf(codes.PermissionDenied, "Default Tenant Admin cannot be enabled/disabled")
	}

	update := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   req.Tenant,
			Username: req.Username,
		},
		Updated:  time.Now().Unix(),
		Disabled: gocloak.BoolP(false),
	}
	err = s.userTbl.Update(ctx, update.Key, update)
	if err != nil {
		log.Printf("failed to update user entry: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	return &api.TenantUserEnableResp{}, nil
}

func (s *TenantUserApiServer) DisableUser(ctx context.Context, req *api.TenantUserDisableReq) (*api.TenantUserDisableResp, error) {
	tEntry, err := s.getTenant(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}

	if tEntry.Config.DefaultAdmin.UserID == req.Username {
		return nil, status.Errorf(codes.PermissionDenied, "Default Tenant Admin cannot be enabled/disabled")
	}

	update := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   req.Tenant,
			Username: req.Username,
		},
		Updated:  time.Now().Unix(),
		Disabled: gocloak.BoolP(true),
	}
	err = s.userTbl.Update(ctx, update.Key, update)
	if err != nil {
		log.Printf("failed to update user entry: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	return &api.TenantUserDisableResp{}, nil
}

func (s *TenantUserApiServer) UpdateUser(ctx context.Context, req *api.TenantUserUpdateReq) (*api.TenantUserUpdateResp, error) {
	tEntry, err := s.getTenant(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}

	if tEntry.Config.DefaultAdmin.UserID == req.Username {
		return nil, status.Errorf(codes.PermissionDenied, "Default Tenant Admin cannot be updated")
	}

	update := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   req.Tenant,
			Username: req.Username,
		},
		Info: &table.UserInfo{
			FirstName: req.Firstname,
			LastName:  req.Lastname,
			Email:     req.Email,
		},
		Updated:  time.Now().Unix(),
		Disabled: utils.BoolP(req.Disabled),
	}
	err = s.userTbl.Update(ctx, update.Key, update)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "User %s not found in tenant %s", req.Username, req.Tenant)
		}
		log.Printf("failed to update user entry: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	resp := &api.TenantUserUpdateResp{
		Username:  update.Key.Username,
		Email:     update.Info.Email,
		FirstName: update.Info.FirstName,
		LastName:  update.Info.LastName,
	}
	return resp, nil
}

func (s *TenantUserApiServer) DeleteUser(ctx context.Context, req *api.TenantUserDeleteReq) (*api.TenantUserDeleteResp, error) {
	tEntry, err := s.getTenant(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}

	if tEntry.Config.DefaultAdmin.UserID == req.Username {
		return nil, status.Errorf(codes.PermissionDenied, "Default Tenant Admin")
	}

	now := time.Now().Unix()
	uEntry := &table.UserEntry{
		Key: &table.UserKey{
			Tenant:   req.Tenant,
			Username: req.Username,
		},
		Updated: now,
		Deleted: gocloak.BoolP(true),
	}
	err = s.userTbl.Update(ctx, uEntry.Key, uEntry)
	if err != nil {
		if !errors.IsAlreadyExists(err) {
			return nil, status.Errorf(codes.InvalidArgument, "failed to create user: %s", err.Error())
		}
	}

	return &api.TenantUserDeleteResp{}, nil
}

func (s *TenantUserApiServer) sessionsToApi(session *gocloak.UserSessionRepresentation) *api.TenantUserSessionInfo {
	if session == nil {
		return nil
	}

	username := ""
	if session.Username != nil {
		username = *session.Username
	}

	sessionId := ""
	if session.ID != nil {
		sessionId = *session.ID
	}

	startTime := int64(0)
	if session.Start != nil {
		startTime = *session.Start
	}

	lastAccess := int64(0)
	if session.LastAccess != nil {
		lastAccess = *session.LastAccess
	}

	ipAddress := ""
	if session.IPAddress != nil {
		ipAddress = *session.IPAddress
	}

	return &api.TenantUserSessionInfo{
		Username:   username,
		SessionId:  sessionId,
		Started:    startTime,
		LastAccess: lastAccess,
		Ip:         ipAddress,
	}
}
func (s *TenantUserApiServer) ListUserSessions(ctx context.Context, req *api.TenantUserSessionsListReq) (*api.TenantUserSessionsListResp, error) {
	_, err := s.getTenant(ctx, req.Tenant)
	if err != nil {
		return nil, err
	}

	resp := &api.TenantUserSessionsListResp{}

	token, _ := s.client.GetAccessToken()
	var sessions []*gocloak.UserSessionRepresentation
	if req.Username != "" {
		params := gocloak.GetUsersParams{
			Username: gocloak.StringP(req.Username),
		}
		users, err := s.client.GetUsers(ctx, token, req.Tenant, params)
		if err != nil || len(users) == 0 {
			log.Printf("failed to fetch users: %v, got error: %s", req, err)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}
		// validate case-insensitive match for username
		if *users[0].Username != strings.ToLower(req.Username) {
			log.Printf("failed to find user: %v", req)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}
		sessions, err = s.client.GetUserSessions(ctx, token, req.Tenant, *users[0].ID)
		if err != nil {
			log.Printf("failed to get sessions: %v, got error: %s", req, err)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}
		resp.Count = int32(len(sessions))
	} else {
		clientsParams := gocloak.GetClientsParams{
			ClientID: gocloak.StringP("controller"),
		}
		clients, err := s.client.GetClients(ctx, token, req.Tenant, clientsParams)
		if err != nil {
			log.Printf("failed to clients for: %v, got error: %s", req, err)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}

		clientID := *clients[0].ID
		count, err := s.client.GetClientUserSessionsCount(ctx, token, req.Tenant, clientID)
		if err != nil {
			log.Printf("failed to fetch user session count for %v, got error: %s", req, err)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}

		params := gocloak.GetClientUserSessionsParams{
			First: gocloak.IntP(int(req.Offset)),
			Max:   gocloak.IntP(int(req.Limit)),
		}

		if req.Limit == 0 {
			// if limit is not specified mark max equal to the total count available
			params.Max = gocloak.IntP(count)
		}

		sessions, err = s.client.GetClientUserSessions(ctx, token, req.Tenant, clientID, params)
		if err != nil {
			log.Printf("failed to fetch user sessions for %v, got error: %s", req, err)
			return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
		}

		resp.Count = int32(count)
	}

	for _, session := range sessions {
		if session != nil {
			resp.Items = append(resp.Items, s.sessionsToApi(session))
		}
	}

	return resp, nil
}

func (s *TenantUserApiServer) LogoutUserSession(ctx context.Context, req *api.TenantUserSessionLogoutReq) (*api.TenantUserSessionLogoutResp, error) {
	params := gocloak.GetUsersParams{
		Username: gocloak.StringP(req.Username),
	}
	token, _ := s.client.GetAccessToken()
	users, err := s.client.GetUsers(ctx, token, req.Tenant, params)
	if err != nil || len(users) == 0 {
		log.Printf("failed to fetch users: %v, got error: %s", req, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	// validate exact match for username
	if *users[0].Username != req.Username {
		log.Printf("failed to find user: %v, got error: %s", req, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	if req.SessionId == "" {
		err = s.client.LogoutAllSessions(ctx, token, req.Tenant, *users[0].ID)
		if err != nil {
			log.Printf("failed to close all sessions of user: %s, got error: %s", req.Username, err)
			return nil, status.Errorf(codes.Internal, "failed to logout user sessions %s", err.Error())
		}
	} else {
		err = s.client.LogoutUserSession(ctx, token, req.Tenant, req.SessionId)
		if err != nil {
			log.Printf("failed to close specified session of user: %v, got error %s", req, err)
			return nil, status.Errorf(codes.Internal, "failed to logout user session %s", err.Error())
		}
	}

	return &api.TenantUserSessionLogoutResp{}, nil
}

func (s *TenantUserApiServer) ListTenantOrgUnitsWithRoles(ctx context.Context, req *api.TenantOrgUnitsWithRolesListReq) (*api.TenantOrgUnitsWithRolesListResp, error) {
	log.Printf("received ListTenantOrgUnitsWithRoles request for user %s in tenant %s: %v", req.Username, req.Tenant, req)

	// Validate tenant exists
	tenantKey := &table.TenantKey{
		Name: req.Tenant,
	}
	_, err := s.tenantTbl.Find(ctx, tenantKey)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Tenant %s not found", req.Tenant)
		}
		log.Printf("error getting tenant %s: %s", req.Tenant, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	// Validate user exists in the tenant
	userKey := &table.UserKey{
		Tenant:   req.Tenant,
		Username: req.Username,
	}
	_, err = s.userTbl.Find(ctx, userKey)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "User %s not found in tenant %s", req.Username, req.Tenant)
		}
		log.Printf("error getting user %s in tenant %s: %s", req.Username, req.Tenant, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	// Get org units where the specified user has roles
	orgUnitUsers, err := s.orgUnitUserTbl.GetByUser(ctx, req.Tenant, req.Username)
	if err != nil {
		log.Printf("error getting org units for user %s in tenant %s: %s", req.Username, req.Tenant, err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}

	// Apply pagination
	totalCount := len(orgUnitUsers)
	startIdx := int(req.Offset)
	endIdx := startIdx + int(req.Limit)
	if req.Limit == 0 || endIdx > totalCount {
		endIdx = totalCount
	}
	if startIdx > totalCount {
		startIdx = totalCount
	}

	resp := &api.TenantOrgUnitsWithRolesListResp{
		Count: int32(totalCount),
		Items: []*api.TenantOrgUnitWithRoles{},
	}

	// Process each org unit user entry
	for _, ouUser := range orgUnitUsers[startIdx:endIdx] {
		// Get org unit details
		orgUnitKey := &table.OrgUnitKey{
			ID: ouUser.Key.OrgUnitId,
		}
		orgUnitEntry, err := s.orgUnitTbl.Find(ctx, orgUnitKey)
		if err != nil {
			log.Printf("error getting org unit details for %s: %s", ouUser.Key.OrgUnitId, err)
			continue // Skip this org unit but continue with others
		}

		// Get user details
		userKey := &table.UserKey{
			Tenant:   req.Tenant,
			Username: req.Username,
		}
		userEntry, err := s.userTbl.Find(ctx, userKey)
		if err != nil {
			log.Printf("error getting user details for %s: %s", req.Username, err)
			continue // Skip this entry but continue with others
		}

		// Get role description (check if it's a custom role)
		roleDesc := ouUser.Role // Default to role name
		customRoleKey := &table.OrgUnitCustomRoleKey{
			Tenant:    req.Tenant,
			OrgUnitId: ouUser.Key.OrgUnitId,
			Name:      ouUser.Role,
		}
		customRole, err := s.orgUnitRoleTbl.Find(ctx, customRoleKey)
		if err == nil && customRole != nil {
			roleDesc = customRole.Description
			if roleDesc == "" {
				roleDesc = customRole.DisplayName
			}
		}

		orgUnitWithRoles := &api.TenantOrgUnitWithRoles{
			OrgUnitId:   orgUnitEntry.Key.ID,
			OrgUnitName: orgUnitEntry.Name,
			OrgUnitDesc: orgUnitEntry.Desc,
			UserRoles: []*api.UserRoleEntry{
				{
					UserId:    req.Username,
					Username:  req.Username,
					FirstName: userEntry.Info.FirstName,
					LastName:  userEntry.Info.LastName,
					RoleName:  ouUser.Role,
					RoleDesc:  roleDesc,
				},
			},
		}

		resp.Items = append(resp.Items, orgUnitWithRoles)
	}

	return resp, nil
}

func NewTenantUserServer(ctx *model.GrpcServerContext, client *keycloak.Client, ep string) *TenantUserApiServer {
	tbl, err := table.GetTenantTable()
	if err != nil {
		log.Panicf("failed to get tenant table: %s", err)
	}
	uTbl, err := table.GetUserTable()
	if err != nil {
		log.Panicf("failed to get user table: %s", err)
	}
	orgUnitTbl, err := table.GetOrgUnitTable()
	if err != nil {
		log.Panicf("failed to get org unit table: %s", err)
	}
	orgUnitUserTbl, err := table.GetOrgUnitUserTable()
	if err != nil {
		log.Panicf("failed to get org unit user table: %s", err)
	}
	orgUnitRoleTbl, err := table.GetOrgUnitCustomRoleTable()
	if err != nil {
		log.Panicf("failed to get org unit custom role table: %s", err)
	}
	srv := &TenantUserApiServer{
		tenantTbl:      tbl,
		userTbl:        uTbl,
		orgUnitTbl:     orgUnitTbl,
		orgUnitUserTbl: orgUnitUserTbl,
		orgUnitRoleTbl: orgUnitRoleTbl,
		client:         client,
	}
	api.RegisterTenantUserServer(ctx.Server, srv)
	err = api.RegisterTenantUserHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	routeTbl, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("failed to get route table: %s", err)
	}
	for _, r := range api.RoutesTenantUser {
		key := &route.Key{
			Url:    r.Url,
			Method: r.Method,
		}
		entry := &route.Route{
			Key:      key,
			Endpoint: ep,
			Resource: r.Resource,
			Verb:     r.Verb,
			IsRoot:   utils.BoolP(true), // these routes are only meant for root tenancy
		}
		if err := routeTbl.Locate(context.Background(), key, entry); err != nil {
			log.Panicf("failed to register route %d %s: %s", r.Method, r.Url, err)
		}
	}
	return srv
}
