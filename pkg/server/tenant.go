// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	auth "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/utils"

	"github.com/go-core-stack/auth-gateway/api"
	"github.com/go-core-stack/auth-gateway/pkg/model"
	"github.com/go-core-stack/auth-gateway/pkg/table"
)

type TenantServer struct {
	api.UnimplementedTenantServer
	tenantTbl *table.TenantTable
}

func (s *TenantServer) CreateTenant(ctx context.Context, req *api.TenantCreateReq) (*api.TenantCreateResp, error) {
	log.Printf("Got Tenant Create Req: %v", req)
	return &api.TenantCreateResp{}, nil
}

func (s *TenantServer) GetTenant(ctx context.Context, req *api.TenantGetReq) (*api.TenantGetResp, error) {
	log.Printf("received Tenant get req: %v", req)
	key := &table.TenantKey{
		Name: req.Id,
	}
	entry, err := s.tenantTbl.Find(ctx, key)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Tenant %s not found", req.Id)
		}
		log.Printf("got error while getting tenant entry: %s, err: %s", req.Id, err)
	}

	resp := &api.TenantGetResp{
		Id:       req.Id,
		DispName: entry.Config.DispName,
		Desc:     entry.Config.Desc,
		Admin:    entry.Config.DefaultAdmin.UserID,
	}
	return resp, nil
}

func (s *TenantServer) ListTenants(ctx context.Context, req *api.TenantsListReq) (*api.TenantsListResp, error) {
	log.Printf("received list tenant request: %v", req)
	count, err := s.tenantTbl.Count(ctx, nil)
	if err != nil {
		log.Printf("got error while fetching count of tenants: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	list, err := s.tenantTbl.FindMany(ctx, nil, req.Offset, req.Limit)
	if err != nil {
		log.Printf("got error while fetching list of tenants: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, Please try again later")
	}
	resp := &api.TenantsListResp{
		Count: int32(count),
	}

	for _, entry := range list {
		item := &api.TenantListEntry{
			Id:       "root",
			DispName: entry.Config.DispName,
			Desc:     entry.Config.Desc,
		}
		resp.Items = append(resp.Items, item)
	}

	return resp, nil
}

// Helper function to validate tenant admin permissions
func (s *TenantServer) validateTenantAdmin(ctx context.Context) (*auth.AuthInfo, error) {
	authInfo, err := auth.GetAuthInfoFromContext(ctx)
	if err != nil || authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Check if user has admin role (tenant admin)
	isAdmin := false
	for _, role := range authInfo.Roles {
		if role == "admin" {
			isAdmin = true
			break
		}
	}

	if !isAdmin {
		return nil, status.Errorf(codes.PermissionDenied, "Access denied: tenant admin role required")
	}

	return authInfo, nil
}

func NewTenantServer(ctx *model.GrpcServerContext, ep string) *TenantServer {
	tbl, err := table.GetTenantTable()
	if err != nil {
		log.Panicf("failed to get tenant table: %s", err)
	}
	srv := &TenantServer{
		tenantTbl: tbl,
	}
	api.RegisterTenantServer(ctx.Server, srv)
	err = api.RegisterTenantHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	routeTbl, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("failed to get route table: %s", err)
	}
	for _, r := range api.RoutesTenant {
		key := &route.Key{
			Url:    r.Url,
			Method: r.Method,
		}
		entry := &route.Route{
			Key:      key,
			Endpoint: ep,
			Resource: r.Resource,
			Verb:     r.Verb,
			IsRoot:   utils.BoolP(true),
		}
		if err := routeTbl.Locate(context.Background(), key, entry); err != nil {
			log.Panicf("failed to register route %d %s: %s", r.Method, r.Url, err)
		}
	}
	return srv
}
