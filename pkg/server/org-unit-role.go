// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package server

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	auth "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/errors"

	"github.com/go-core-stack/auth-gateway/api"
	"github.com/go-core-stack/auth-gateway/pkg/model"
	"github.com/go-core-stack/auth-gateway/pkg/table"
)

type OrgUnitRoleServer struct {
	api.UnimplementedOrgUnitRoleServer
	customRoleTable *table.OrgUnitCustomRoleTable // Table for managing custom roles
}

func (s *OrgUnitRoleServer) ListOrgUnitRoles(ctx context.Context, req *api.OrgUnitRolesListReq) (*api.OrgUnitRolesListResp, error) {
	log.Printf("received list request for org unit roles: %v", req)
	resp := &api.OrgUnitRolesListResp{
		Items: []*api.OrgUnitRolesListEntry{
			{
				Name: "default",
				Desc: "Standard user role to provide access to all the resources available in the Organization Unit",
			},
			{
				Name: "admin",
				Desc: "Administrator role to provide access to everything in the Organization Unit including management of users and resources",
			},
			{
				Name: "auditor",
				Desc: "Auditor role to provider read-only access to all the resources available in the Organization Unit",
			},
		},
	}
	return resp, nil
}

// CreateCustomRole creates a new custom role for the organization unit
func (s *OrgUnitRoleServer) CreateCustomRole(ctx context.Context, req *api.CreateCustomRoleReq) (*api.CreateCustomRoleResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Validate that role name is not one of the system reserved names
	if req.Name == "admin" || req.Name == "default" || req.Name == "auditor" {
		return nil, status.Errorf(codes.InvalidArgument, "Role name '%s' is reserved and cannot be used for custom roles", req.Name)
	}

	// Convert protobuf permissions to table permissions
	var permissions []*table.RolePermission
	for _, perm := range req.Permissions {
		permissions = append(permissions, &table.RolePermission{
			Resource: perm.Resource, // Resource name from the permission
			Verbs:    perm.Verbs,    // Action verbs allowed for this resource
		})
	}

	// Create the custom role entry
	customRole := &table.OrgUnitCustomRole{
		Key: &table.OrgUnitCustomRoleKey{
			Tenant:    authInfo.Realm, // Current user's tenant
			OrgUnitId: req.Ou,         // Organization unit ID from request
			Name:      req.Name,       // Custom role name
		},
		DisplayName: req.DisplayName,   // Human-readable name for the role
		Description: req.Description,   // Detailed description of role purpose
		Permissions: permissions,       // List of permissions granted by this role
		Created:     time.Now().Unix(), // Timestamp when role was created
		CreatedBy:   authInfo.UserName, // User who created this role
		Active:      getBoolPtr(true),  // Mark role as active
	}

	// Insert the custom role into the database
	err := s.customRoleTable.Insert(ctx, customRole.Key, customRole)
	if err != nil {
		if errors.IsAlreadyExists(err) {
			// Check if there's a soft-deleted role with the same name
			deletedRole, checkErr := s.customRoleTable.FindInactiveByNameAndOrgUnit(ctx, authInfo.Realm, req.Ou, req.Name)
			if checkErr == nil && deletedRole != nil {
				return nil, status.Errorf(codes.AlreadyExists, "Custom role '%s' was previously deleted. Please restore it instead of creating a new one", req.Name)
			}
			return nil, status.Errorf(codes.AlreadyExists, "Custom role '%s' already exists in organization unit", req.Name)
		}
		log.Printf("failed to create custom role: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	return &api.CreateCustomRoleResp{
		Message: "Custom role created successfully", // Success confirmation message
	}, nil
}

// UpdateCustomRole updates an existing custom role
func (s *OrgUnitRoleServer) UpdateCustomRole(ctx context.Context, req *api.UpdateCustomRoleReq) (*api.UpdateCustomRoleResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Convert protobuf permissions to table permissions
	var permissions []*table.RolePermission
	for _, perm := range req.Permissions {
		permissions = append(permissions, &table.RolePermission{
			Resource: perm.Resource, // Resource name from the permission
			Verbs:    perm.Verbs,    // Action verbs allowed for this resource
		})
	}

	// Create the update entry
	updateRole := &table.OrgUnitCustomRole{
		DisplayName: req.DisplayName,   // Updated human-readable name
		Description: req.Description,   // Updated description
		Permissions: permissions,       // Updated list of permissions
		Updated:     time.Now().Unix(), // Timestamp when role was updated
		UpdatedBy:   authInfo.UserName, // User who updated this role
	}

	// Create the key for finding the role to update
	key := &table.OrgUnitCustomRoleKey{
		Tenant:    authInfo.Realm, // Current user's tenant
		OrgUnitId: req.Ou,         // Organization unit ID from request
		Name:      req.RoleName,   // Role name to update
	}

	// Update the custom role in the database
	err := s.customRoleTable.Update(ctx, key, updateRole)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Custom role '%s' not found in organization unit", req.RoleName)
		}
		log.Printf("failed to update custom role: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	return &api.UpdateCustomRoleResp{
		Message: "Custom role updated successfully", // Success confirmation message
	}, nil
}

// GetCustomRole retrieves details of a specific custom role
func (s *OrgUnitRoleServer) GetCustomRole(ctx context.Context, req *api.GetCustomRoleReq) (*api.GetCustomRoleResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Find the custom role by name and org unit
	customRole, err := s.customRoleTable.FindByNameAndOrgUnit(ctx, authInfo.Realm, req.Ou, req.RoleName)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Custom role '%s' not found in organization unit", req.RoleName)
		}
		log.Printf("failed to get custom role: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	// Convert table permissions to protobuf permissions
	var permissions []*api.RolePermission
	for _, perm := range customRole.Permissions {
		permissions = append(permissions, &api.RolePermission{
			Resource: perm.Resource, // Resource name from database
			Verbs:    perm.Verbs,    // Action verbs from database
		})
	}

	return &api.GetCustomRoleResp{
		Name:        customRole.Key.Name,    // Role name
		DisplayName: customRole.DisplayName, // Human-readable name
		Description: customRole.Description, // Role description
		Permissions: permissions,            // List of permissions
		Created:     customRole.Created,     // Creation timestamp
		CreatedBy:   customRole.CreatedBy,   // Creator username
		Updated:     customRole.Updated,     // Last update timestamp
		UpdatedBy:   customRole.UpdatedBy,   // Last updater username
	}, nil
}

// DeleteCustomRole soft-deletes a custom role from the organization unit
func (s *OrgUnitRoleServer) DeleteCustomRole(ctx context.Context, req *api.DeleteCustomRoleReq) (*api.DeleteCustomRoleResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Create the key for finding the role to delete
	key := &table.OrgUnitCustomRoleKey{
		Tenant:    authInfo.Realm, // Current user's tenant
		OrgUnitId: req.Ou,         // Organization unit ID from request
		Name:      req.RoleName,   // Role name to delete
	}

	// Perform soft delete (mark as inactive)
	err := s.customRoleTable.SoftDelete(ctx, key, authInfo.UserName)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Custom role '%s' not found in organization unit", req.RoleName)
		}
		log.Printf("failed to delete custom role: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	return &api.DeleteCustomRoleResp{
		Message: "Custom role deleted successfully", // Success confirmation message
	}, nil
}

// RestoreCustomRole restores a previously soft-deleted custom role
func (s *OrgUnitRoleServer) RestoreCustomRole(ctx context.Context, req *api.RestoreCustomRoleReq) (*api.RestoreCustomRoleResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Create the key for finding the role to restore
	key := &table.OrgUnitCustomRoleKey{
		Tenant:    authInfo.Realm, // Current user's tenant
		OrgUnitId: req.Ou,         // Organization unit ID from request
		Name:      req.RoleName,   // Role name to restore
	}

	// Perform restore operation (mark as active)
	err := s.customRoleTable.RestoreRole(ctx, key, authInfo.UserName)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "Deleted custom role '%s' not found in organization unit", req.RoleName)
		}
		log.Printf("failed to restore custom role: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	return &api.RestoreCustomRoleResp{
		Message: "Custom role restored successfully", // Success confirmation message
	}, nil
}

// ListCustomRoles retrieves all custom roles for the organization unit
func (s *OrgUnitRoleServer) ListCustomRoles(ctx context.Context, req *api.ListCustomRolesReq) (*api.ListCustomRolesResp, error) {
	authInfo, _ := auth.GetAuthInfoFromContext(ctx)
	if authInfo == nil {
		return nil, status.Errorf(codes.Unauthenticated, "User not authenticated")
	}

	// Get count of custom roles for pagination
	count, err := s.customRoleTable.CountByOrgUnit(ctx, authInfo.Realm, req.Ou)
	if err != nil {
		log.Printf("failed to count custom roles: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	// Get list of custom roles with pagination
	customRoles, err := s.customRoleTable.GetByOrgUnit(ctx, authInfo.Realm, req.Ou, req.Offset, req.Limit)
	if err != nil {
		log.Printf("failed to list custom roles: %s", err)
		return nil, status.Errorf(codes.Internal, "Something went wrong, please try again later")
	}

	// Convert to response format
	var items []*api.CustomRoleListEntry
	for _, role := range customRoles {
		items = append(items, &api.CustomRoleListEntry{
			Name:            role.Key.Name,                // Role name
			DisplayName:     role.DisplayName,             // Human-readable name
			Description:     role.Description,             // Role description
			PermissionCount: int32(len(role.Permissions)), // Number of permissions
			Created:         role.Created,                 // Creation timestamp
			CreatedBy:       role.CreatedBy,               // Creator username
		})
	}

	return &api.ListCustomRolesResp{
		Count: count, // Total count for pagination
		Items: items, // List of custom role entries
	}, nil
}

func NewOrgUnitRoleServer(ctx *model.GrpcServerContext, ep string) *OrgUnitRoleServer {
	// Get the custom role table for managing org unit custom roles
	customRoleTable, err := table.GetOrgUnitCustomRoleTable()
	if err != nil {
		log.Panicf("failed to get org unit custom role table: %s", err)
	}

	srv := &OrgUnitRoleServer{
		customRoleTable: customRoleTable, // Initialize custom role table
	}
	api.RegisterOrgUnitRoleServer(ctx.Server, srv)
	err = api.RegisterOrgUnitRoleHandler(context.Background(), ctx.Mux, ctx.Conn)
	if err != nil {
		log.Panicf("failed to register handler: %s", err)
	}
	routeTbl, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("failed to get route table: %s", err)
	}
	for _, r := range api.RoutesOrgUnitRole {
		key := &route.Key{
			Url:    r.Url,
			Method: r.Method,
		}
		entry := &route.Route{
			Key:      key,
			Endpoint: ep,
			Resource: r.Resource,
			Scopes:   r.Scopes,
			Verb:     r.Verb,
		}
		if err := routeTbl.Locate(context.Background(), key, entry); err != nil {
			log.Panicf("failed to register route %d %s: %s", r.Method, r.Url, err)
		}
	}
	return srv
}

// Helper function to create boolean pointer
func getBoolPtr(b bool) *bool {
	return &b // Return pointer to boolean value
}
