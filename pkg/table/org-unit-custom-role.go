// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package table

import (
	"context"
	"time"

	"github.com/go-core-stack/core/db"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/table"
	"go.mongodb.org/mongo-driver/bson"
)

var orgUnitCustomRoleTable *OrgUnitCustomRoleTable

// OrgUnitCustomRoleKey defines the key structure for custom roles
type OrgUnitCustomRoleKey struct {
	// Tenant name this custom role belongs to
	Tenant string `bson:"tenant,omitempty"`
	// Org unit ID this custom role is scoped to
	OrgUnitId string `bson:"orgUnitId,omitempty"`
	// Role name, unique within the org unit
	Name string `bson:"name,omitempty"`
}

// RolePermission defines individual permission for a resource
type RolePermission struct {
	// Resource name the permission applies to
	Resource string `bson:"resource,omitempty"`
	// List of allowed verbs/actions for this resource
	Verbs []string `bson:"verbs,omitempty"`
}

// OrgUnitCustomRole defines a custom role within an organization unit
type OrgUnitCustomRole struct {
	// Custom role key
	Key *OrgUnitCustomRoleKey `bson:"key,omitempty"`
	// Display name for the custom role
	DisplayName string `bson:"displayName,omitempty"`
	// Description explaining the purpose of this custom role
	Description string `bson:"description,omitempty"`
	// List of permissions granted by this custom role
	Permissions []*RolePermission `bson:"permissions,omitempty"`
	// Created timestamp
	Created int64 `bson:"created,omitempty"`
	// User who created this custom role
	CreatedBy string `bson:"createdBy,omitempty"`
	// Last updated timestamp
	Updated int64 `bson:"updated,omitempty"`
	// User who last updated this custom role
	UpdatedBy string `bson:"updatedBy,omitempty"`
	// Whether this custom role is currently active
	Active *bool `bson:"active,omitempty"`
}

// OrgUnitCustomRoleTable manages custom roles for organization units
type OrgUnitCustomRoleTable struct {
	table.Table[OrgUnitCustomRoleKey, OrgUnitCustomRole]
	col db.StoreCollection
}

// GetByOrgUnit retrieves all custom roles for a specific organization unit
func (t *OrgUnitCustomRoleTable) GetByOrgUnit(ctx context.Context, tenant, orgUnitId string, offset, limit int32) ([]*OrgUnitCustomRole, error) {
	filter := bson.M{
		"key.tenant":    tenant,
		"key.orgUnitId": orgUnitId,
		"active":        bson.M{"$ne": false}, // Include roles where active is true or nil
	}

	list, err := t.FindMany(ctx, filter, offset, limit)
	if err != nil {
		return nil, err
	}

	return list, nil
}

// CountByOrgUnit counts active custom roles for a specific organization unit
func (t *OrgUnitCustomRoleTable) CountByOrgUnit(ctx context.Context, tenant, orgUnitId string) (int32, error) {
	filter := bson.M{
		"key.tenant":    tenant,
		"key.orgUnitId": orgUnitId,
		"active":        bson.M{"$ne": false}, // Include roles where active is true or nil
	}
	count, err := t.col.Count(ctx, filter)
	return int32(count), err
}

// GetByTenant retrieves all custom roles for a tenant across all org units
func (t *OrgUnitCustomRoleTable) GetByTenant(ctx context.Context, tenant string, offset, limit int32) ([]*OrgUnitCustomRole, error) {
	filter := bson.M{
		"key.tenant": tenant,
		"active":     bson.M{"$ne": false}, // Include roles where active is true or nil
	}

	list, err := t.FindMany(ctx, filter, offset, limit)
	if err != nil {
		return nil, err
	}

	return list, nil
}

// FindByNameAndOrgUnit finds a specific custom role by name within an org unit
func (t *OrgUnitCustomRoleTable) FindByNameAndOrgUnit(ctx context.Context, tenant, orgUnitId, roleName string) (*OrgUnitCustomRole, error) {
	key := &OrgUnitCustomRoleKey{
		Tenant:    tenant,
		OrgUnitId: orgUnitId,
		Name:      roleName,
	}

	return t.Find(ctx, key)
}

// SoftDelete marks a custom role as inactive instead of physically deleting it
func (t *OrgUnitCustomRoleTable) SoftDelete(ctx context.Context, key *OrgUnitCustomRoleKey, deletedBy string) error {
	update := &OrgUnitCustomRole{
		Active:    boolPtr(false),   // Mark as inactive
		UpdatedBy: deletedBy,        // Track who performed the deletion
		Updated:   getCurrentTime(), // Update timestamp
	}

	return t.Update(ctx, key, update)
}

// GetOrgUnitCustomRoleTable returns the global custom role table instance
func GetOrgUnitCustomRoleTable() (*OrgUnitCustomRoleTable, error) {
	if orgUnitCustomRoleTable != nil {
		return orgUnitCustomRoleTable, nil
	}

	return nil, errors.Wrapf(errors.NotFound, "org unit custom role table not found")
}

// LocateOrgUnitCustomRoleTable initializes and returns the custom role table
func LocateOrgUnitCustomRoleTable(client db.StoreClient) (*OrgUnitCustomRoleTable, error) {
	if orgUnitCustomRoleTable != nil {
		return orgUnitCustomRoleTable, nil
	}

	col := client.GetCollection(AuthDatabaseName, OrgUnitCustomRoleCollectionName)
	tbl := &OrgUnitCustomRoleTable{
		col: col,
	}

	err := tbl.Initialize(col)
	if err != nil {
		return nil, err
	}

	orgUnitCustomRoleTable = tbl

	return orgUnitCustomRoleTable, nil
}

// Helper function to create boolean pointer
func boolPtr(b bool) *bool {
	return &b
}

// Helper function to get current timestamp
func getCurrentTime() int64 {
	return time.Now().Unix() // Get current Unix timestamp
}
