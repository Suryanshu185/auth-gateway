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
	filter := bson.M{
		"key.tenant":    tenant,               // Filter by tenant
		"key.orgUnitId": orgUnitId,            // Filter by organization unit
		"key.name":      roleName,             // Filter by role name
		"active":        bson.M{"$ne": false}, // Include only active roles (true or nil)
	}

	// Use FindMany with limit 1 to get a single active role
	results, err := t.FindMany(ctx, filter, 0, 1)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, errors.Wrapf(errors.NotFound, "custom role not found")
	}

	return results[0], nil
}

// SoftDelete marks a custom role as inactive instead of physically deleting it
func (t *OrgUnitCustomRoleTable) SoftDelete(ctx context.Context, key *OrgUnitCustomRoleKey, deletedBy string) error {
	update := &OrgUnitCustomRole{
		Active:    &[]bool{false}[0], // Mark as inactive
		UpdatedBy: deletedBy,         // Track who performed the deletion
		Updated:   time.Now().Unix(), // Update timestamp
	}

	return t.Update(ctx, key, update)
}

// HasBindings checks if a custom role has any users assigned to it
func (t *OrgUnitCustomRoleTable) HasBindings(ctx context.Context, tenant, orgUnitId, roleName string) (bool, error) {
	// Get the org unit user table to check for role assignments
	orgUnitUserTable, err := GetOrgUnitUserTable()
	if err != nil {
		return false, err
	}

	// Check if any users are assigned this custom role
	filter := bson.M{
		"key.tenant":    tenant,
		"key.orgUnitId": orgUnitId,
		"role":          roleName,
	}

	count, err := orgUnitUserTable.col.Count(ctx, filter)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// PermanentDelete permanently removes a custom role from the database
func (t *OrgUnitCustomRoleTable) PermanentDelete(ctx context.Context, key *OrgUnitCustomRoleKey) error {
	return t.DeleteKey(ctx, key)
}

// DeleteCustomRoleWithBindingCheck performs intelligent deletion based on binding status
func (t *OrgUnitCustomRoleTable) DeleteCustomRoleWithBindingCheck(ctx context.Context, key *OrgUnitCustomRoleKey, deletedBy string) error {
	// Check if the role has any bindings
	hasBindings, err := t.HasBindings(ctx, key.Tenant, key.OrgUnitId, key.Name)
	if err != nil {
		return err
	}

	if hasBindings {
		// Role has bindings - perform soft delete only
		return t.SoftDelete(ctx, key, deletedBy)
	} else {
		// No bindings - permanently delete the role
		return t.PermanentDelete(ctx, key)
	}
}

// FindAnyByNameAndOrgUnit finds a custom role by name (including soft-deleted ones)
// This is used to check for name conflicts including soft-deleted roles with bindings
func (t *OrgUnitCustomRoleTable) FindAnyByNameAndOrgUnit(ctx context.Context, tenant, orgUnitId, roleName string) (*OrgUnitCustomRole, error) {
	filter := bson.M{
		"key.tenant":    tenant,    // Filter by tenant
		"key.orgUnitId": orgUnitId, // Filter by organization unit
		"key.name":      roleName,  // Filter by role name
		// No active filter - find both active and inactive roles
	}

	// Use FindMany with limit 1 to get any role (active or inactive)
	results, err := t.FindMany(ctx, filter, 0, 1)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, errors.Wrapf(errors.NotFound, "custom role not found")
	}

	return results[0], nil
}

// CleanupOrphanedSoftDeletedRoles removes soft-deleted roles that no longer have bindings
func (t *OrgUnitCustomRoleTable) CleanupOrphanedSoftDeletedRoles(ctx context.Context, tenant, orgUnitId string) error {
	// Find all soft-deleted roles
	filter := bson.M{
		"key.tenant":    tenant,
		"key.orgUnitId": orgUnitId,
		"active":        false, // Only soft-deleted roles
	}

	softDeletedRoles, err := t.FindMany(ctx, filter, 0, 0) // Get all
	if err != nil {
		return err
	}

	// Check each soft-deleted role for bindings
	for _, role := range softDeletedRoles {
		hasBindings, err := t.HasBindings(ctx, tenant, orgUnitId, role.Key.Name)
		if err != nil {
			continue // Skip on error, don't fail the entire cleanup
		}

		// If no bindings, permanently delete
		if !hasBindings {
			err = t.PermanentDelete(ctx, role.Key)
			if err != nil {
				// Log error but continue with other roles
				continue
			}
		}
	}

	return nil
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
