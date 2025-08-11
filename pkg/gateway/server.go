// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"slices"
	"sync"
	"time"

	common "github.com/go-core-stack/auth/context"
	"github.com/go-core-stack/auth/hash"
	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/reconciler"
	"github.com/go-core-stack/core/utils"
	"golang.org/x/net/http2"

	"github.com/go-core-stack/auth-gateway/pkg/auth"
	"github.com/go-core-stack/auth-gateway/pkg/table"
)

type gwContextKey string

const (
	authKey gwContextKey = "auth"
	ouKey   gwContextKey = "ou"
)

type gateway struct {
	http.Handler
	validator       hash.Validator
	apiKeys         *table.ApiKeyTable
	userTbl         *table.UserTable
	routes          *route.RouteTable
	ouTbl           *table.OrgUnitTable
	ouUserTbl       *table.OrgUnitUserTable
	ouCustomRoleTbl *table.OrgUnitCustomRoleTable // Table for managing custom roles
	proxyV1         *httputil.ReverseProxy
	proxyV2         *httputil.ReverseProxy
}

type gatewayReconciler struct {
	reconciler.Controller
	mu sync.Mutex
	gw *gateway
}

func (r *gatewayReconciler) Reconcile(k any) (*reconciler.Result, error) {
	ok := r.mu.TryLock()
	if !ok {
		return &reconciler.Result{}, nil
	}
	go func() {
		time.Sleep(10 * time.Second)
		r.mu.Unlock()
		populateRoutes(r.gw.routes)
	}()
	return &reconciler.Result{}, nil
}

func (s *gateway) AuthenticateRequest(r *http.Request) (*common.AuthInfo, error) {
	var authInfo *common.AuthInfo
	var user *table.UserEntry
	var err error
	now := time.Now().Unix()
	keyId := s.validator.GetKeyId(r)
	// check if an API key is used
	if keyId != "" {
		key := &table.ApiKeyId{
			Id: keyId,
		}
		entry, err := s.apiKeys.Find(r.Context(), key)
		if err != nil {
			if errors.IsNotFound(err) {
				return nil, errors.Wrapf(errors.Unauthorized, "Invalid Api Key")
			}
			return nil, errors.Wrapf(errors.Unauthorized, "Failed to perform auth at the moment")
		}
		if entry.UserInfo == nil {
			return nil, errors.Wrapf(errors.Unauthorized, "user not available")
		}
		if entry.Config.ExpireAt != 0 && entry.Config.ExpireAt < now {
			return nil, errors.Wrapf(errors.Unauthorized, "Api Key is %s expired", keyId)
		}
		_, err = s.validator.Validate(r, entry.Secret.Value)
		if err != nil {
			return nil, errors.Wrapf(errors.Unauthorized, "Invalid Signature")
		}

		uKey := &table.UserKey{
			Tenant:   entry.UserInfo.Tenant,
			Username: entry.UserInfo.Username,
		}
		user, err = s.userTbl.Find(r.Context(), uKey)
		if err != nil {
			if errors.IsNotFound(err) {
				return nil, errors.Wrapf(errors.Unauthorized, "User %s not found in tenant %s", entry.UserInfo.Username, entry.UserInfo.Tenant)
			}
			log.Printf("Failed to find user %s in tenant %s: %s", entry.UserInfo.Username, entry.UserInfo.Tenant, err)
			return nil, errors.Wrapf(errors.Unknown, "Something went wrong while processing request: %s", err)
		}

		authInfo = &common.AuthInfo{
			Realm:     user.Key.Tenant,
			UserName:  user.Key.Username,
			Email:     user.Info.Email,
			FirstName: user.Info.FirstName,
			LastName:  user.Info.LastName,
			FullName:  user.Info.FirstName + " " + user.Info.LastName,
		}

		// trigger an update to lastUsed timestamp for ApiKey
		if entry.LastUsed == 0 || (entry.LastUsed+60) <= now {
			update := &table.ApiKeyEntry{
				Key: table.ApiKeyId{
					Id: keyId,
				},
				LastUsed: now,
			}
			err = s.apiKeys.Update(r.Context(), &update.Key, update)
			if err != nil {
				log.Printf("Failed to update last access for user %s in tenant %s: %s", authInfo.UserName, authInfo.Realm, err)
			}
		}
	} else {
		var err error
		authInfo, err = auth.AuthenticateRequest(r, "")
		if err != nil {
			return nil, errors.Wrapf(errors.Unauthorized, "failed to authenticate incoming request: %s", err)
		}

		uKey := &table.UserKey{
			Tenant:   authInfo.Realm,
			Username: authInfo.UserName,
		}
		user, err = s.userTbl.Find(r.Context(), uKey)
		if err != nil {
			if !errors.IsNotFound(err) {
				log.Printf("Failed to find user %s in tenant %s: %s", authInfo.UserName, authInfo.Realm, err)
				return nil, errors.Wrapf(errors.Unknown, "Something went wrong while processing request: %s", err)
			}
			// locate a new user entry, to handle SSO created users
			update := &table.UserEntry{
				Key: &table.UserKey{
					Tenant:   authInfo.Realm,
					Username: authInfo.UserName,
				},
				Created: now,
				Updated: now,
				Info: &table.UserInfo{
					Email:     authInfo.Email,
					FirstName: authInfo.FirstName,
					LastName:  authInfo.LastName,
				},
			}
			err := s.userTbl.Locate(r.Context(), update.Key, update)
			if err != nil {
				log.Printf("Failed to locate user %s in tenant %s: %s", authInfo.UserName, authInfo.Realm, err)
				return nil, errors.Wrapf(errors.Unknown, "Something went wrong while processing request: %s", err)
			}
			user = update
		}

		// trigger an update to lastAccess timestamp
		if user.LastAccess == 0 || (user.LastAccess+60) <= now {
			update := &table.UserEntry{
				Key: &table.UserKey{
					Tenant:   authInfo.Realm,
					Username: authInfo.UserName,
				},
				LastAccess: now,
			}
			err = s.userTbl.Update(r.Context(), update.Key, update)
			if err != nil {
				log.Printf("Failed to update last access for user %s in tenant %s: %s", authInfo.UserName, authInfo.Realm, err)
			}
		}
	}

	if utils.PBool(user.Disabled) {
		return nil, errors.Wrapf(errors.Unauthorized, "User %s is disabled in tenant %s", authInfo.UserName, authInfo.Realm)
	}

	// Add Auth info for the backend server
	err = common.SetAuthInfoHeader(r, authInfo)
	if err != nil {
		return nil, errors.Wrapf(errors.Unauthorized, "Failed to process auth information: %s", err)
	}
	return authInfo, nil
}

// performOrgUnitRoleCheck checks if the Org unit role associated with the user
// allows the requested access, returns true if the role allows access
func (s *gateway) performOrgUnitRoleCheck(authInfo *common.AuthInfo, ou string, r *http.Request) bool {
	ouUserKey := &table.OrgUnitUserKey{
		Tenant:    authInfo.Realm,
		Username:  authInfo.UserName,
		OrgUnitId: ou,
	}
	ouUser, err := s.ouUserTbl.Find(r.Context(), ouUserKey)
	if err != nil {
		if !errors.IsNotFound(err) {
			log.Printf("failed to find org unit user %v, got error: %s", ouUserKey, err)
		}
		return false
	}

	// Check built-in system roles first
	switch ouUser.Role {
	case "admin":
		// wildcard access to the org unit
		return true
	case "auditor":
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			// allow read-only access for auditor role
			return true
		}
		return false
	case "default":
		// default role has basic access - implement based on requirements
		return true
	}

	// Check if it's a custom role
	customRole, err := s.ouCustomRoleTbl.FindByNameAndOrgUnit(r.Context(), authInfo.Realm, ou, ouUser.Role)
	if err != nil {
		if !errors.IsNotFound(err) {
			log.Printf("failed to find custom role %s for org unit %s: %s", ouUser.Role, ou, err)
		}
		// If custom role not found, deny access
		return false
	}

	// Check if the custom role allows the requested action
	return s.checkCustomRolePermissions(customRole, r)
}

// checkCustomRolePermissions validates if a custom role permits the requested HTTP action
func (s *gateway) checkCustomRolePermissions(customRole *table.OrgUnitCustomRole, r *http.Request) bool {
	// Extract the resource and verb from the current route
	routeInfo, err := s.extractRouteInfo(r)
	if err != nil {
		log.Printf("failed to extract route info for permission check: %s", err)
		return false // Deny access if we can't determine the resource
	}

	// Check each permission in the custom role
	for _, permission := range customRole.Permissions {
		if permission.Resource == routeInfo.Resource {
			// Check if the required verb is allowed
			for _, allowedVerb := range permission.Verbs {
				if allowedVerb == routeInfo.Verb {
					return true // Permission granted
				}
			}
		}
	}

	// If no matching permission found, deny access
	return false
}

// RouteInfo holds information about the current request route
type RouteInfo struct {
	Resource string // The resource being accessed
	Verb     string // The action being performed
}

// extractRouteInfo extracts resource and verb information from the current request
func (s *gateway) extractRouteInfo(r *http.Request) (*RouteInfo, error) {
	// Find the route configuration for this request
	routes, err := s.routes.FindMany(r.Context(), nil, 0, 0)
	if err != nil {
		return nil, err
	}

	// Convert HTTP method to route.MethodType for matching
	var targetMethod route.MethodType
	switch r.Method {
	case "GET":
		targetMethod = route.GET
	case "POST":
		targetMethod = route.POST
	case "PUT":
		targetMethod = route.PUT
	case "DELETE":
		targetMethod = route.DELETE
	case "PATCH":
		targetMethod = route.PATCH
	case "HEAD":
		targetMethod = route.HEAD
	case "OPTIONS":
		targetMethod = route.OPTIONS
	default:
		return nil, errors.New("unsupported HTTP method") // Unsupported method
	}

	// Match the current request to a route
	for _, route := range routes {
		if route.Key.Method == targetMethod &&
			matchesPath(route.Key.Url, r.URL.Path) {
			return &RouteInfo{
				Resource: route.Resource, // Resource name from route config
				Verb:     route.Verb,     // Verb/action from route config
			}, nil
		}
	}

	return nil, errors.New("route not found") // Route not found in configuration
}

// matchesPath checks if a route pattern matches the request path
func matchesPath(pattern, path string) bool {
	// Simple path matching - could be enhanced with parameter matching
	// For now, just check if the paths are equal (excluding parameters)
	return pattern == path || containsPathPattern(pattern, path)
}

// containsPathPattern performs basic pattern matching for routes with parameters
func containsPathPattern(pattern, path string) bool {
	// This is a simplified implementation
	// A more robust implementation would handle {param} patterns properly
	return false // Placeholder - should implement proper pattern matching
}

func (s *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var status int
	match, orgUnit, err := matchRoute(r.Method, r.URL.Path)
	if err != nil {
		status = http.StatusNotFound
		http.Error(w, fmt.Sprintf("No route found for %s %s", r.Method, r.URL.Path), status)
		return
	}

	var authInfo *common.AuthInfo
	defer func() {
		if status != 0 {
			s.handleAccessLog(authInfo, orgUnit, r, status)
		}
	}()

	if match.isPublic {
		// even for public route ensure that we have auth info
		// set in the request header, so that backend server
		// can process the request correctly.
		// This is important for public routes that are used
		// ensuring uniform handling of gRPC gateway based
		// request processing, as it allows bypassing used gRPC
		// interceptors
		err = common.SetAuthInfoHeader(r, &common.AuthInfo{})
		if err != nil {
			status = http.StatusInternalServerError
			http.Error(w, fmt.Sprintf("Something went wrong: %s", err), status)
			return
		}
	} else {
		authInfo, err = s.AuthenticateRequest(r)
		if err != nil {
			status = http.StatusUnauthorized
			http.Error(w, fmt.Sprintf("Authentication failed: %s", err), status)
			return
		}
		newCtx := context.WithValue(r.Context(), authKey, *authInfo)
		newCtx = context.WithValue(newCtx, ouKey, orgUnit)
		r = r.WithContext(newCtx)
		if !match.isUserSpecific {
			if match.isRoot && !authInfo.IsRoot {
				// access to the route is meant to come only from root tenancy
				status = http.StatusForbidden
				http.Error(w, "Access Denied", status)
				return
			}
			// perform RBAC / PBAC and scope validations
			// TODO(prabhjot) currently only allow admin role
			isTenantAdmin := slices.Contains(authInfo.Roles, "admin")

			if !isTenantAdmin {
				allow := false
				if orgUnit != "" {
					// check if Org Unit Role associated with user, allows the
					// requested access
					allow = s.performOrgUnitRoleCheck(authInfo, orgUnit, r)
				}
				if !allow {
					status = http.StatusForbidden
					http.Error(w, "Access Denied", status)
					return
				}
			}
		}
		// validate Org unit scope irrespective if the match is
		// user specific or not
		if orgUnit != "" {
			//log.Printf("Checking access for org unit %s in tenant %s", orgUnit, authInfo.Realm)
			// check org unit is available and associated with tenant
			ouList, err := s.ouTbl.FindByTenant(r.Context(), authInfo.Realm, orgUnit)
			if err != nil {
				if errors.IsNotFound(err) {
					status = http.StatusNotFound
					http.Error(w, fmt.Sprintf("Org Unit %s not found", orgUnit), status)
					return
				}
				log.Printf("Failed to find org unit %s in tenant %s: %s", orgUnit, authInfo.Realm, err)
				status = http.StatusInternalServerError
				http.Error(w, "Something went wrong while processing request", status)
				return
			}
			if len(ouList) == 0 {
				status = http.StatusNotFound
				http.Error(w, fmt.Sprintf("Org Unit %s not found", orgUnit), status)
				return
			}
		}
	}

	r.URL.Scheme = match.scheme
	r.URL.Host = match.host
	// Set the Host header to match the URL host
	// This is important for the reverse proxy to work correctly
	// especially for HTTP/2 where the Host header is mandatory
	// and should match the authority of the request.
	// This is also important for HTTP/1.1 where the Host header
	// is used to determine the target host for the request.
	// This is required for the reverse proxy to work correctly
	// and to ensure that the backend server receives the correct
	// Host header.
	r.Host = r.URL.Host

	// support for HTTP/2 as well as HTTP/1.1
	if r.ProtoMajor == 2 {
		s.proxyV2.ServeHTTP(w, r)
	} else {
		s.proxyV1.ServeHTTP(w, r)
	}
}

func (s *gateway) handleAccessLog(authInfo *common.AuthInfo, ou string, r *http.Request, status int) {
	msg := fmt.Sprintf("[Access Log] Method: %s, Url: %s, Status: %d", r.Method, r.URL.Path, status)
	if ou != "" {
		msg += fmt.Sprintf(", ou: %s", ou)
	}
	if authInfo != nil {
		msg += fmt.Sprintf(", accessed by %s:%s", authInfo.Realm, authInfo.UserName)
	} else {
		msg += ", accessed anonymously"
	}
	log.Println(msg)
}

// currently this is only relevant for logging response
func (s *gateway) ModifyResponse(resp *http.Response) error {
	var authInfo *common.AuthInfo
	authInfoObj, ok := resp.Request.Context().Value(authKey).(common.AuthInfo)
	if ok {
		authInfo = &authInfoObj
	}
	ou, ok := resp.Request.Context().Value(ouKey).(string)
	if !ok {
		ou = ""
	}
	s.handleAccessLog(authInfo, ou, resp.Request, resp.StatusCode)
	return nil
}

func gatewayErrorHandler(w http.ResponseWriter, req *http.Request, err error) {
	log.Println("Auth gateway proxy received error", err)
	http.Error(w, "Service temporarily unavailable, please try after sometime", http.StatusServiceUnavailable)
}

// Create a new Auth Gateway server, wrapped around
// locally hosted insecure server
func New() http.Handler {
	apiKeys, err := table.GetApiKeyTable()
	if err != nil {
		log.Panicf("unable to get api keys table: %s", err)
	}

	userTbl, err := table.GetUserTable()
	if err != nil {
		log.Panicf("unable to get user table: %s", err)
	}

	routes, err := route.GetRouteTable()
	if err != nil {
		log.Panicf("unable to get route table: %s", err)
	}

	ouTbl, err := table.GetOrgUnitTable()
	if err != nil {
		log.Panicf("unable to get org unit table: %s", err)
	}

	ouUserTbl, err := table.GetOrgUnitUserTable()
	if err != nil {
		log.Panicf("unable to get org unit user table: %s", err)
	}

	director := func(req *http.Request) {
		// we don't use director we will handle request modification
		// of our own
	}

	// Transport for HTTP/1.1
	tr1 := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// Transport for HTTP/2
	tr2 := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	gateway := &gateway{
		validator: hash.NewValidator(300), // Allow an API request to be valid for 5 mins, to handle offer if any
		apiKeys:   apiKeys,
		userTbl:   userTbl,
		routes:    routes,
		ouTbl:     ouTbl,
		ouUserTbl: ouUserTbl,
		proxyV1: &httputil.ReverseProxy{
			Director:     director,
			Transport:    tr1,
			ErrorHandler: gatewayErrorHandler,
		},
		proxyV2: &httputil.ReverseProxy{
			Director:     director,
			Transport:    tr2,
			ErrorHandler: gatewayErrorHandler,
		},
	}

	// set modify response handler for both v1 and v2 proxy
	gateway.proxyV1.ModifyResponse = gateway.ModifyResponse
	gateway.proxyV2.ModifyResponse = gateway.ModifyResponse

	r := &gatewayReconciler{
		gw: gateway,
	}

	err = routes.Register("GatewayController", r)
	if err != nil {
		log.Panicf("Failed to register GatewayController: %s", err)
	}
	return gateway
}
