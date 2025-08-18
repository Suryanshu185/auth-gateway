// Copyright © 2025 Prabhjot Singh Sethi, All Rights reserved
// Author: Prabhjot Singh Sethi <prabhjot.sethi@gmail.com>

package gateway

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"sync"

	"github.com/go-core-stack/auth/route"
	"github.com/go-core-stack/core/errors"
	"github.com/go-core-stack/core/utils"
	"github.com/go-core-stack/patricia"
)

type routeData struct {
	scheme         string
	host           string
	isPublic       bool
	isRoot         bool
	isUserSpecific bool
	scopes         []string
	resource       string
	verb           string
}

type routeNodes map[route.MethodType]routeData

var routeLock sync.RWMutex
var gwRoutes = patricia.NewUrlTree[*routeNodes]()

func populateRoutes(routes *route.RouteTable) {
	list, err := routes.FindMany(context.Background(), nil, 0, 0)
	if err != nil {
		log.Printf("Failed to find routes: %s", err)
		return
	}
	nRoutes := patricia.NewUrlTree[*routeNodes]()
	for _, r := range list {
		ep, _ := url.Parse(r.Endpoint)
		_, _, node, ok := nRoutes.Match(r.Key.Url)
		if !ok {
			node = &routeNodes{
				r.Key.Method: {
					scheme:         ep.Scheme,
					host:           ep.Host,
					isPublic:       utils.PBool(r.IsPublic),
					isRoot:         utils.PBool(r.IsRoot),
					isUserSpecific: utils.PBool(r.IsUserSpecific),
					scopes:         r.Scopes,
					resource:       r.Resource,
					verb:           r.Verb,
				},
			}
			nRoutes.Insert(r.Key.Url, node)
		} else {
			(*node)[r.Key.Method] = routeData{
				scheme:         ep.Scheme,
				host:           ep.Host,
				isPublic:       utils.PBool(r.IsPublic),
				isRoot:         utils.PBool(r.IsRoot),
				isUserSpecific: utils.PBool(r.IsUserSpecific),
				scopes:         r.Scopes,
				resource:       r.Resource,
				verb:           r.Verb,
			}
		}
	}
	// take a lock before updating the global routes
	routeLock.Lock()
	defer routeLock.Unlock()
	gwRoutes = nRoutes
}

func matchRoute(m string, url string) (*routeData, map[string]string, error) {
	var node *routeNodes
	var ok bool
	var keys, values []string

	func() {
		routeLock.RLock()
		defer routeLock.RUnlock()

		keys, values, node, ok = gwRoutes.Match(url)
	}()

	if !ok {
		return nil, nil, errors.Wrapf(errors.NotFound, "route not found for %s", url)
	}

	var method route.MethodType
	switch m {
	case http.MethodGet:
		method = route.GET
	case http.MethodPost:
		method = route.POST
	case http.MethodPut:
		method = route.PUT
	case http.MethodDelete:
		method = route.DELETE
	case http.MethodConnect:
		method = route.CONNECT
	case http.MethodPatch:
		method = route.PATCH
	case http.MethodHead:
		method = route.HEAD
	case http.MethodOptions:
		method = route.OPTIONS
	case http.MethodTrace:
		method = route.TRACE
	default:
		return nil, nil, errors.Wrapf(errors.InvalidArgument, "invalid method %s", m)
	}

	data, ok := (*node)[method]
	if !ok {
		return nil, nil, errors.Wrapf(errors.NotFound, "route not found for %s", url)
	}

	// Extract scope parameters based on the defined scopes
	scopeParams := make(map[string]string)

	switch len(data.scopes) {
	case 1:
		if data.scopes[0] != "ou" {
			return nil, nil, errors.Wrapf(errors.InvalidArgument, "invalid scope %s for %s", data.scopes[0], url)
		}
		for i, k := range keys {
			if k == "ou" {
				scopeParams["ou"] = values[i]
				break
			}
		}
		if scopeParams["ou"] == "" {
			return nil, nil, errors.Wrapf(errors.InvalidArgument, "org unit not found")
		}
	case 0:
		break
	default:
		// Handle multiple scopes - extract all scope parameters that are present
		for _, scope := range data.scopes {
			for i, k := range keys {
				if k == scope {
					scopeParams[scope] = values[i]
					break
				}
			}
		}

		// Validate that required scopes are present
		for _, scope := range data.scopes {
			switch scope {
			case "ou":
				if scopeParams["ou"] == "" {
					return nil, nil, errors.Wrapf(errors.InvalidArgument, "org unit not found")
				}
			case "vpc":
				if scopeParams["vpc"] == "" {
					return nil, nil, errors.Wrapf(errors.InvalidArgument, "vpc not found")
				}
			}
		}
	}

	return &data, scopeParams, nil
}
