package server

import (
	"net/http"

	"github.com/apimgr/whois/src/swagger"
	"github.com/go-chi/chi/v5"
)

func (s *Server) addAPIRoute(router chi.Router, method, path, operationID, summary, auth string, listed, internal bool, handler http.Handler) {
	s.addAPIRouteStatus(router, method, path, operationID, summary, auth, listed, internal, http.StatusOK, handler)
}

func (s *Server) addAPIRouteStatus(router chi.Router, method, path, operationID, summary, auth string, listed, internal bool, successStatus int, handler http.Handler) {
	s.addAPIRouteModel(router, swagger.Route{Method: method, Path: path, OperationID: operationID, Summary: summary, Auth: auth, Listed: listed, Internal: internal, Response: swagger.APIResponseModel{}, SuccessStatus: successStatus, Handler: handler})
}

func (s *Server) addAPIRouteModel(router chi.Router, route swagger.Route) {
	s.addContractRoute(router, route)
}

func (s *Server) addContractRoute(router chi.Router, route swagger.Route) {
	if s.routeRegistry == nil {
		s.routeRegistry = swagger.NewRegistry()
	}
	if err := s.routeRegistry.Add(route); err != nil {
		panic(err)
	}
	router.Method(route.Method, route.Path, route.Handler)
}

func (s *Server) apiRoutes() []swagger.Route {
	if s.routeRegistry == nil {
		s.setupRoutes()
	}
	return s.routeRegistry.Routes()
}
