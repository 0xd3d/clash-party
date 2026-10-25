package route

import (
	"net/http"

	"github.com/Dreamacro/clash/tunnel"
	"github.com/go-chi/render"
)

func getRouteDecisions(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, render.M{
		"decisions": tunnel.RouteDecisions(),
	})
}
