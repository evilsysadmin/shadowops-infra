package websession

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/evilsysadmin/shadowops-infra/services/identity/issuance"
)

//go:embed assets/*
var assets embed.FS

var loginTemplate = template.Must(template.ParseFS(assets, "assets/login.html"))

func (h *Handler) page(w http.ResponseWriter, r *http.Request) bool {
	var asset, contentType string
	switch r.URL.Path {
	case "/login":
	case "/assets/login.js":
		asset, contentType = "assets/login.js", "text/javascript; charset=utf-8"
	case "/assets/login.css":
		asset, contentType = "assets/login.css", "text/css; charset=utf-8"
	default:
		return false
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method denied", http.StatusMethodNotAllowed)
		return true
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	if asset != "" {
		data, err := assets.ReadFile(asset)
		if err != nil {
			http.Error(w, "asset unavailable", http.StatusServiceUnavailable)
			return true
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(data)
		return true
	}
	query := r.URL.Query()
	if len(query) != 1 || len(query["app"]) != 1 {
		http.Error(w, "application required", http.StatusBadRequest)
		return true
	}
	app := issuance.Application(query.Get("app"))
	var origin string
	for candidate, audience := range consumers {
		if audience == app {
			origin = candidate
		}
	}
	labels := map[issuance.Application]string{issuance.ChessStudio: "Chess Studio", issuance.Chronicles: "Chronicles", issuance.CKASimulator: "CKA"}
	if origin == "" {
		http.Error(w, "application denied", http.StatusBadRequest)
		return true
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = loginTemplate.Execute(w, struct{ Application, ReturnURL string }{labels[app], origin + "/?shadowops=central"})
	return true
}
