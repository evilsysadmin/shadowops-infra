package websession

import "net/http"

// StagingAdminPage serves only the static administration shell. Account data
// remains behind the separately authenticated and audited inventory API.
func StagingAdminPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.TLS == nil || r.Host != stagingHost || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method denied", http.StatusMethodNotAllowed)
		return
	}
	var asset, contentType string
	switch r.URL.Path {
	case "/admin":
		asset, contentType = "assets/admin.html", "text/html; charset=utf-8"
	case "/assets/admin.css":
		asset, contentType = "assets/admin.css", "text/css; charset=utf-8"
	case "/assets/admin.js":
		asset, contentType = "assets/admin.js", "text/javascript; charset=utf-8"
	default:
		http.NotFound(w, r)
		return
	}
	data, err := assets.ReadFile(asset)
	if err != nil {
		http.Error(w, "asset unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(data)
}
