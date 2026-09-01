package handlers

import (
	"context"
	"fmt"
	"net/http"
	"sentinel-core/internal/db"
)

func RenderTenantDashboard(w http.ResponseWriter, r *http.Request) {
	// Beispiel: Tenant-Slug aus Query oder Context auslesen
	tenantSlug := r.URL.Query().Get("tenant")
	if tenantSlug == "" {
		tenantSlug = "default-systemhaus"
	}

	ctx := context.Background()
	var primaryColor string = "#2563eb" // Fallback
	var tenantName string = "SentinelCore"

	// Branding live aus DB laden
	query := `SELECT name, primary_color FROM tenants WHERE slug = $1`
	_ = db.Pool.QueryRow(ctx, query, tenantSlug).Scan(&tenantName, &primaryColor)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
		<!DOCTYPE html>
		<html lang="de">
		<head>
		    <meta charset="UTF-8">
		    <title>%s - Managed Security Hub</title>
		    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
		    <script src="https://cdn.tailwindcss.com"></script>
		    <style>
		        :root { --brand-color: %s; }
		        .bg-brand { background-color: var(--brand-color); }
		        .text-brand { color: var(--brand-color); }
		    </style>
		</head>
		<body class="bg-gray-900 text-gray-100 font-sans antialiased">
		    <div class="p-6">
		        <h1 class="text-2xl font-bold text-brand mb-2">%s Management Hub</h1>
		        <p class="text-gray-400">Mandantenfähige Infrastruktur- und Security-Überwachung.</p>
		    </div>
		</body>
		</html>
	`, tenantName, primaryColor, tenantName)
}
