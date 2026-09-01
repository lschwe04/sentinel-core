package handlers

import (
	"context"
	"fmt"
	"net/http"
	"sentinel-core/internal/db"
)

// RenderTenantOverview zeigt dem Systemhaus alle seine Endkunden und deren Status auf einen Blick
func RenderTenantOverview(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		http.Error(w, "tenant_id required", http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	query := `
		SELECT c.id, c.name, COUNT(n.node_id) as node_count
		FROM customers c
		LEFT JOIN hardening_status n ON c.id = n.customer_id
		WHERE c.tenant_id = $1
		GROUP BY c.id, c.name
	`
	rows, err := db.Pool.Query(ctx, query, tenantID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
		<div class="border border-gray-700 rounded-lg p-6 bg-gray-800">
			<h2 class="text-xl font-semibold mb-4">🏢 Endkunden-Übersicht (Mandanten)</h2>
			<div class="space-y-4">
	`)

	hasRows := false
	for rows.Next() {
		hasRows = true
		var customerID int
		var customerName string
		var nodeCount int
		if err := rows.Scan(&customerID, &customerName, &nodeCount); err == nil {
			fmt.Fprintf(w, `
				<div class="p-4 bg-gray-900 rounded border border-gray-700 flex justify-between items-center">
					<div>
						<h3 class="font-bold text-lg text-white">%s</h3>
						<p class="text-sm text-gray-400">Verwaltete Nodes: %d</p>
					</div>
					<span class="px-3 py-1 bg-green-900 text-green-300 text-xs rounded-full">Aktiv</span>
				</div>
			`, customerName, nodeCount)
		}
	}

	if !hasRows {
		fmt.Fprintf(w, `<p class="text-gray-400">Noch keine Endkunden angelegt.</p>`)
	}

	fmt.Fprintf(w, `</div></div>`)
}
