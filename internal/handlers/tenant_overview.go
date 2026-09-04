package handlers

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"time"

	"sentinel-core/internal/db"
)

type CustomerSummary struct {
	ID            int     `json:"id"`
	Name          string  `json:"name"`
	TotalNodes    int     `json:"total_nodes"`
	CompliancePct float64 `json:"compliance_pct"`
	Status        string  `json:"status"`
}

// RenderTenantOverview stellt das mandantenfähige Systemhaus-Dashboard bereit
func RenderTenantOverview(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		tenantID = "1"
	}
	safeTenantID := html.EscapeString(tenantID)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	query := `
		SELECT c.id, c.name, 
		       COALESCE(COUNT(h.node_id), 0) as total_nodes,
		       COALESCE(AVG(CASE WHEN h.cis_level_2_compliant THEN 100.0 ELSE 0.0 END), 100.0) as compliance_pct
		FROM customers c
		LEFT JOIN hardening_status h ON c.id = h.customer_id
		WHERE c.tenant_id = $1
		GROUP BY c.id, c.name
	`

	rows, err := db.Pool.Query(ctx, query, safeTenantID)
	var customers []CustomerSummary
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var cs CustomerSummary
			if err := rows.Scan(&cs.ID, &cs.Name, &cs.TotalNodes, &cs.CompliancePct); err == nil {
				if cs.CompliancePct >= 90.0 {
					cs.Status = "Optimal"
				} else if cs.CompliancePct >= 50.0 {
					cs.Status = "Warnung"
				} else {
					cs.Status = "Kritisch"
				}
				customers = append(customers, cs)
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	// Responsives UI mit Tailwind & HTMX für maximale Geschwindigkeit und UX
	fmt.Fprintf(w, `
		<div class="space-y-6">
			<div class="flex justify-between items-center bg-gray-800 p-6 rounded-lg border border-gray-700 shadow-lg">
				<div>
					<h1 class="text-2xl font-bold text-white">Systemhaus Mandanten-Übersicht</h1>
					<p class="text-sm text-gray-400">Zentrales Enterprise Management für alle Endkunden im DACH-Raum</p>
				</div>
				<div>
					<span class="px-3 py-1 bg-blue-900 text-blue-300 border border-blue-700 rounded-full text-xs font-semibold">
						DACH Enterprise Edition
					</span>
				</div>
			</div>

			<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
	`)

	if len(customers) == 0 {
		fmt.Fprintf(w, `<div class="col-span-full p-8 text-center text-gray-400 bg-gray-800 rounded-lg border border-gray-700">Keine Endkunden für diesen Mandanten gefunden.</div>`)
	} else {
		for _, c := range customers {
			badgeClass := "bg-green-900 text-green-300 border-green-700"
			switch c.Status {
			case "Warnung":
				badgeClass = "bg-yellow-900 text-yellow-300 border-yellow-700"
			case "Kritisch":
				badgeClass = "bg-red-900 text-red-300 border-red-700"
			}

			fmt.Fprintf(w, `
				<div class="bg-gray-800 border border-gray-700 rounded-lg p-6 space-y-4 hover:border-blue-500 transition shadow-md">
					<div class="flex justify-between items-start">
						<h3 class="text-lg font-bold text-white">%s</h3>
						<span class="px-2.5 py-0.5 rounded-full text-xs font-semibold border %s">%s</span>
					</div>
					<div class="text-sm text-gray-300 space-y-1">
						<p>Verwaltete Nodes: <span class="font-mono text-blue-400 font-bold">%d</span></p>
						<p>Hardening Score: <span class="font-mono text-white font-bold">%.1f%%</span></p>
					</div>
					<div class="pt-4 border-t border-gray-700 flex justify-between items-center text-xs">
						<a href="/api/v1/ui/tenant/overview?customer_id=%d" class="text-blue-400 hover:underline">Details anzeigen &rarr;</a>
						<span class="text-gray-500 font-mono">ID: %d</span>
					</div>
				</div>
			`, html.EscapeString(c.Name), badgeClass, c.Status, c.TotalNodes, c.CompliancePct, c.ID, c.ID)
		}
	}

	fmt.Fprintf(w, `
			</div>
		</div>
	`)
}
