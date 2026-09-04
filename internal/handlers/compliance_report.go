// sentinel-core: internal/handlers/compliance_report.go
package handlers

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"time"

	"sentinel-core/internal/db"
)

type CustomerComplianceOverview struct {
	CustomerName   string    `json:"customer_name"`
	NodeCount      int       `json:"node_count"`
	CompliantNodes int       `json:"compliant_nodes"`
	LastScan       time.Time `json:"last_scan"`
	BackupStatus   string    `json:"backup_status"`
}

// RenderCustomerComplianceReport generiert ein druckbares, audit-gerechtes Compliance-Dokument für den Endkunden
func RenderCustomerComplianceReport(w http.ResponseWriter, r *http.Request) {
	customerID := r.URL.Query().Get("customer_id")
	tenantID := r.Header.Get("X-Tenant-ID")

	if customerID == "" || tenantID == "" {
		http.Error(w, "customer_id and X-Tenant-ID required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// 1. Mandanten- und Kundendaten abfragen
	var customerName string
	err := db.Pool.QueryRow(ctx, `SELECT name FROM customers WHERE id = $1 AND tenant_id = (SELECT id FROM tenants WHERE slug = $2)`, customerID, tenantID).Scan(&customerName)
	if err != nil {
		http.Error(w, "Customer not found or unauthorized", http.StatusNotFound)
		return
	}

	// 2. Hardening & Node Status aggregieren
	query := `
		SELECT 
			COUNT(n.node_id) as total_nodes,
			COUNT(CASE WHEN n.cis_level_2_compliant = true THEN 1 END) as compliant_nodes,
			MAX(n.last_scan) as last_scan
		FROM hardening_status n
		WHERE n.customer_id = $1
	`
	var totalNodes, compliantNodes int
	var lastScan *time.Time
	_ = db.Pool.QueryRow(ctx, query, customerID).Scan(&totalNodes, &compliantNodes, &lastScan)

	scanTimeStr := "Noch kein Scan durchgeführt"
	if lastScan != nil {
		scanTimeStr = lastScan.Format("02.01.2006 15:04:05 MST")
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
		<!DOCTYPE html>
		<html lang="de">
		<head>
			<meta charset="UTF-8">
			<title>Compliance Report - %s</title>
			<script src="https://cdn.tailwindcss.com"></script>
		</head>
		<body class="bg-white text-gray-900 p-10 font-sans print:p-0">
			<div class="max-w-3xl mx-auto space-y-8 border p-8 rounded-xl shadow-sm">
				<div class="flex justify-between items-border border-b pb-6">
					<div>
						<h1 class="text-2xl font-bold text-blue-600">SentinelCore Security & Compliance Report</h1>
						<p class="text-sm text-gray-500">Erstellt für Endkunde: <span class="font-semibold text-gray-800">%s</span></p>
					</div>
					<div class="text-right">
						<p class="text-xs text-gray-400">Datum:</p>
						<p class="text-sm font-mono">%s</p>
					</div>
				</div>

				<div class="grid grid-cols-3 gap-4">
					<div class="p-4 bg-gray-50 rounded border">
						<p class="text-xs text-gray-500">Verwaltete Nodes</p>
						<p class="text-2xl font-bold font-mono">%d</p>
					</div>
					<div class="p-4 bg-gray-50 rounded border">
						<p class="text-xs text-gray-500">CIS Level 2 Konform</p>
						<p class="text-2xl font-bold font-mono text-green-600">%d / %d</p>
					</div>
					<div class="p-4 bg-gray-50 rounded border">
						<p class="text-xs text-gray-500">Letzter Sicherheits-Scan</p>
						<p class="text-xs font-mono mt-2">%s</p>
					</div>
				</div>

				<div class="space-y-4">
					<h2 class="text-lg font-semibold border-b pb-2">Zusammenfassung der Härtung</h2>
					<p class="text-sm text-gray-600">
						Dieser automatisiert generierte Bericht bescheinigt den Sicherheitsstatus der IT-Infrastruktur im Rahmen des Mandanten-Managements. 
						Alle Richtlinien basieren auf CIS Benchmark v3.0 Vorgaben.
					</p>
				</div>

				<div class="pt-8 border-t flex justify-between text-xs text-gray-400">
					<p>SentinelCore Enterprise Hub - Zero Trust Architecture</p>
					<button onclick="window.print()" class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-500 print:hidden">
						Report als PDF drucken / speichern
					</button>
				</div>
			</div>
		</body>
		</html>
	`, html.EscapeString(customerName), html.EscapeString(customerName), time.Now().Format("02.01.2006"), totalNodes, compliantNodes, totalNodes, scanTimeStr)
}
