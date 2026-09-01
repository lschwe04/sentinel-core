package handlers

import (
	"fmt"
	"net/http"
)

func RenderHardeningTab(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
		<div class="border border-gray-700 rounded-lg p-6 bg-gray-800">
			<h2 class="text-xl font-semibold mb-4">🛡️ CIS Hardening Management</h2>
			<p class="text-gray-400 mb-6">Überwache und erzwinge Compliance-Richtlinien auf allen Nodes.</p>
			<button hx-post="/api/v1/hardening/trigger" hx-swap="outerHTML"
					class="px-6 py-2 bg-blue-600 hover:bg-blue-500 font-bold rounded transition">
				CIS Hardening (Level 2) jetzt ausführen
			</button>
		</div>
	`)
}

func RenderMetricsTab(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
		<div class="border border-gray-700 rounded-lg p-6 bg-gray-800">
			<h2 class="text-xl font-semibold mb-4">📊 Live Metriken & Auslastung</h2>
			<p class="text-gray-400">CPU-, RAM- und Netzwerk-Telemetrie der angebundenen Nodes.</p>
			<div class="mt-4 p-4 bg-gray-900 rounded border border-gray-700 font-mono text-sm text-green-400">
				[System OK] Keine Engpässe detektiert. Aktualisierungsrate: 10s
			</div>
		</div>
	`)
}
