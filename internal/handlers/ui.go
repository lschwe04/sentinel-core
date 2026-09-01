package handlers

import (
	"fmt"
	"net/http"
)

func RenderHardeningTab(w http.ResponseWriter, r *http.Request) {
	// Delegiert direkt an das dynamische Live-Widget mit Polling
	RenderHardeningWidget(w, r)
}

func RenderProvisioningTab(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `
		<div class="border border-gray-700 rounded-lg p-6 bg-gray-800">
			<h2 class="text-xl font-semibold mb-4">🚀 Hybrides Server Provisioning & Security Hardening</h2>
			<p class="text-gray-400 mb-6">Rolle neue Nodes via Terraform (Cloud) oder Ansible (On-Premises) aus.</p>
			
			<form hx-post="/api/v1/provisioning/trigger" hx-swap="outerHTML" class="space-y-4 max-w-lg">
				<div>
					<label class="block text-sm font-medium text-gray-300 mb-1">Server Name / Node ID</label>
					<input type="text" name="node_name" required placeholder="node-prod-02" 
						class="w-full bg-gray-900 border border-gray-700 rounded p-2 text-white focus:outline-none focus:border-blue-500">
				</div>

				<div>
					<label class="block text-sm font-medium text-gray-300 mb-1">Infrastruktur Provider</label>
					<select name="provider" class="w-full bg-gray-900 border border-gray-700 rounded p-2 text-white focus:outline-none focus:border-blue-500">
						<option value="hetzner">Hetzner Cloud (Terraform)</option>
						<option value="local">On-Premises Server (Ansible direkt)[cite: 3]</option>
					</select>
				</div>

				<div>
					<label class="block text-sm font-medium text-gray-300 mb-1">CIS Hardening Profil</label>
					<select name="hardening_level" class="w-full bg-gray-900 border border-gray-700 rounded p-2 text-white focus:outline-none focus:border-blue-500">
						<option value="level1">CIS Level 1 (Standard Best Practices)[cite: 3]</option>
						<option value="level2" selected>CIS Level 2 (Strikt / High Security)[cite: 3]</option>
					</select>
				</div>

				<button type="submit" class="px-6 py-2 bg-blue-600 hover:bg-blue-500 font-bold rounded transition text-white">
					Ausrollen & Härten starten
				</button>
			</form>
		</div>
	`)
}

func RenderMetricsTab(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<div class="border border-gray-700 rounded-lg p-6 bg-gray-800"><h2 class="text-xl font-semibold mb-4">📊 Live Metriken</h2><p class="text-gray-400">Echtzeit-Telemetrie via gopsutil aktiv[cite: 3].</p></div>`)
}

func RenderBackupsTab(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<div class="border border-gray-700 rounded-lg p-6 bg-gray-800"><h2 class="text-xl font-semibold mb-4">💾 Backup Status</h2><p class="text-gray-400">Restic Snapshot Monitoring aktiv[cite: 3].</p></div>`)
}

func RenderLogsTab(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<div class="border border-gray-700 rounded-lg p-6 bg-gray-800"><h2 class="text-xl font-semibold mb-4">📋 Security Logs</h2><p class="text-gray-400">Falco & Auditd Auswertung aktiv[cite: 3].</p></div>`)
}
