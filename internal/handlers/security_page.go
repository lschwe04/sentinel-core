package handlers

import (
	"fmt"
	"net/http"
)

func RenderSecurityTrustPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `
		<!DOCTYPE html>
		<html lang="de">
		<head>
		    <meta charset="UTF-8">
		    <title>Security & Trust | SentinelCore</title>
		    <script src="https://cdn.tailwindcss.com"></script>
		</head>
		<body class="bg-gray-900 text-gray-100 p-10 font-sans">
		    <div class="max-w-4xl mx-auto space-y-8">
		        <h1 class="text-3xl font-bold text-blue-500">Security & Compliance bei SentinelCore</h1>
		        <p class="text-gray-300">Wir nehmen die Sicherheit Ihrer Infrastruktur ernst. Hier erfahren Sie, wie wir Ihre Daten schützen.</p>
		        
		        <div class="bg-gray-800 p-6 rounded-lg border border-gray-700 space-y-4">
		            <h2 class="text-xl font-semibold text-white">1. Verschlüsselung (Transport & Storage)</h2>
		            <p class="text-gray-400">Sämtliche Kommunikation zwischen Agent und Hub erfolgt ausschließlich über erzwungenes mTLS (TLS 1.3) innerhalb isolierter Netzwerke.</p>
		        </div>

		        <div class="bg-gray-800 p-6 rounded-lg border border-gray-700 space-y-4">
		            <h2 class="text-xl font-semibold text-white">2. Agenten-Sandboxing</h2>
		            <p class="text-gray-400">Der Sentinel-Agent läuft auf Linux-Systemen mit strengen systemd-Restriktionen (u.a. <code>ProtectSystem=strict</code> und <code>MemoryDenyWriteExecute</code>).</p>
		        </div>

		        <div class="bg-gray-800 p-6 rounded-lg border border-gray-700 space-y-4">
		            <h2 class="text-xl font-semibold text-white">3. Datenschutz & DSGVO (AVV)</h2>
		            <p class="text-gray-400">Hosting in ISO 27001-zertifizierten Rechenzentren in Deutschland/Frankfurt. Einen Vertrag zur Auftragsverarbeitung (AVV) nach Art. 28 DSGVO stellen wir all unseren Partnern digital zur Verfügung.</p>
		        </div>
		    </div>
		</body>
		</html>
	`)
}
