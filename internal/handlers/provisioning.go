package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os/exec"
	"time"
)

type ProvisionRequest struct {
	Provider string `json:"provider"` // z.B. "hetzner", "aws", "proxmox"
	NodeName string `json:"node_name"`
	CISLevel string `json:"cis_level"`
}

func TriggerProvisioning(w http.ResponseWriter, r *http.Request) {
	var req ProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// Sicherheit: Context mit Timeout verhindert unendlich laufende Terraform-Prozesse
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Best Practice: Arbeitsverzeichnis strikt auf den Terraform-Ordner setzen
	cmd := exec.CommandContext(ctx, "/usr/bin/terraform", "apply", "-auto-approve",
		"-var", "node_name="+req.NodeName,
		"-var", "provider="+req.Provider)
	cmd.Dir = "/opt/sentinel/deployments/terraform"

	// Führt Terraform asynchron in einer Goroutine aus, um die API nicht zu blockieren
	go func() {
		output, err := cmd.CombinedOutput()
		if err != nil {
			slog.Error("Provisioning fehlgeschlagen", "node", req.NodeName, "error", err, "output", string(output))
			return
		}
		slog.Info("Provisioning erfolgreich", "node", req.NodeName)
		// Hier würde ein Webhook oder Datenbank-Update folgen
	}()

	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status": "provisioning_started", "node": "` + req.NodeName + `"}`))
}
