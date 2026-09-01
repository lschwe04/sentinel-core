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
	Provider       string `json:"provider"` // z.B. "hetzner", "aws", oder "local"
	NodeName       string `json:"node_name"`
	NodeIP         string `json:"node_ip,omitempty"` // Relevant für lokale Server
	HardeningLevel string `json:"hardening_level"`   // "level1" oder "level2"
}

func TriggerProvisioning(w http.ResponseWriter, r *http.Request) {
	var req ProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// Standardwert setzen, falls kein Level im Request übergeben wurde
	if req.HardeningLevel == "" {
		req.HardeningLevel = "level1"
	}

	// Hybride Unterscheidung
	if req.Provider == "local" {
		// Lokaler Weg: Terraform wird übersprungen, Ansible übernimmt direkt das On-Premises-Setup und Härtung
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()

			cmd := exec.CommandContext(ctx, "/usr/bin/ansible-playbook", "/etc/sentinel/playbooks/onprem-bootstrap.yml",
				"-e", "target_host="+req.NodeIP,
				"-e", "hardening_level="+req.HardeningLevel)

			if err := cmd.Run(); err != nil {
				slog.Error("Lokales On-Premises Provisioning & Hardening fehlgeschlagen", "node", req.NodeName, "error", err)
				return
			}
			slog.Info("Lokaler Node erfolgreich angebunden und gehärtet", "node", req.NodeName, "hardening", req.HardeningLevel)
		}()

		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status": "local_provisioning_started", "node": "` + req.NodeName + `", "hardening": "` + req.HardeningLevel + `"}`))
		return
	}

	// Cloud-Weg via Terraform (inklusive Übergabe des Hardening-Levels)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/usr/bin/terraform", "apply", "-auto-approve",
		"-var", "node_name="+req.NodeName,
		"-var", "provider="+req.Provider,
		"-var", "hardening_level="+req.HardeningLevel)
	cmd.Dir = "/opt/sentinel/deployments/terraform"

	go func() {
		if output, err := cmd.CombinedOutput(); err != nil {
			slog.Error("Cloud Provisioning fehlgeschlagen", "node", req.NodeName, "error", err, "output", string(output))
			return
		}
		slog.Info("Cloud Provisioning & Hardening erfolgreich", "node", req.NodeName, "hardening", req.HardeningLevel)
	}()

	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status": "cloud_provisioning_started", "node": "` + req.NodeName + `", "hardening": "` + req.HardeningLevel + `"}`))
}
