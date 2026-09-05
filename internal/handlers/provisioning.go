package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"time"
)

type ProvisionRequest struct {
	Provider       string `json:"provider"` // "local" oder "hetzner"
	NodeName       string `json:"node_name"`
	NodeIP         string `json:"node_ip,omitempty"`
	HardeningLevel string `json:"hardening_level"` // "level1" oder "level2"
}

var safeNameRegex = regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)

func TriggerProvisioning(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	if !safeNameRegex.MatchString(req.NodeName) {
		http.Error(w, `{"error": "Invalid node_name format"}`, http.StatusBadRequest)
		return
	}

	if req.HardeningLevel == "" {
		req.HardeningLevel = "level1"
	}

	if req.Provider == "local" {
		if req.NodeIP == "" {
			http.Error(w, `{"error": "node_ip is required for local provisioning"}`, http.StatusBadRequest)
			return
		}
		// Validierung der IP-Adresse gegen Injection und Fehlkonfiguration
		if net.ParseIP(req.NodeIP) == nil {
			http.Error(w, `{"error": "Invalid node_ip format"}`, http.StatusBadRequest)
			return
		}

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()

			cmd := exec.CommandContext(ctx, "/usr/bin/ansible-playbook", "/etc/sentinel/playbooks/onprem-bootstrap.yml",
				"-e", "target_host="+req.NodeIP,
				"-e", "hardening_level="+req.HardeningLevel)

			if output, err := cmd.CombinedOutput(); err != nil {
				slog.Error("On-Premises Provisioning fehlgeschlagen", "node", req.NodeName, "error", err, "output", string(output))
				return
			}
			slog.Info("Lokaler Node erfolgreich eingerichtet und gehärtet", "node", req.NodeName)
		}()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status": "local_provisioning_started", "node": "` + req.NodeName + `"}`))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/usr/bin/terraform", "apply", "-auto-approve",
		"-var", "node_name="+req.NodeName,
		"-var", "hardening_level="+req.HardeningLevel)
	cmd.Dir = "/opt/sentinel/deployments/terraform"

	go func() {
		if output, err := cmd.CombinedOutput(); err != nil {
			slog.Error("Cloud Provisioning fehlgeschlagen", "node", req.NodeName, "error", err, "output", string(output))
			return
		}
		slog.Info("Cloud Provisioning erfolgreich abgeschlossen", "node", req.NodeName)
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status": "cloud_provisioning_started", "node": "` + req.NodeName + `"}`))
}
