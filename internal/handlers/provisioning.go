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
	Provider       string `json:"provider"`
	NodeName       string `json:"node_name"`
	NodeIP         string `json:"node_ip,omitempty"`
	HardeningLevel string `json:"hardening_level"`
}

var safeNameRegex = regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)

func TriggerProvisioning(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req ProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid payload"}`, http.StatusBadRequest)
		return
	}

	// Security: Strikte Input-Validierung
	if !safeNameRegex.MatchString(req.NodeName) {
		http.Error(w, `{"error": "Invalid node_name format"}`, http.StatusBadRequest)
		return
	}

	// Security: Whitelisting gegen Command Injection in Sub-Prozessen
	if req.HardeningLevel != "level1" && req.HardeningLevel != "level2" {
		req.HardeningLevel = "level1"
	}

	if req.Provider == "local" {
		if net.ParseIP(req.NodeIP) == nil {
			http.Error(w, `{"error": "Invalid node_ip format"}`, http.StatusBadRequest)
			return
		}

		// Scalability: Parameter in die Goroutine übergeben, um Race Conditions im Heap zu vermeiden
		go func(ip, level, name string) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()

			cmd := exec.CommandContext(ctx, "/usr/bin/ansible-playbook", "/etc/sentinel/playbooks/onprem-bootstrap.yml",
				"-e", "target_host="+ip,
				"-e", "hardening_level="+level)

			if output, err := cmd.CombinedOutput(); err != nil {
				slog.Error("On-Premises Provisioning failed", "node", name, "error", err, "output", string(output))
				return
			}
			slog.Info("Lokaler Node erfolgreich eingerichtet", "node", name)
		}(req.NodeIP, req.HardeningLevel, req.NodeName)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status": "local_provisioning_started", "node": "` + req.NodeName + `"}`))
		return
	}

	go func(name, level string) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()

		cmd := exec.CommandContext(ctx, "/usr/bin/terraform", "apply", "-auto-approve",
			"-var", "node_name="+name,
			"-var", "hardening_level="+level)
		cmd.Dir = "/opt/sentinel/deployments/terraform"

		if output, err := cmd.CombinedOutput(); err != nil {
			slog.Error("Cloud Provisioning failed", "node", name, "error", err, "output", string(output))
			return
		}
		slog.Info("Cloud Provisioning erfolgreich abgeschlossen", "node", name)
	}(req.NodeName, req.HardeningLevel)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"status": "cloud_provisioning_started", "node": "` + req.NodeName + `"}`))
}
