package executor

import (
	"context"
	"log/slog"
	"net/http"
	"os/exec"
	"time"
)

func RunAnsiblePlaybook(w http.ResponseWriter, r *http.Request) {
	// Sicherheit: Context mit striktem Timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Pfad absolut angeben (Security Best Practice)
	cmd := exec.CommandContext(ctx, "/usr/bin/ansible-playbook", "/etc/sentinel/hardening.yml")

	output, err := cmd.CombinedOutput()
	if err != nil {
		slog.Error("Ansible Ausführung fehlgeschlagen", "error", err, "output", string(output))
		http.Error(w, "Execution failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "success"}`))
}
