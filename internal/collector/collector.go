package collector

import (
	"context"
	"net/http"
	"os/exec"
	"time"
)

func CheckResticStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Restic via JSON output abfragen
	cmd := exec.CommandContext(ctx, "/usr/bin/restic", "snapshots", "--json")
	// In Prod: Environment Variablen (S3 Keys, Password) hier injizieren

	output, err := cmd.Output()
	if err != nil {
		http.Error(w, "Restic check failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(output)
}
