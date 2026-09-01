package handlers

import (
	"encoding/json"
	"net/http"
	"time"
)

type BackupStatus struct {
	NodeID          string    `json:"node_id"`
	LastBackup      time.Time `json:"last_backup_time"`
	Status          string    `json:"status"` // "success", "failed", "running"
	S3ObjectLock    bool      `json:"s3_object_lock_active"`
	LastRestoreTest time.Time `json:"last_restore_test"`
	TotalSizeGB     float64   `json:"total_size_gb"`
}

func GetBackupStatus(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, "node_id query parameter is required", http.StatusBadRequest)
		return
	}

	// Mock: Normalerweise ein sicherer Datenbank-Select (z.B. pgx) auf die aggregierten Agenten-Daten
	status := BackupStatus{
		NodeID:          nodeID,
		LastBackup:      time.Now().Add(-2 * time.Hour),
		Status:          "success",
		S3ObjectLock:    true,
		LastRestoreTest: time.Now().Add(-720 * time.Hour), // Vor 30 Tagen
		TotalSizeGB:     145.5,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
