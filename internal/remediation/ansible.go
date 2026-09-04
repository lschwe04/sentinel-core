package remediation

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"sentinel-core/internal/audit"
)

type Engine struct {
	auditLogger *audit.Logger
	playbookDir string
}

func NewEngine(logger *audit.Logger, playbookDir string) *Engine {
	return &Engine{
		auditLogger: logger,
		playbookDir: playbookDir,
	}
}

// TriggerHardening führt ein Playbook gegen einen spezifischen Node aus
func (e *Engine) TriggerHardening(ctx context.Context, tenantID, nodeID, ruleID string) error {
	playbookPath := fmt.Sprintf("%s/%s.yml", e.playbookDir, ruleID)

	cmd := exec.CommandContext(ctx, "ansible-playbook", playbookPath, "--limit", nodeID)

	start := time.Now()
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	status := "SUCCESS"
	if err != nil {
		status = "FAILED"
		slog.Error("Playbook execution failed", "node", nodeID, "error", err, "output", string(output))
	}

	// Audit-Log-Eintrag schreiben
	auditPayload := map[string]any{
		"rule_id":        ruleID,
		"execution_time": duration.String(),
		"status":         status,
		"output_snippet": string(output)[0:min(len(output), 500)], // Nur die ersten 500 Zeichen
	}

	if auditErr := e.auditLogger.LogEvent(ctx, tenantID, "ANSIBLE_HARDENING_TRIGGER", "system_remediation_engine", nodeID, auditPayload); auditErr != nil {
		slog.Error("Failed to write audit log for remediation", "error", auditErr)
	}

	if err != nil {
		return fmt.Errorf("remediation failed: %w", err)
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
