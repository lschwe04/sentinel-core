package remediation

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"sentinel-core/internal/audit"
)

type Engine struct {
	auditLogger *audit.Logger
	playbookDir string
}

var safeRuleIDRegex = regexp.MustCompile(`^[a-zA-Z0-9\-_]+$`)

func NewEngine(logger *audit.Logger, playbookDir string) *Engine {
	return &Engine{
		auditLogger: logger,
		playbookDir: playbookDir,
	}
}

// TriggerHardening führt ein Playbook gegen einen spezifischen Node aus
func (e *Engine) TriggerHardening(ctx context.Context, tenantID, nodeID, ruleID string) error {
	if !safeRuleIDRegex.MatchString(ruleID) {
		return fmt.Errorf("invalid rule_id format: potential path traversal detected")
	}

	// Sicherer Pfadaufbau mit filepath.Join und Clean
	playbookFilename := fmt.Sprintf("%s.yml", ruleID)
	playbookPath := filepath.Clean(filepath.Join(e.playbookDir, playbookFilename))

	// Verzeichnis-Isolation absichern
	absPlaybookDir, err := filepath.Abs(e.playbookDir)
	if err != nil {
		return fmt.Errorf("invalid playbook directory: %w", err)
	}
	absPlaybookPath, err := filepath.Abs(playbookPath)
	if err != nil || len(absPlaybookPath) < len(absPlaybookDir) || absPlaybookPath[:len(absPlaybookDir)] != absPlaybookDir {
		return fmt.Errorf("unauthorized path traversal attempt via rule_id")
	}

	cmd := exec.CommandContext(ctx, "ansible-playbook", absPlaybookPath, "--limit", nodeID)

	start := time.Now()
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	status := "SUCCESS"
	if err != nil {
		status = "FAILED"
		slog.Error("Playbook execution failed", "node", nodeID, "error", err, "output", string(output))
	}

	snippetLimit := 500
	if len(output) < snippetLimit {
		snippetLimit = len(output)
	}

	auditPayload := map[string]any{
		"rule_id":        ruleID,
		"execution_time": duration.String(),
		"status":         status,
		"output_snippet": string(output)[0:snippetLimit],
	}

	if auditErr := e.auditLogger.LogEvent(ctx, tenantID, "ANSIBLE_HARDENING_TRIGGER", "system_remediation_engine", nodeID, auditPayload); auditErr != nil {
		slog.Error("Failed to write audit log for remediation", "error", auditErr)
	}

	if err != nil {
		return fmt.Errorf("remediation failed: %w", err)
	}
	return nil
}
