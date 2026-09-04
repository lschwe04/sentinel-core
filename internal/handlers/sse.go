package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

type LiveMetricEvent struct {
	NodeID      string    `json:"node_id"`
	TenantID    string    `json:"tenant_id"`
	CPUUsagePct float64   `json:"cpu_usage_pct"`
	RAMUsagePct float64   `json:"ram_usage_pct"`
	Status      string    `json:"status"`
	Timestamp   time.Time `json:"timestamp"`
}

// SSEBroker verwaltet aktive SSE-Verbindungen für HTMX Push Updates
type SSEBroker struct {
	mu        sync.RWMutex
	clients   map[chan LiveMetricEvent]string // Client Channel -> TenantID
	Broadcast chan LiveMetricEvent
}

var GlobalSSEBroker *SSEBroker

func InitSSEBroker() *SSEBroker {
	broker := &SSEBroker{
		clients:   make(map[chan LiveMetricEvent]string),
		Broadcast: make(chan LiveMetricEvent, 256),
	}
	go broker.listen()
	GlobalSSEBroker = broker
	return broker
}

func (b *SSEBroker) listen() {
	for event := range b.Broadcast {
		b.mu.RLock()
		for clientChan, tenantID := range b.clients {
			if tenantID == "" || tenantID == event.TenantID {
				select {
				case clientChan <- event:
				default:
					slog.Warn("SSE client stream slow, dropping frame", "node_id", event.NodeID)
				}
			}
		}
		b.mu.RUnlock()
	}
}

// HandleSSEStream stellt den HTTP Event-Stream für das HTMX Dashboard bereit
func HandleSSEStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusBadRequest)
		return
	}

	tenantID := r.URL.Query().Get("tenant_id")

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	clientChan := make(chan LiveMetricEvent, 32)

	GlobalSSEBroker.mu.Lock()
	GlobalSSEBroker.clients[clientChan] = tenantID
	GlobalSSEBroker.mu.Unlock()

	defer func() {
		GlobalSSEBroker.mu.Lock()
		delete(GlobalSSEBroker.clients, clientChan)
		GlobalSSEBroker.mu.Unlock()
		close(clientChan)
	}()

	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-clientChan:
			if !ok {
				return
			}

			// Formatierung als HTMX-kompatibles HTML-Fragment für hx-ext="sse"
			htmlFragment := fmt.Sprintf(
				`<div id="node-card-%s" class="p-4 bg-gray-800 border border-gray-700 rounded-lg">`+
					`<h3 class="font-bold text-blue-400">%s</h3>`+
					`<p class="text-sm">CPU: <span class="font-mono">%0.1f%%</span> | RAM: <span class="font-mono">%0.1f%%</span></p>`+
					`<span class="text-xs text-gray-400">Status: %s (Aktualisiert: %s)</span>`+
					`</div>`,
				event.NodeID, event.NodeID, event.CPUUsagePct, event.RAMUsagePct, event.Status, event.Timestamp.Format("15:04:05"),
			)

			// SSE Payload senden
			fmt.Fprintf(w, "event: metric_update\ndata: %s\n\n", htmlFragment)
			flusher.Flush()
		}
	}
}
