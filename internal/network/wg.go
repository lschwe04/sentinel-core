// sentinel-core: internal/network/wg.go
package network

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
)

type WireGuardManager struct {
	mu     sync.RWMutex
	peers  map[string]string // NodeID -> Peer IP
	subnet *net.IPNet
}

func NewWireGuardManager(cidr string) (*WireGuardManager, error) {
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("ungültiges WireGuard-CIDR: %w", err)
	}

	return &WireGuardManager{
		peers:  make(map[string]string),
		subnet: subnet,
	}, nil
}

// ValidateVPNConnection prüft strikt, ob ein Agent aus dem autorisierten Overlay-Netzwerk kommuniziert
func (wm *WireGuardManager) ValidateVPNConnection(remoteAddr string) error {
	ipStr, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ipStr = remoteAddr
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		slog.Error("Sicherheitswarnung: Ungültiges IP-Format bei VPN-Verbindung", "addr", remoteAddr)
		return errors.New("invalid IP format")
	}

	if !wm.subnet.Contains(ip) {
		slog.Warn("Sicherheitsverletzung: Zugriff von außerhalb des vertrauenswürdigen WireGuard-Subnetzes blockiert", "ip", ipStr)
		return errors.New("ip outside trusted vpn range")
	}

	return nil
}
