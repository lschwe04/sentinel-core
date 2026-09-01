package network

import (
	"errors"
	"log/slog"
	"net"
)

// ValidateInterface prüft, ob die eingehende IP-Adresse zum erlaubten VPN-Subnetz gehört
func ValidateVPNConnection(remoteAddr string) error {
	ipStr, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return err
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return errors.New("invalid IP format")
	}

	// Das strikte WireGuard Subnetz des Hubs (z.B. 10.0.0.0/24)
	_, vpnNet, _ := net.ParseCIDR("10.0.0.0/24")

	if !vpnNet.Contains(ip) {
		slog.Warn("Zugriff von nicht autorisiertem Netzwerk blockiert", "ip", ipStr)
		return errors.New("access denied: request not from wireguard interface")
	}

	return nil
}
