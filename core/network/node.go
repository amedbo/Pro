package network

import "time"

// LocationCoordinates defines the geographical location of a node.
type LocationCoordinates struct {
	Latitude  float64
	Longitude float64
	Country   string
	City      string
}

// NetworkNode represents a single node (entry, middle, or exit) in the VPN network.
// Its properties are used by the SmartRouter to calculate optimal paths.
type NetworkNode struct {
	ID          string
	Address     string // IP:Port
	PublicKey   []byte // Node's public key for encryption
	Location    LocationCoordinates
	LastSeen    time.Time
	IsOnline    bool

	// Performance and security metrics (to be updated dynamically)
	Latency     time.Duration // Measured latency
	Bandwidth   float64       // Mbps
	Reputation  float64       // Score from 0.0 to 1.0
	Reliability float64       // Uptime score from 0.0 to 1.0
}
