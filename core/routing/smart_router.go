// core/routing/smart_router.go
package routing

import (
	"math"
	"sort"
	"sync"
	"time"
)

type NetworkNode struct {
	ID              string
	Latency         time.Duration
	Bandwidth       float64 // Mbps
	Reliability     float64 // Between 0 and 1
	Load            float64 // Between 0 and 1
	Location        LocationCoordinates
	Cost            float64 // Usage cost
	EncryptionLevel int
	Reputation      float64
	LastUpdated     time.Time
}

type LocationCoordinates struct {
	Latitude  float64
	Longitude float64
	Country   string
	City      string
}

type SmartRouter struct {
	Nodes           []NetworkNode
	Weights         RoutingWeights
	History         RoutingHistory
	AIModel         AIModelInterface
	mutex           sync.RWMutex
	updateInterval  time.Duration
}

type RoutingWeights struct {
	LatencyWeight     float64
	BandwidthWeight   float64
	ReliabilityWeight float64
	LoadWeight        float64
	CostWeight        float64
	DistanceWeight    float64
	ReputationWeight  float64
}

type RoutingHistory struct {
	NodePerformance map[string]NodePerformanceStats
	RouteSuccess    map[string]float64 // Route hash to success rate
}

type NodePerformanceStats struct {
	SuccessCount int
	FailureCount int
	TotalLatency time.Duration
	LastUsed     time.Time
}

func NewSmartRouter(nodes []NetworkNode, updateInterval time.Duration) *SmartRouter {
	router := &SmartRouter{
		Nodes:          nodes,
		updateInterval: updateInterval,
		Weights: RoutingWeights{
			LatencyWeight:     0.25,
			BandwidthWeight:   0.20,
			ReliabilityWeight: 0.15,
			LoadWeight:        0.10,
			CostWeight:        0.10,
			DistanceWeight:    0.10,
			ReputationWeight:  0.10,
		},
		History: RoutingHistory{
			NodePerformance: make(map[string]NodePerformanceStats),
			RouteSuccess:    make(map[string]float64),
		},
	}

	// Start background node monitoring
	go router.monitorNodes()

	return router
}

func (sr *SmartRouter) monitorNodes() {
	ticker := time.NewTicker(sr.updateInterval)
	defer ticker.Stop()

	for range ticker.C {
		sr.updateNodeStats()
	}
}

func (sr *SmartRouter) updateNodeStats() {
	sr.mutex.Lock()
	defer sr.mutex.Unlock()

	// Update node statistics based on recent performance
	for i := range sr.Nodes {
		node := &sr.Nodes[i]
		stats, exists := sr.History.NodePerformance[node.ID]

		if exists {
			// Calculate updated reputation based on performance
			totalAttempts := stats.SuccessCount + stats.FailureCount
			if totalAttempts > 0 {
				successRate := float64(stats.SuccessCount) / float64(totalAttempts)

				// Update reputation with decay factor for older data
				node.Reputation = 0.7*node.Reputation + 0.3*successRate

				// Update reliability based on historical performance
				node.Reliability = 0.8*node.Reliability + 0.2*successRate
			}
		}

		// Simulate load changes (in real implementation, would get from node)
		node.Load = math.Min(1.0, node.Load+0.1*(math.Sin(float64(time.Now().Unix())/1000)+1)/2)
	}
}

func (sr *SmartRouter) CalculateNodeScore(node NetworkNode, destination LocationCoordinates, requirements RouteRequirements) float64 {
	// Calculate geographical distance
	distance := calculateDistance(node.Location, destination)

	// Normalize values
	latencyScore := 1.0 - math.Min(node.Latency.Seconds()/requirements.MaxLatency.Seconds(), 1.0)
	bandwidthScore := math.Min(node.Bandwidth/requirements.MinBandwidth, 1.0)
	reliabilityScore := node.Reliability
	loadScore := 1.0 - node.Load
	costScore := 1.0 - math.Min(node.Cost/requirements.MaxCost, 1.0)
	distanceScore := 1.0 - math.Min(distance/requirements.MaxDistance, 1.0)
	reputationScore := node.Reputation

	// Apply AI-predicted performance boost if available
	if sr.AIModel != nil {
		aiBoost := sr.AIModel.PredictNodePerformance(node.ID)
		reliabilityScore = math.Min(1.0, reliabilityScore+aiBoost)
	}

	// Calculate weighted score
	score := latencyScore*sr.Weights.LatencyWeight +
		bandwidthScore*sr.Weights.BandwidthWeight +
		reliabilityScore*sr.Weights.ReliabilityWeight +
		loadScore*sr.Weights.LoadWeight +
		costScore*sr.Weights.CostWeight +
		distanceScore*sr.Weights.DistanceWeight +
		reputationScore*sr.Weights.ReputationWeight

	return score
}

func (sr *SmartRouter) FindOptimalPath(source, destination LocationCoordinates, requirements RouteRequirements) []NetworkNode {
	sr.mutex.RLock()
	defer sr.mutex.RUnlock()

	scoredNodes := make([]struct {
		Node  NetworkNode
		Score float64
	}, len(sr.Nodes))

	// Score all nodes
	for i, node := range sr.Nodes {
		score := sr.CalculateNodeScore(node, destination, requirements)
		scoredNodes[i] = struct {
			Node  NetworkNode
			Score float64
		}{node, score}
	}

	// Sort nodes by score
	sort.Slice(scoredNodes, func(i, j int) bool {
		return scoredNodes[i].Score > scoredNodes[j].Score
	})

	// Select optimal nodes for the path
	path := make([]NetworkNode, 0)
	selectedCount := 0
	minNodes := int(math.Min(3, float64(len(scoredNodes))))
	maxNodes := int(math.Min(6, float64(len(scoredNodes))))

	for i := 0; i < len(scoredNodes) && selectedCount < maxNodes; i++ {
		node := scoredNodes[i].Node

		// Apply additional constraints
		if node.EncryptionLevel >= requirements.MinEncryptionLevel &&
			node.Location.Country != requirements.BlockedCountries {

			path = append(path, node)
			selectedCount++

			// Ensure we have at least the minimum number of nodes
			if selectedCount >= minNodes && requirements.OptimizeForSpeed {
				break
			}
		}
	}

	return path
}

func calculateDistance(loc1, loc2 LocationCoordinates) float64 {
	// Haversine formula to calculate distance between coordinates
	const R = 6371 // Earth radius in kilometers
	lat1 := loc1.Latitude * math.Pi / 180
	lat2 := loc2.Latitude * math.Pi / 180
	deltaLat := (loc2.Latitude - loc1.Latitude) * math.Pi / 180
	deltaLon := (loc2.Longitude - loc1.Longitude) * math.Pi / 180

	a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
		math.Cos(lat1)*math.Cos(lat2)*
		math.Sin(deltaLon/2)*math.Sin(deltaLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return R * c
}

type RouteRequirements struct {
	MaxLatency         time.Duration
	MinBandwidth       float64
	MaxCost            float64
	MaxDistance        float64
	MinEncryptionLevel int
	BlockedCountries   string
	OptimizeForSpeed   bool
	OptimizeForPrivacy bool
}
