package tunnel

import (
	"strconv"
	"strings"
	"sync"
	"time"

	C "github.com/Dreamacro/clash/constant"
)

type RouteDecision struct {
	ID                 string    `json:"id"`
	Network            string    `json:"network"`
	Source             string    `json:"source"`
	Host               string    `json:"host"`
	SniffHost          string    `json:"sniffHost,omitempty"`
	DestinationIP      string    `json:"destinationIP"`
	DestinationPort    int       `json:"destinationPort,omitempty"`
	DestinationIPASN   string    `json:"destinationIPASN,omitempty"`
	MatchedRule        string    `json:"matchedRule"`
	MatchedRulePayload string    `json:"matchedRulePayload,omitempty"`
	MatchedRuleKind    string    `json:"matchedRuleKind"`
	SelectedProxy      string    `json:"selectedProxy"`
	ChainComponents    []string  `json:"chainComponents"`
	FinalNode          string    `json:"finalNode"`
	DNSMode            string    `json:"dnsMode"`
	Outcome            string    `json:"outcome"`
	Upload             int64     `json:"upload"`
	Download           int64     `json:"download"`
	CreatedAt          time.Time `json:"createdAt"`
}

var routeDecisionStore = struct {
	sync.RWMutex
	next  int
	items []RouteDecision
}{
	items: nil,
}

func RouteDecisions() []RouteDecision {
	routeDecisionStore.RLock()
	defer routeDecisionStore.RUnlock()

	if len(routeDecisionStore.items) == 0 {
		return nil
	}

	decisions := make([]RouteDecision, 0, len(routeDecisionStore.items))
	capacity := cap(routeDecisionStore.items)
	if len(routeDecisionStore.items) < capacity {
		for i := len(routeDecisionStore.items) - 1; i >= 0; i-- {
			decisions = append(decisions, routeDecisionStore.items[i])
		}
		return decisions
	}

	for offset := 0; offset < len(routeDecisionStore.items); offset++ {
		index := (routeDecisionStore.next - 1 - offset + len(routeDecisionStore.items)) % len(routeDecisionStore.items)
		decisions = append(decisions, routeDecisionStore.items[index])
	}
	return decisions
}

func recordRouteDecision(
	network string,
	metadata *C.Metadata,
	rule C.Rule,
	proxy C.Proxy,
	chain C.Chain,
	upload int64,
	download int64,
) {
	if metadata == nil {
		return
	}

	components := normalizedRouteChain(chain)
	decision := RouteDecision{
		ID:                 routeDecisionID(network, metadata),
		Network:            strings.ToLower(network),
		Source:             metadata.SourceDetail(),
		Host:               routeDecisionHost(metadata),
		SniffHost:          strings.TrimSpace(metadata.SniffHost),
		DestinationIP:      routeDecisionDestinationIP(metadata),
		DestinationPort:    routeDecisionPort(metadata.DstPort),
		DestinationIPASN:   strings.TrimSpace(metadata.DstASNLabel),
		MatchedRule:        routeDecisionRule(rule),
		MatchedRulePayload: routeDecisionRulePayload(rule),
		MatchedRuleKind:    routeDecisionRuleKind(rule),
		SelectedProxy:      routeDecisionProxyName(proxy),
		ChainComponents:    components,
		FinalNode:          routeDecisionFinalNode(components, proxy),
		DNSMode:            metadata.DNSMode.String(),
		Upload:             upload,
		Download:           download,
		CreatedAt:          time.Now(),
	}
	decision.Outcome = routeDecisionOutcome(decision.FinalNode, components)

	routeDecisionStore.Lock()
	defer routeDecisionStore.Unlock()

	ensureRouteDecisionStoreLocked()
	capacity := cap(routeDecisionStore.items)
	if capacity <= 0 {
		return
	}
	if len(routeDecisionStore.items) < capacity {
		routeDecisionStore.items = append(routeDecisionStore.items, decision)
		routeDecisionStore.next = len(routeDecisionStore.items) % capacity
		return
	}

	routeDecisionStore.items[routeDecisionStore.next] = decision
	routeDecisionStore.next = (routeDecisionStore.next + 1) % capacity
}

func ensureRouteDecisionStoreLocked() {
	if cap(routeDecisionStore.items) > 0 {
		return
	}
	routeDecisionStore.items = make([]RouteDecision, 0, routeDecisionCapacity())
}

func routeDecisionCapacity() int {
	capacity := cap(tcpQueue)
	if udpCapacity := cap(udpQueue); udpCapacity > capacity {
		capacity = udpCapacity
	}
	return capacity
}

func normalizedRouteChain(chain C.Chain) []string {
	components := make([]string, 0, len(chain))
	seen := map[string]struct{}{}
	for _, rawComponent := range chain {
		component := strings.TrimSpace(rawComponent)
		if component == "" || strings.EqualFold(component, "unknown") {
			continue
		}
		key := strings.ToLower(component)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		components = append(components, component)
	}
	return components
}

func routeDecisionID(network string, metadata *C.Metadata) string {
	parts := []string{
		strings.ToLower(network),
		metadata.SourceAddress(),
		metadata.RemoteAddress(),
		metadata.RuleHost(),
		strconv.FormatInt(time.Now().UnixNano(), 10),
	}
	return strings.Join(parts, "|")
}

func routeDecisionHost(metadata *C.Metadata) string {
	for _, candidate := range []string{
		metadata.SniffHost,
		metadata.Host,
		metadata.RemoteAddress(),
	} {
		trimmed := strings.TrimSpace(candidate)
		if trimmed != "" && !strings.EqualFold(trimmed, "unknown") {
			return trimmed
		}
	}
	return "Pending route"
}

func routeDecisionDestinationIP(metadata *C.Metadata) string {
	if metadata.DstIP.IsValid() {
		return metadata.DstIP.String()
	}
	return ""
}

func routeDecisionPort(port string) int {
	if port == "" {
		return 0
	}
	value, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return value
}

func routeDecisionRule(rule C.Rule) string {
	if rule == nil {
		return "MATCH"
	}
	name := strings.TrimSpace(rule.RuleType().String())
	if name == "" || strings.EqualFold(name, "unknown") {
		return "MATCH"
	}
	return name
}

func routeDecisionRulePayload(rule C.Rule) string {
	if rule == nil {
		return ""
	}
	return strings.TrimSpace(rule.Payload())
}

func routeDecisionRuleKind(rule C.Rule) string {
	return strings.ToLower(strings.ReplaceAll(routeDecisionRule(rule), "-", ""))
}

func routeDecisionProxyName(proxy C.Proxy) string {
	if proxy == nil {
		return "DIRECT"
	}
	name := strings.TrimSpace(proxy.Name())
	if name == "" {
		return "DIRECT"
	}
	return name
}

func routeDecisionFinalNode(components []string, proxy C.Proxy) string {
	for _, component := range components {
		if !strings.EqualFold(component, "DIRECT") && !strings.EqualFold(component, "REJECT") {
			return component
		}
	}
	if len(components) > 0 {
		return components[0]
	}
	return routeDecisionProxyName(proxy)
}

func routeDecisionOutcome(finalNode string, components []string) string {
	if len(components) == 0 {
		return "unknown"
	}
	for _, component := range components {
		if !strings.EqualFold(component, "DIRECT") {
			return "ruleHit"
		}
	}
	if strings.EqualFold(finalNode, "DIRECT") {
		return "direct"
	}
	return "unknown"
}
