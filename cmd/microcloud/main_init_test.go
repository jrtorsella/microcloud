package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"testing"

	lxdAPI "github.com/canonical/lxd/shared/api"

	"github.com/canonical/microcloud/microcloud/api/types"
	"github.com/canonical/microcloud/microcloud/multicast"
	"github.com/canonical/microcloud/microcloud/service"
)

func newSystemWithNetworks(address string, networks []lxdAPI.NetworksPost) InitSystem {
	return InitSystem{
		ServerInfo: multicast.ServerInfo{
			Name:    "testSystem",
			Address: address,
		},
		Networks: networks,
	}
}

func newSystemWithUplinkNetConfig(address string, config map[string]string) InitSystem {
	return newSystemWithNetworks(address, []lxdAPI.NetworksPost{{
		Name: service.DefaultUplinkNetwork,
		Type: "physical",
		NetworkPut: lxdAPI.NetworkPut{
			Config: config,
		},
	}})
}

func newTestHandler(addr string, t *testing.T) *service.Handler {
	handler, err := service.NewHandler("testSystem", addr, "/tmp/microcloud_test_hander")
	if err != nil {
		t.Fatalf("Failed to create test service handler: %s", err)
	}

	return handler
}

func newTestSystemsMap(systems ...InitSystem) map[string]InitSystem {
	systemsMap := map[string]InitSystem{}

	for _, system := range systems {
		systemsMap[system.ServerInfo.Name] = system
	}

	return systemsMap
}

func ensureValidateSystemsPasses(handler *service.Handler, testSystems map[string]InitSystem, t *testing.T) {
	for testName, system := range testSystems {
		systems := newTestSystemsMap(system)
		cfg := initConfig{systems: systems, bootstrap: true}

		err := cfg.validateSystems(handler)
		if err != nil {
			t.Fatalf("Valid system %q failed validate: %s", testName, err)
		}
	}
}

func ensureValidateSystemsFails(handler *service.Handler, testSystems map[string]InitSystem, t *testing.T) {
	for testName, system := range testSystems {
		systems := newTestSystemsMap(system)
		cfg := initConfig{systems: systems, bootstrap: true}

		err := cfg.validateSystems(handler)
		if err == nil {
			t.Fatalf("Invalid system %q passed validation", testName)
		}
	}
}

func TestValidateSystemsIP4(t *testing.T) {
	address := "192.168.1.27"
	handler := newTestHandler(address, t)

	// Each entry in these maps is validated individually
	validSystems := map[string]InitSystem{
		"plainGateway": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv4.gateway": "10.234.0.1/16",
		}),
		"dns": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv4.gateway":    "10.234.0.1/16",
			"dns.nameservers": "1.1.1.1,8.8.8.8",
		}),
		"16Net": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv4.gateway":    "10.42.0.1/16",
			"ipv4.ovn.ranges": "10.42.1.1-10.42.5.255",
		}),
		"24Net": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv4.gateway":    "190.168.4.1/24",
			"ipv4.ovn.ranges": "190.168.4.50-190.168.4.60",
		}),
	}

	ensureValidateSystemsPasses(handler, validSystems, t)

	invalidSystems := map[string]InitSystem{
		"invalidNameservers1": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv4.gateway":    "10.234.0.1/16",
			"dns.nameservers": "8.8",
		}),
		"invalidNameservers2": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv4.gateway":    "10.234.0.1/16",
			"dns.nameservers": "8.8.8.128/23",
		}),
		"gatewayIsSubnetAddr": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv4.gateway": "192.168.28.0/24",
		}),
		"backwardsRange": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv4.gateway":    "10.42.0.1/16",
			"ipv4.ovn.ranges": "10.42.5.255-10.42.1.1",
		}),
		"rangesOutsideGateway": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv4.gateway":    "10.1.1.0/24",
			"ipv4.ovn.ranges": "10.2.2.50-10.2.2.100",
		}),
		"rangesContainGateway": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv4.gateway":    "192.168.1.1/24",
			"ipv4.ovn.ranges": "192.168.1.1-192.168.1.20",
		}),
		"rangesContainSystem": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv4.gateway":    "192.168.1.1/16",
			"ipv4.ovn.ranges": "192.168.1.20-192.168.1.30",
		}),
	}

	ensureValidateSystemsFails(handler, invalidSystems, t)
}

func TestValidateSystemsIP6(t *testing.T) {
	address := "fc00:feed:beef::bed1"
	handler := newTestHandler(address, t)

	validSystems := map[string]InitSystem{
		"plainGateway": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv6.gateway": "fc00:bad:feed::1/64",
		}),
		"dns": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv6.gateway":    "fc00:feed:f00d::1/64",
			"dns.nameservers": "2001:4860:4860::8888,2001:4860:4860::8844",
		}),
		"dnsMulti": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv6.gateway":    "fc00:feed:f00d::1/64",
			"dns.nameservers": "2001:4860:4860::8888,1.1.1.1",
		}),
		"64Net": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv6.gateway":    "fc00:bad:feed::1/64",
			"ipv6.ovn.ranges": "fc00:bad:feed::f-fc00:bad:feed::fffe",
		}),
	}

	ensureValidateSystemsPasses(handler, validSystems, t)

	invalidSystems := map[string]InitSystem{
		"invalidNameservers1": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv6.gateway":    "fc00:feed:f00d::1/64",
			"dns.nameservers": "8:8",
		}),
		"invalidNameservers2": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv6.gateway":    "fc00:feed:f00d::1/64",
			"dns.nameservers": "2001:4860:4860::8888/32",
		}),
		"gatewayIsSubnetAddr": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv6.gateway": "fc00:feed:f00d::0/64",
		}),
		"rangesOutsideGateway": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv6.gateway":    "fc00:feed:f00d::1/64",
			"ipv6.ovn.ranges": "fc00:feed:beef::f-fc00:feed:beef::fffe",
		}),
		"rangesContainGateway": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv6.gateway":    "fc00:feed:f00d::1/64",
			"ipv6.ovn.ranges": "fc00:feed:f00d::1-fc00:feed:f00d::ff",
		}),
		"rangesContainSystem": newSystemWithUplinkNetConfig(address, map[string]string{
			"ipv6.gateway":    "fc00:feed:beef::1/64",
			"ipv6.ovn.ranges": "fc00:feed:beef::bed1-fc00:feed:beef::bedf",
		}),
	}

	ensureValidateSystemsFails(handler, invalidSystems, t)
}

func TestValidateSystemsMultiSystem(t *testing.T) {
	localAddr := "10.23.1.20"
	handler := newTestHandler(localAddr, t)

	uplinkConfig := map[string]string{
		"ipv4.gateway":    "10.23.1.1/16",
		"ipv4.ovn.ranges": "10.23.1.50-10.23.1.100",
	}

	sys1 := newSystemWithUplinkNetConfig(localAddr, uplinkConfig)

	sys2 := newSystemWithUplinkNetConfig("10.23.1.72", uplinkConfig)
	sys2.ServerInfo.Name = "sys2"

	systems := newTestSystemsMap(sys1, sys2)
	cfg := initConfig{systems: systems, bootstrap: true}

	err := cfg.validateSystems(handler)
	if err == nil {
		t.Fatalf("sys2 with conflicting management IP and ipv4.ovn.ranges passed validation")
	}

	localAddr = "fc00:bad:feed::f00d"
	handler = newTestHandler(localAddr, t)

	uplinkConfig = map[string]string{
		"ipv6.gateway":    "fc00:bad:feed::1/64",
		"ipv6.ovn.ranges": "fc00:bad:feed::1-fc00:bad:feed::ff",
	}

	sys3 := newSystemWithUplinkNetConfig(localAddr, uplinkConfig)

	sys4 := newSystemWithUplinkNetConfig("fc00:bad:feed::60", uplinkConfig)
	sys4.ServerInfo.Name = "sys4"

	systems = newTestSystemsMap(sys3, sys4)
	cfg = initConfig{systems: systems, bootstrap: true}

	err = cfg.validateSystems(handler)
	if err == nil {
		t.Fatalf("sys4 with conflicting management IP and ipv6.ovn.ranges passed validation")
	}
}

// tokenTestService is a service that records the tokens it issues.
type tokenTestService struct {
	service.Service

	serviceType types.ServiceType
	issue       func(serviceType types.ServiceType, peer string)
}

func (s *tokenTestService) Type() types.ServiceType {
	return s.serviceType
}

func (s *tokenTestService) IssueToken(ctx context.Context, peer string) (string, error) {
	s.issue(s.serviceType, peer)
	return fmt.Sprintf("%s-%s", s.serviceType, peer), nil
}

func TestAddPeersIssuesTokensBeforeEachJoin(t *testing.T) {
	serviceTypes := []types.ServiceType{types.MicroCloud, types.LXD, types.MicroCeph, types.MicroOVN}
	peers := []string{"peer1", "peer2", "peer3", "peer4", "peer5"}

	mu := sync.Mutex{}
	issued := map[string]int{}
	joined := map[string]bool{}

	handler := &service.Handler{Name: "local", Services: map[types.ServiceType]service.Service{}}
	for _, serviceType := range serviceTypes {
		handler.Services[serviceType] = &tokenTestService{
			serviceType: serviceType,
			issue: func(serviceType types.ServiceType, peer string) {
				mu.Lock()
				defer mu.Unlock()

				if joined[peer] {
					t.Errorf("Issued %s token for peer %q after it joined", serviceType, peer)
				}

				issued[peer]++
			},
		}
	}

	// The local system has bootstrapped every service, and the peers have already joined MicroCloud.
	localServices := map[types.ServiceType]map[string]string{}
	for _, serviceType := range serviceTypes {
		localServices[serviceType] = map[string]string{"local": "10.0.0.1"}
	}

	cfg := initConfig{
		systems: map[string]InitSystem{"local": {ServerInfo: multicast.ServerInfo{Name: "local", Address: "10.0.0.1"}}},
		state:   map[string]service.SystemInformation{"local": {ExistingServices: localServices}},
	}

	for i, peer := range peers {
		address := fmt.Sprintf("10.0.0.%d", i+2)
		localServices[types.MicroCloud][peer] = address
		cfg.systems[peer] = InitSystem{ServerInfo: multicast.ServerInfo{Name: peer, Address: address}}
	}

	oldJoinPeer := joinPeer
	t.Cleanup(func() { joinPeer = oldJoinPeer })
	joinPeer = func(sh *service.Handler, clusterSizes map[types.ServiceType]int, peer string, cert *x509.Certificate, cfg types.ServicesPut) error {
		mu.Lock()
		defer mu.Unlock()

		if len(cfg.Tokens) != len(serviceTypes)-1 {
			t.Errorf("Peer %q joined with %d tokens, expected %d", peer, len(cfg.Tokens), len(serviceTypes)-1)
		}

		// Only the joining peer and the peers that already joined may have tokens.
		for tokenPeer := range issued {
			if tokenPeer != peer && !joined[tokenPeer] {
				t.Errorf("Token for peer %q was issued before peer %q joined", tokenPeer, peer)
			}
		}

		joined[peer] = true
		return nil
	}

	_, err := cfg.addPeers(handler)
	if err != nil {
		t.Fatalf("Failed to add peers: %v", err)
	}

	for _, peer := range peers {
		if !joined[peer] {
			t.Errorf("Peer %q did not join", peer)
		}

		if issued[peer] != len(serviceTypes)-1 {
			t.Errorf("Issued %d tokens for peer %q, expected %d", issued[peer], peer, len(serviceTypes)-1)
		}
	}

	if joined["local"] || issued["local"] != 0 {
		t.Errorf("Local system should not join or receive tokens")
	}
}
