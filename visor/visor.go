package visor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/trafficstars/registry"
)

const (
	defaultDockerHost       = "unix:///var/run/docker.sock"
	defaultDockerAPIVersion = "1.24"
	defaultRegistryDSN      = "http://127.0.0.1:8500?dc=dc1&refresh_interval=5"
)

var hostname, _ = os.Hostname()

// Run new docker visor observer
func Run() {
	client, err := client.NewClient(
		env("DOCKER_HOST", defaultDockerHost),
		env("DOCKER_API_VERSION", defaultDockerAPIVersion),
		nil,
		nil,
	)

	if err != nil {
		log.Fatal(err)
	}

	registryURL := env("REGISTRY_DSN", defaultRegistryDSN)
	registry, err := registry.New(registryURL, []string{})
	if err != nil {
		log.Fatal(err)
	}

	info, err := client.Info(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	(&visor{
		info:      info,
		docker:    client,
		discovery: registry.Discovery(),
	}).run()
}

type Stats struct {
	CPUUsage    float64
	MemoryUsage uint64
	MemoryLimit uint64
}

type visor struct {
	info       types.Info
	mutex      sync.RWMutex
	docker     *client.Client
	discovery  registry.Discovery
	inProgress bool
}

func (s *visor) refresh() {
	if s.isInProgress() {
		return
	}

	s.setInProgress(true)
	defer s.setInProgress(false)

	hostIP := os.Getenv("HOST_IP")
	services, err := s.discovery.Lookup(&registry.Filter{Tags: []string{"HOST_IP=" + hostIP}})
	if err != nil {
		log.Errorf("Discovery get list of the services on HOST_IP=%s: %v", hostIP, err)
	}

	containers, err := s.docker.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		log.Errorf("Refresh services (container list): %v", err)
		return
	}

	// Refresh registration of exists services
	for _, container := range containers {
		log.Infof("Refresh container: %s", container.ID[:12])
		if err := s.serviceRegister(container.ID); err != nil {
			log.Errorf("Register service [%s]: %v", container.ID[:12], err)
		}
	}

	// Deregister unexisted services on this HOST
cleanLoop:
	for _, srv := range services {
		for _, container := range containers {
			if container.ID == srv.ID {
				continue cleanLoop
			}
		}

		log.Infof("Deregister container: %s", srv.ID[:12])
		if err := s.discovery.Deregister(srv.ID); err != nil {
			log.Errorf("Deregister container [%s]: %v", srv.ID[:12], err)
		}
	}
}

// containerStats collects base metrics of the container (CPU, Memory usage)
func (s *visor) containerStats(containerID string) (Stats, error) {
	var (
		stats         types.Stats
		response, err = s.docker.ContainerStats(context.Background(), containerID, false)
	)

	if err != nil {
		return Stats{}, err
	}

	if err := json.NewDecoder(response.Body).Decode(&stats); err != nil {
		return Stats{}, err
	}

	var (
		cpuUsage    float64
		cpuDelta    = float64(stats.CPUStats.CPUUsage.TotalUsage) - float64(stats.PreCPUStats.CPUUsage.TotalUsage)
		systemDelta = float64(stats.CPUStats.SystemUsage) - float64(stats.PreCPUStats.SystemUsage)
	)

	if systemDelta > 0.0 && cpuDelta > 0.0 {
		cpuUsage = (cpuDelta / systemDelta) * float64(len(stats.CPUStats.CPUUsage.PercpuUsage)) * 100.0
	}

	return Stats{
		CPUUsage:    cpuUsage,
		MemoryUsage: stats.MemoryStats.Usage,
		MemoryLimit: stats.MemoryStats.Limit,
	}, nil
}

// serviceRegister in consul if docker container have correct environment
// ENV SERVICE_NAME=... required
// ENV SERVICE_PORT=port optional
func (s *visor) serviceRegister(containerID string) error {
	container, err := s.docker.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return err
	}

	if container.State.Status != "running" {
		log.Debugf("Container [%s] is not running", containerID[:12])
		return nil
	}

	var (
		name    string
		tags    []string
		port    string
		address string
		hostIP  = os.Getenv("HOST_IP")
	)

	for _, env := range container.Config.Env {
		switch {
		case strings.HasPrefix(env, "SERVICE_NAME="):
			name = strings.TrimPrefix(env, "SERVICE_NAME=")
		case strings.HasPrefix(env, "SERVICE_PORT="):
			port = strings.TrimPrefix(env, "SERVICE_PORT=")
		case strings.HasPrefix(env, "TAG_"): // Custom service tags
			tags = append(tags, strings.TrimPrefix(env, "TAG_"))
		}
	}

	if len(name) == 0 {
		log.Debugf("Container [%s] is not the service", containerID[:12])
		return nil
	}

	stats, err := s.containerStats(containerID)
	if err != nil {
		return err
	}

	// Grab service hostIP and port
	for _, mapping := range container.NetworkSettings.Ports {
		if len(mapping) != 0 {
			host := hostIP
			if len(mapping[0].HostIP) != 0 && mapping[0].HostIP != "0.0.0.0" {
				host = mapping[0].HostIP
			}
			if port == "" {
				// If we haven't custom port
				port = mapping[0].HostPort
			}
			address = net.JoinHostPort(host, port)
			break
		}
	}

	if address == "" {
		address = net.JoinHostPort(hostIP, port)
	}

	tags = append(tags,
		fmt.Sprintf("HOST_IP=%s", hostIP),
		fmt.Sprintf("CPU_USAGE=%f", stats.CPUUsage),
		fmt.Sprintf("NUMCPU=%d", runtime.NumCPU()),
		fmt.Sprintf("MEMORY_USAGE=%f", (float64(stats.MemoryUsage)/float64(stats.MemoryLimit))*100),
		fmt.Sprintf("MEMORY_LIMIT=%d", stats.MemoryLimit),
		fmt.Sprintf("MEMORY_TOTAL=%d", s.info.MemTotal),
		fmt.Sprintf("PORT_MAP=%s", toJSON(container.NetworkSettings.Ports)),
		fmt.Sprintf("REGISTRY=%s", hostname),
	)

	return s.discovery.Register(registry.ServiceOptions{
		ID:      container.ID,
		Name:    name,
		Address: address,
		Tags:    tags,
		Check:   checkOptions(address, container.Config.Env),
	})
}

func (s *visor) api() {
	http.HandleFunc("/api/v1/check", s.healthCheck)
	http.HandleFunc("/api/v1/unregister", s.unregisterService)
	http.HandleFunc("/api/v1/sanitize", s.sanitizeService)
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func (s *visor) setInProgress(status bool) {
	s.mutex.Lock()
	s.inProgress = status
	s.mutex.Unlock()
}

func (s *visor) isInProgress() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.inProgress
}

func (s *visor) run() {
	var (
		tick           = time.Tick(30 * time.Second)
		events, errors = s.docker.Events(context.Background(), types.EventsOptions{})
	)

	log.Info("Run visor")
	s.refresh()
	go s.api()

	for {
		select {
		case event := <-events:
			switch event.Action {
			case "start", "unpause", "refresh", "resumed":
				log.Infof("Register new service [%s]: %s", event.Action, event.Actor.ID[:12])

				if err := s.serviceRegister(event.Actor.ID); err != nil {
					log.Errorf("Register service [%s]: %s (%v)", event.Action, event.Actor.ID[:12], err)
				}
			case "die", "kill", "stop", "pause", "paused", "oom":
				log.Infof("Deregister service [%s]: %s (%v)", event.Action, event.Actor.ID[:12], event.Actor.Attributes)

				if err := s.discovery.Deregister(event.Actor.ID); err != nil {
					log.Errorf("Deregister service [%s]: %v", event.Action, err)
				}
			default:
				log.Infof("Service unsupported event [%s]: %s (%v)", event.Action, event.Actor.ID[:12], event.Actor.Attributes)
			}
		case error := <-errors:
			log.Errorf("Event: %v", error)
		case <-tick:
			go s.refresh()
		}
	}
}

func (s *visor) healthCheck(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(rw)
	encoder.SetIndent("", "    ")
	if info, err := s.docker.Info(context.Background()); err == nil {
		encoder.Encode(map[string]interface{}{
			"ID":                info.ID,
			"Gorutines":         runtime.NumGoroutine(),
			"Containers":        info.Containers,
			"ContainersRunning": info.ContainersRunning,
			"ContainersPaused":  info.ContainersPaused,
			"ContainersStopped": info.ContainersStopped,
			"Images":            info.Images,
			"SystemTime":        info.SystemTime,
			"KernelVersion":     info.KernelVersion,
			"OperatingSystem":   info.OperatingSystem,
			"NCPU":              info.NCPU,
			"MemTotal":          info.MemTotal,
		})
		return
	}
	encoder.Encode(map[string]interface{}{
		"Gorutines": runtime.NumGoroutine(),
	})
}

func (s *visor) unregisterService(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")

	var (
		encoder     = json.NewEncoder(rw)
		serviceName = req.URL.Query().Get("service")
		servs, err  = s.discovery.Lookup(&registry.Filter{Service: serviceName})
		log         = log.WithFields(log.Fields{"action": "unregister", "service": serviceName})
	)

	if serviceName == "" {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(map[string]interface{}{"result": "error", "error": `"service" param is empty`})
		return
	}

	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(map[string]interface{}{"result": "error", "error": err.Error()})
		return
	}

	for _, srv := range servs {
		lg := log.WithField("id", srv.ID)
		if err := s.discovery.Deregister(srv.ID); err != nil {
			lg.WithError(err).Error("unregister error")
		} else {
			lg.Info("service deregistered")
		}
	}

	rw.WriteHeader(http.StatusOK)
	encoder.Encode(map[string]interface{}{"result": "ok", "services": servs})
}

func (s *visor) sanitizeService(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")

	var (
		encoder       = json.NewEncoder(rw)
		serviceName   = req.URL.Query().Get("service")
		servs, err    = s.discovery.Lookup(&registry.Filter{Service: serviceName})
		uneregistered []registry.Service
		active        []registry.Service
		log           = log.WithFields(log.Fields{"action": "sanitize", "service": serviceName})
	)

	if serviceName == "" {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(map[string]interface{}{"result": "error", "error": `"service" param is empty`})
		return
	}

	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		encoder.Encode(map[string]interface{}{"result": "error", "error": err})
		return
	}

	for _, srv := range servs {
		if srv.Status != registry.SERVICE_STATUS_PASSING {
			lg := log.WithField("id", srv.ID)
			if err := s.discovery.Deregister(srv.ID); err != nil {
				lg.WithError(err).Error("invalid deregestration")
			} else {
				lg.Info("service deregistered")
			}
			uneregistered = append(uneregistered, srv)
		} else {
			active = append(active, srv)
		}
	}

	rw.WriteHeader(http.StatusOK)
	encoder.Encode(map[string]interface{}{"result": "ok", "services": servs, "unregistered": uneregistered, "active": active})
}

func checkOptions(address string, env []string) registry.CheckOptions {
	options := registry.CheckOptions{
		Interval: "5s",
		Timeout:  "2s",
	}
	for _, e := range env {
		switch {
		case strings.HasPrefix(e, "CHECK_INTERVAL="):
			options.Interval = strings.TrimPrefix(e, "CHECK_INTERVAL=")
		case strings.HasPrefix(e, "CHECK_TIMEOUT="):
			options.Timeout = strings.TrimPrefix(e, "CHECK_TIMEOUT=")
		case strings.HasPrefix(e, "CHECK_HTTP="):
			options.HTTP = strings.Replace(strings.TrimPrefix(e, "CHECK_HTTP="), "{{address}}", address, 1)
		case strings.HasPrefix(e, "CHECK_TCP="):
			options.TCP = strings.Replace(strings.TrimPrefix(e, "CHECK_TCP="), "{{address}}", address, 1)
		}
	}
	return options
}

func env(key, defaultValue string) string {
	if value := os.Getenv(key); len(value) != 0 {
		return value
	}
	return defaultValue
}

func toJSON(v interface{}) string {
	if json, err := json.Marshal(v); err == nil {
		return string(json)
	}
	return ""
}
