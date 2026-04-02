//go:build linux

package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hashicorp/go-plugin"
)

func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func runHost(ctx context.Context, parentNIC, selfBinary, runtimeBase, hostHTTPAddr string, configs []NSConfig) (err error) {
	if err := ensurePrivateOwnedDir(runtimeBase); err != nil {
		return err
	}

	for i := range configs {
		configs[i] = normalizeNSConfig(configs[i])
	}
	if err := validateHostConfig(parentNIC, configs); err != nil {
		return err
	}

	recreatedNamespaces, err := reconcileNamespaces(parentNIC, runtimeBase, configs)
	if err != nil {
		return err
	}

	plugins := make([]*runningPlugin, 0, len(configs))
	cleanupNamespacesOnExit := true
	defer func() {
		for _, p := range plugins {
			p.Stop()
		}
		if cleanupNamespacesOnExit {
			cleanupNamespaceSet(runtimeBase, recreatedNamespaces)
		}
	}()

	for _, cfg := range configs {
		rp, err := startNamespacePlugin(selfBinary, runtimeBase, cfg)
		if err != nil {
			return err
		}
		plugins = append(plugins, rp)

		desc, err := rp.rpc.Describe()
		if err != nil {
			return err
		}
		status, err := rp.rpc.Status()
		if err != nil {
			return err
		}
		log.Printf("namespace=%s message=%q http=%s running=%v", desc.Namespace, desc.Message, status.HTTPAddr, status.HTTPRunning)
	}

	server, actualAddr, err := startHostDashboard(hostHTTPAddr, parentNIC, runtimeBase, plugins)
	if err != nil {
		return err
	}
	log.Printf("host dashboard listening on http://%s", actualAddr)
	cleanupNamespacesOnExit = false

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}

func runPluginMode() error {
	if err := ensurePluginSandbox(); err != nil {
		return err
	}

	cfg, err := loadPluginConfigFromEnv()
	if err != nil {
		return err
	}

	svc := &namespaceHTTPService{cfg: cfg}
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshake,
		Plugins: map[string]plugin.Plugin{
			pluginName: &namespaceServicePlugin{Impl: svc},
		},
	})
	return nil
}

func runMain() error {
	if os.Getenv(envPluginSandboxSeccompProbe) == "1" {
		return runPluginSandboxSeccompProbe()
	}

	if os.Getenv("NS_PLUGIN_MODE") == "1" {
		return runPluginMode()
	}

	if os.Geteuid() != 0 {
		return errors.New("run as root")
	}

	selfBinary, err := os.Executable()
	if err != nil {
		return err
	}

	parentNIC := envDefault("PARENT_NIC", "enp0s31f6")
	hostHTTPAddr := envDefault("HOST_HTTP_ADDR", "127.0.0.1:8090")

	configs, err := loadConfigs(parentNIC)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return runHost(ctx, parentNIC, selfBinary, defaultPluginRuntimeBase, hostHTTPAddr, configs)
}

func main() {
	if err := runMain(); err != nil {
		log.Fatal(err)
	}
}
