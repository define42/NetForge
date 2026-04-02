//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-plugin/runner"
	"github.com/vishvananda/netns"
)

type namespaceHTTPService struct {
	cfg        PluginConfig
	mu         sync.Mutex
	httpServer *http.Server
	httpAddr   string
	port       int
}

func (s *namespaceHTTPService) Describe() (*DescribeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return &DescribeResponse{
		Namespace: s.cfg.Namespace,
		HTTPAddr:  s.httpAddr,
		Message:   "plugin ready",
	}, nil
}

func (s *namespaceHTTPService) StartHTTP(port int) (*StartHTTPResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.httpServer != nil {
		if s.port != port {
			return nil, fmt.Errorf("http server already running on port %d", s.port)
		}
		return &StartHTTPResponse{HTTPAddr: s.httpAddr}, nil
	}

	addr := fmt.Sprintf(":%d", port)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(
			w,
			"hello from namespace=%s interface=%s ip=%s mac=%s gateway=%s remote=%s time=%s\n",
			s.cfg.Namespace,
			s.cfg.Interface,
			s.cfg.IPCIDR,
			s.cfg.MAC,
			s.cfg.Gateway,
			r.RemoteAddr,
			time.Now().Format(time.RFC3339),
		)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	s.port = port
	s.httpAddr = addr

	go func(server *http.Server, listener net.Listener) {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("namespace=%s http server error: %v", s.cfg.Namespace, err)
		}
	}(s.httpServer, ln)

	return &StartHTTPResponse{HTTPAddr: s.httpAddr}, nil
}

func (s *namespaceHTTPService) CheckTCPPort(targetIP string, port int) (string, error) {
	return checkCurrentNamespaceTCPPort(s.cfg.Namespace, targetIP, port)
}

func (s *namespaceHTTPService) StopHTTP() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.httpServer == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.httpServer.Shutdown(ctx)
	s.httpServer = nil
	s.httpAddr = ""
	s.port = 0
	return err
}

func (s *namespaceHTTPService) Status() (*StatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return &StatusResponse{
		Namespace:   s.cfg.Namespace,
		Interface:   s.cfg.Interface,
		IPCIDR:      s.cfg.IPCIDR,
		MAC:         s.cfg.MAC,
		Gateway:     s.cfg.Gateway,
		OpenPorts:   cloneOpenPorts(s.cfg.OpenPorts),
		AllowICMP:   s.cfg.AllowICMP,
		HTTPAddr:    s.httpAddr,
		HTTPRunning: s.httpServer != nil,
	}, nil
}

type runningPlugin struct {
	cfg     NSConfig
	client  *plugin.Client
	rpc     NamespaceService
	pid     int
	sandbox pluginSandboxSpec
	cgroup  pluginCgroup
}

type namespaceCmdRunner struct {
	logger    hclog.Logger
	cmd       *exec.Cmd
	namespace string
	sandbox   pluginSandboxSpec
	cgroup    pluginCgroup

	stdout io.ReadCloser
	stderr io.ReadCloser
	path   string
	pid    int
}

func stagePluginChildBinary(selfBinary, runtimeDir string) (string, error) {
	// The child enters a new user namespace before exec, so it can lose DAC
	// bypass on private host paths like /home/$USER. Stage a private executable
	// copy under the runtime dir so the sandboxed child can always traverse and exec it.
	srcInfo, err := os.Stat(selfBinary)
	if err != nil {
		return "", fmt.Errorf("stat plugin child binary %q: %w", selfBinary, err)
	}

	staged := filepath.Join(runtimeDir, "plugin-child")
	if info, err := os.Stat(staged); err == nil {
		if info.Size() == srcInfo.Size() && info.Mode().Perm()&0o111 != 0 {
			return staged, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("stat staged plugin child %q: %w", staged, err)
	}

	src, err := os.Open(selfBinary)
	if err != nil {
		return "", fmt.Errorf("open plugin child binary %q: %w", selfBinary, err)
	}
	defer src.Close()

	tmp := staged + ".tmp"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, srcInfo.Mode().Perm()|0o111)
	if err != nil {
		return "", fmt.Errorf("create staged plugin child %q: %w", tmp, err)
	}

	copyErr := func() error {
		if _, err := io.Copy(dst, src); err != nil {
			return fmt.Errorf("copy plugin child binary to %q: %w", tmp, err)
		}
		if err := dst.Chmod(srcInfo.Mode().Perm() | 0o111); err != nil {
			return fmt.Errorf("chmod staged plugin child %q: %w", tmp, err)
		}
		if err := dst.Close(); err != nil {
			return fmt.Errorf("close staged plugin child %q: %w", tmp, err)
		}
		if err := os.Rename(tmp, staged); err != nil {
			return fmt.Errorf("rename staged plugin child to %q: %w", staged, err)
		}
		return nil
	}()
	if copyErr != nil {
		_ = dst.Close()
		_ = os.Remove(tmp)
		return "", copyErr
	}

	return staged, nil
}

func newNamespaceCmdRunner(logger hclog.Logger, cmd *exec.Cmd, namespace string, sandbox pluginSandboxSpec) (*namespaceCmdRunner, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := applyPluginSandboxSysProcAttr(cmd); err != nil {
		return nil, err
	}

	cgroup, err := pluginCgroupFactory(namespace)
	if err != nil {
		return nil, err
	}
	if err := cgroup.ConfigureCommand(cmd); err != nil {
		cleanupPluginCgroup(cgroup)
		return nil, err
	}

	displayPath := cmd.Path
	if len(cmd.Args) > 0 && cmd.Args[0] != "" {
		displayPath = cmd.Args[0]
	}

	return &namespaceCmdRunner{
		logger:    logger,
		cmd:       cmd,
		namespace: namespace,
		sandbox:   sandbox,
		cgroup:    cgroup,
		stdout:    stdout,
		stderr:    stderr,
		path:      displayPath,
	}, nil
}

func (r *namespaceCmdRunner) Start(_ context.Context) error {
	cgroupPath := ""
	if r.cgroup != nil {
		cgroupPath = r.cgroup.Path()
	}
	r.logger.Debug("starting plugin", "path", r.cmd.Path, "args", r.cmd.Args, "namespace", r.namespace, "sandbox_root", r.sandbox.rootDir, "cgroup", cgroupPath)
	if err := startCmdInNamedNamespace(r.cmd, r.namespace); err != nil {
		cleanupPluginCgroup(r.cgroup)
		return err
	}

	r.pid = r.cmd.Process.Pid
	r.logger.Debug("plugin started", "path", r.path, "pid", r.pid, "namespace", r.namespace, "cgroup", cgroupPath)
	return nil
}

func (r *namespaceCmdRunner) Wait(_ context.Context) error {
	return r.cmd.Wait()
}

func (r *namespaceCmdRunner) Kill(_ context.Context) error {
	if r.cmd.Process == nil {
		return nil
	}

	err := r.cmd.Process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

func (r *namespaceCmdRunner) Stdout() io.ReadCloser {
	return r.stdout
}

func (r *namespaceCmdRunner) Stderr() io.ReadCloser {
	return r.stderr
}

func (r *namespaceCmdRunner) Name() string {
	return r.path
}

func (r *namespaceCmdRunner) ID() string {
	return fmt.Sprintf("%d", r.pid)
}

func (r *namespaceCmdRunner) Diagnose(_ context.Context) string {
	return fmt.Sprintf("failed to start %s in network namespace %q", r.path, r.namespace)
}

func (r *namespaceCmdRunner) PluginToHost(pluginNet, pluginAddr string) (string, string, error) {
	return r.sandbox.pluginToHostAddr(pluginNet, pluginAddr)
}

func (r *namespaceCmdRunner) HostToPlugin(hostNet, hostAddr string) (string, string, error) {
	return r.sandbox.hostToPluginAddr(hostNet, hostAddr)
}

var _ runner.Runner = (*namespaceCmdRunner)(nil)

func (p *runningPlugin) Stop() {
	if p == nil {
		return
	}
	if p.rpc != nil {
		_ = p.rpc.StopHTTP()
	}
	if p.client != nil {
		p.client.Kill()
		p.client = nil
	}
	if p.cgroup != nil {
		cleanupPluginCgroup(p.cgroup)
		p.cgroup = nil
	}
}

func startCmdInNamedNamespace(cmd *exec.Cmd, namespace string) (err error) {
	ns, err := netns.GetFromName(namespace)
	if err != nil {
		return fmt.Errorf("lookup namespace %q: %w", namespace, err)
	}
	defer ns.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	original, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get current namespace: %w", err)
	}
	defer original.Close()

	if err := netns.Set(ns); err != nil {
		return fmt.Errorf("enter namespace %q: %w", namespace, err)
	}

	started := false
	defer func() {
		restoreErr := netns.Set(original)
		if restoreErr == nil {
			return
		}
		if started && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		if err == nil {
			err = fmt.Errorf("restore original namespace after starting %q: %w", namespace, restoreErr)
		}
	}()

	if err := cmd.Start(); err != nil {
		return err
	}
	started = true

	return nil
}

func startNamespacePlugin(selfBinary, runtimeBase string, cfg NSConfig) (*runningPlugin, error) {
	cfg = normalizeNSConfig(cfg)

	runtimeDir := filepath.Join(runtimeBase, cfg.Name)
	if err := ensurePrivateOwnedDir(runtimeDir); err != nil {
		return nil, err
	}

	childBinary, err := stagePluginChildBinary(selfBinary, runtimeDir)
	if err != nil {
		return nil, err
	}

	cfgJSON, err := pluginConfigJSON(cfg)
	if err != nil {
		return nil, err
	}

	var cmdRunner *namespaceCmdRunner
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: handshake,
		Plugins:         pluginMap,
		RunnerFunc: func(logger hclog.Logger, cmd *exec.Cmd, socketDir string) (runner.Runner, error) {
			sandbox, err := newPluginSandboxSpec(runtimeDir, socketDir)
			if err != nil {
				return nil, err
			}
			cmd.Path = childBinary
			cmd.Args = []string{selfBinary}
			cmd.Env = append(cmd.Env,
				"NS_PLUGIN_MODE=1",
				"NS_PLUGIN_CONFIG="+cfgJSON,
			)
			cmd.Env = append(cmd.Env, sandbox.env()...)
			cmdRunner, err = newNamespaceCmdRunner(logger, cmd, cfg.Name, sandbox)
			if err != nil {
				return nil, err
			}
			return cmdRunner, nil
		},
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolNetRPC,
		},
		StartTimeout: 20 * time.Second,
		UnixSocketConfig: &plugin.UnixSocketConfig{
			TempDir: runtimeDir,
		},
		SyncStdout: os.Stdout,
		SyncStderr: os.Stderr,
		Stderr:     os.Stderr,
	})

	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		if cmdRunner != nil {
			cleanupPluginCgroup(cmdRunner.cgroup)
		}
		return nil, fmt.Errorf("connect plugin for %s: %w", cfg.Name, err)
	}

	raw, err := rpcClient.Dispense(pluginName)
	if err != nil {
		client.Kill()
		if cmdRunner != nil {
			cleanupPluginCgroup(cmdRunner.cgroup)
		}
		return nil, fmt.Errorf("dispense plugin for %s: %w", cfg.Name, err)
	}

	svc, ok := raw.(NamespaceService)
	if !ok {
		client.Kill()
		if cmdRunner != nil {
			cleanupPluginCgroup(cmdRunner.cgroup)
		}
		return nil, fmt.Errorf("dispensed plugin has type %T, want NamespaceService", raw)
	}

	if _, err := svc.StartHTTP(cfg.ListenPort); err != nil {
		client.Kill()
		if cmdRunner != nil {
			cleanupPluginCgroup(cmdRunner.cgroup)
		}
		return nil, fmt.Errorf("start namespace http server in %s: %w", cfg.Name, err)
	}

	rp := &runningPlugin{cfg: cfg, client: client, rpc: svc}
	if cmdRunner != nil {
		rp.pid = cmdRunner.pid
		rp.sandbox = cmdRunner.sandbox
		rp.cgroup = cmdRunner.cgroup
	}
	return rp, nil
}
