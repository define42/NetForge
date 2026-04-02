//go:build linux

package main

import (
	"net/rpc"

	"github.com/hashicorp/go-plugin"
)

const pluginName = "namespace_service"

type NSConfig struct {
	Name       string `json:"name"`
	VLANID     int    `json:"vlan_id"`
	IfName     string `json:"if_name"`
	IPCIDR     string `json:"ip_cidr"`
	MAC        string `json:"mac"`
	Gateway    string `json:"gateway"`
	ListenPort int    `json:"listen_port"`
	OpenPort   int    `json:"open_port"`
	AllowICMP  bool   `json:"allow_icmp"`
}

type PluginConfig struct {
	Namespace string `json:"namespace"`
	Interface string `json:"interface"`
	IPCIDR    string `json:"ip_cidr"`
	MAC       string `json:"mac"`
	Gateway   string `json:"gateway"`
	OpenPort  int    `json:"open_port"`
	AllowICMP bool   `json:"allow_icmp"`
}

type DescribeResponse struct {
	Namespace string
	HTTPAddr  string
	Message   string
}

type StartHTTPResponse struct {
	HTTPAddr string
}

type StatusResponse struct {
	Namespace   string
	Interface   string
	IPCIDR      string
	MAC         string
	Gateway     string
	OpenPort    int
	AllowICMP   bool
	HTTPAddr    string
	HTTPRunning bool
}

type NamespaceService interface {
	Describe() (*DescribeResponse, error)
	StartHTTP(port int) (*StartHTTPResponse, error)
	StopHTTP() error
	Status() (*StatusResponse, error)
}

var handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "NS_PLUGIN",
	MagicCookieValue: "namespace-service",
}

type namespaceServicePlugin struct {
	plugin.Plugin
	Impl NamespaceService
}

func (p *namespaceServicePlugin) Server(*plugin.MuxBroker) (interface{}, error) {
	return &namespaceServiceRPCServer{Impl: p.Impl}, nil
}

func (p *namespaceServicePlugin) Client(_ *plugin.MuxBroker, c *rpc.Client) (interface{}, error) {
	return &namespaceServiceRPCClient{client: c}, nil
}

var pluginMap = map[string]plugin.Plugin{
	pluginName: &namespaceServicePlugin{},
}

type namespaceServiceRPCServer struct {
	Impl NamespaceService
}

func (s *namespaceServiceRPCServer) Describe(_ struct{}, resp *DescribeResponse) error {
	out, err := s.Impl.Describe()
	if err != nil {
		return err
	}
	*resp = *out
	return nil
}

func (s *namespaceServiceRPCServer) StartHTTP(port int, resp *StartHTTPResponse) error {
	out, err := s.Impl.StartHTTP(port)
	if err != nil {
		return err
	}
	*resp = *out
	return nil
}

func (s *namespaceServiceRPCServer) StopHTTP(_ struct{}, _ *struct{}) error {
	return s.Impl.StopHTTP()
}

func (s *namespaceServiceRPCServer) Status(_ struct{}, resp *StatusResponse) error {
	out, err := s.Impl.Status()
	if err != nil {
		return err
	}
	*resp = *out
	return nil
}

type namespaceServiceRPCClient struct {
	client *rpc.Client
}

func (c *namespaceServiceRPCClient) Describe() (*DescribeResponse, error) {
	var out DescribeResponse
	err := c.client.Call("Plugin.Describe", struct{}{}, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) StartHTTP(port int) (*StartHTTPResponse, error) {
	var out StartHTTPResponse
	err := c.client.Call("Plugin.StartHTTP", port, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) StopHTTP() error {
	var out struct{}
	return c.client.Call("Plugin.StopHTTP", struct{}{}, &out)
}

func (c *namespaceServiceRPCClient) Status() (*StatusResponse, error) {
	var out StatusResponse
	err := c.client.Call("Plugin.Status", struct{}{}, &out)
	return &out, err
}
