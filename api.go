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
	OpenPorts  []int  `json:"open_ports"`
	AllowICMP  bool   `json:"allow_icmp"`
}

type PluginConfig struct {
	Namespace string `json:"namespace"`
	Interface string `json:"interface"`
	IPCIDR    string `json:"ip_cidr"`
	MAC       string `json:"mac"`
	Gateway   string `json:"gateway"`
	OpenPorts []int  `json:"open_ports"`
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

type CheckTCPPortRequest struct {
	TargetIP string
	Port     int
}

type SFTPConnectionInfo struct {
	Address               string `json:"address"`
	Username              string `json:"username"`
	Password              string `json:"password,omitempty"`
	PrivateKeyPEM         string `json:"private_key_pem,omitempty"`
	HostPublicKey         string `json:"host_public_key,omitempty"`
	InsecureIgnoreHostKey bool   `json:"insecure_ignore_host_key,omitempty"`
}

type SFTPListRequest struct {
	Connection SFTPConnectionInfo `json:"connection"`
	Directory  string             `json:"directory"`
}

type SFTPEntry struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	Mode        uint32 `json:"mode"`
	IsDir       bool   `json:"is_dir"`
	ModTimeUnix int64  `json:"mod_time_unix"`
}

type SFTPListResponse struct {
	Entries []SFTPEntry `json:"entries"`
}

type SFTPFetchRequest struct {
	Connection SFTPConnectionInfo `json:"connection"`
	Path       string             `json:"path"`
}

type SFTPFetchResponse struct {
	Path        string `json:"path"`
	Data        []byte `json:"data"`
	Size        int64  `json:"size"`
	Mode        uint32 `json:"mode"`
	ModTimeUnix int64  `json:"mod_time_unix"`
}

type SFTPPushRequest struct {
	Connection    SFTPConnectionInfo `json:"connection"`
	Path          string             `json:"path"`
	Data          []byte             `json:"data"`
	Mode          uint32             `json:"mode"`
	CreateParents bool               `json:"create_parents"`
}

type SFTPPushResponse struct {
	Path         string `json:"path"`
	BytesWritten int64  `json:"bytes_written"`
}

type SFTPDeleteRequest struct {
	Connection SFTPConnectionInfo `json:"connection"`
	Path       string             `json:"path"`
	Recursive  bool               `json:"recursive"`
}

type SFTPDeleteResponse struct {
	Path    string `json:"path"`
	Removed bool   `json:"removed"`
}

type StatusResponse struct {
	Namespace   string
	Interface   string
	IPCIDR      string
	MAC         string
	Gateway     string
	OpenPorts   []int
	AllowICMP   bool
	HTTPAddr    string
	HTTPRunning bool
}

type NamespaceService interface {
	Describe() (*DescribeResponse, error)
	StartHTTP(port int) (*StartHTTPResponse, error)
	CheckTCPPort(targetIP string, port int) (string, error)
	SFTPList(req SFTPListRequest) (*SFTPListResponse, error)
	SFTPFetch(req SFTPFetchRequest) (*SFTPFetchResponse, error)
	SFTPPush(req SFTPPushRequest) (*SFTPPushResponse, error)
	SFTPDelete(req SFTPDeleteRequest) (*SFTPDeleteResponse, error)
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

func (s *namespaceServiceRPCServer) CheckTCPPort(req CheckTCPPortRequest, resp *string) error {
	out, err := s.Impl.CheckTCPPort(req.TargetIP, req.Port)
	if err != nil {
		return err
	}
	*resp = out
	return nil
}

func (s *namespaceServiceRPCServer) SFTPList(req SFTPListRequest, resp *SFTPListResponse) error {
	out, err := s.Impl.SFTPList(req)
	if err != nil {
		return err
	}
	*resp = *out
	return nil
}

func (s *namespaceServiceRPCServer) SFTPFetch(req SFTPFetchRequest, resp *SFTPFetchResponse) error {
	out, err := s.Impl.SFTPFetch(req)
	if err != nil {
		return err
	}
	*resp = *out
	return nil
}

func (s *namespaceServiceRPCServer) SFTPPush(req SFTPPushRequest, resp *SFTPPushResponse) error {
	out, err := s.Impl.SFTPPush(req)
	if err != nil {
		return err
	}
	*resp = *out
	return nil
}

func (s *namespaceServiceRPCServer) SFTPDelete(req SFTPDeleteRequest, resp *SFTPDeleteResponse) error {
	out, err := s.Impl.SFTPDelete(req)
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

func (c *namespaceServiceRPCClient) CheckTCPPort(targetIP string, port int) (string, error) {
	var out string
	err := c.client.Call("Plugin.CheckTCPPort", CheckTCPPortRequest{TargetIP: targetIP, Port: port}, &out)
	return out, err
}

func (c *namespaceServiceRPCClient) SFTPList(req SFTPListRequest) (*SFTPListResponse, error) {
	var out SFTPListResponse
	err := c.client.Call("Plugin.SFTPList", req, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) SFTPFetch(req SFTPFetchRequest) (*SFTPFetchResponse, error) {
	var out SFTPFetchResponse
	err := c.client.Call("Plugin.SFTPFetch", req, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) SFTPPush(req SFTPPushRequest) (*SFTPPushResponse, error) {
	var out SFTPPushResponse
	err := c.client.Call("Plugin.SFTPPush", req, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) SFTPDelete(req SFTPDeleteRequest) (*SFTPDeleteResponse, error) {
	var out SFTPDeleteResponse
	err := c.client.Call("Plugin.SFTPDelete", req, &out)
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
