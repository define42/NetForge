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
	SFTPAddr  string
	Message   string
}

type StartHTTPResponse struct {
	HTTPAddr string
}

type StartSFTPResponse struct {
	SFTPAddr string
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

type SFTPFetchChunkRequest struct {
	Connection SFTPConnectionInfo `json:"connection"`
	Path       string             `json:"path"`
	Offset     int64              `json:"offset"`
	Length     int                `json:"length"`
}

type SFTPFetchResponse struct {
	Path        string `json:"path"`
	Data        []byte `json:"data"`
	Size        int64  `json:"size"`
	Mode        uint32 `json:"mode"`
	ModTimeUnix int64  `json:"mod_time_unix"`
}

type SFTPFetchChunkResponse struct {
	Path      string `json:"path"`
	Offset    int64  `json:"offset"`
	Data      []byte `json:"data"`
	EOF       bool   `json:"eof"`
	TotalSize int64  `json:"total_size"`
	Mode      uint32 `json:"mode"`
}

type SFTPPushRequest struct {
	Connection    SFTPConnectionInfo `json:"connection"`
	Path          string             `json:"path"`
	Data          []byte             `json:"data"`
	Mode          uint32             `json:"mode"`
	CreateParents bool               `json:"create_parents"`
}

type SFTPPushChunkRequest struct {
	Connection    SFTPConnectionInfo `json:"connection"`
	Path          string             `json:"path"`
	Offset        int64              `json:"offset"`
	Data          []byte             `json:"data"`
	Mode          uint32             `json:"mode"`
	CreateParents bool               `json:"create_parents"`
	Truncate      bool               `json:"truncate"`
}

type SFTPPushResponse struct {
	Path         string `json:"path"`
	BytesWritten int64  `json:"bytes_written"`
}

type SFTPPushChunkResponse struct {
	Path         string `json:"path"`
	Offset       int64  `json:"offset"`
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

type StartSFTPStageDownloadRequest struct {
	JobID               int64              `json:"job_id"`
	Connection          SFTPConnectionInfo `json:"connection"`
	RemoteDirectory     string             `json:"remote_directory"`
	LocalIncomingDir    string             `json:"local_incoming_dir"`
	LocalTmpDir         string             `json:"local_tmp_dir"`
	PollIntervalSeconds int64              `json:"poll_interval_seconds"`
}

type StartSFTPStageUploadRequest struct {
	JobID               int64              `json:"job_id"`
	Connection          SFTPConnectionInfo `json:"connection"`
	RemoteDirectory     string             `json:"remote_directory"`
	LocalIncomingDir    string             `json:"local_incoming_dir"`
	LocalTmpDir         string             `json:"local_tmp_dir"`
	LocalAckDir         string             `json:"local_ack_dir"`
	PollIntervalSeconds int64              `json:"poll_interval_seconds"`
}

type SFTPStageWorkerStatus struct {
	JobID         int64  `json:"job_id"`
	Running       bool   `json:"running"`
	LastPollAt    string `json:"last_poll_at,omitempty"`
	LastSuccessAt string `json:"last_success_at,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	LastFiles     int    `json:"last_files"`
	TotalFiles    int    `json:"total_files"`
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
	SFTPAddr    string
	SFTPRunning bool
}

type NamespaceService interface {
	Describe() (*DescribeResponse, error)
	StartHTTP(port int) (*StartHTTPResponse, error)
	StartSFTP(port int) (*StartSFTPResponse, error)
	CheckTCPPort(targetIP string, port int) (string, error)
	SFTPList(req SFTPListRequest) (*SFTPListResponse, error)
	SFTPFetch(req SFTPFetchRequest) (*SFTPFetchResponse, error)
	SFTPFetchChunk(req SFTPFetchChunkRequest) (*SFTPFetchChunkResponse, error)
	SFTPPush(req SFTPPushRequest) (*SFTPPushResponse, error)
	SFTPPushChunk(req SFTPPushChunkRequest) (*SFTPPushChunkResponse, error)
	SFTPDelete(req SFTPDeleteRequest) (*SFTPDeleteResponse, error)
	StartSFTPStageDownload(req StartSFTPStageDownloadRequest) (*SFTPStageWorkerStatus, error)
	StopSFTPStageDownload(jobID int64) (*SFTPStageWorkerStatus, error)
	GetSFTPStageDownloadStatus(jobID int64) (*SFTPStageWorkerStatus, error)
	StartSFTPStageUpload(req StartSFTPStageUploadRequest) (*SFTPStageWorkerStatus, error)
	StopSFTPStageUpload(jobID int64) (*SFTPStageWorkerStatus, error)
	GetSFTPStageUploadStatus(jobID int64) (*SFTPStageWorkerStatus, error)
	StopHTTP() error
	StopSFTP() error
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

func (s *namespaceServiceRPCServer) StartSFTP(port int, resp *StartSFTPResponse) error {
	out, err := s.Impl.StartSFTP(port)
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

func (s *namespaceServiceRPCServer) SFTPFetchChunk(req SFTPFetchChunkRequest, resp *SFTPFetchChunkResponse) error {
	out, err := s.Impl.SFTPFetchChunk(req)
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

func (s *namespaceServiceRPCServer) SFTPPushChunk(req SFTPPushChunkRequest, resp *SFTPPushChunkResponse) error {
	out, err := s.Impl.SFTPPushChunk(req)
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

func (s *namespaceServiceRPCServer) StartSFTPStageDownload(req StartSFTPStageDownloadRequest, resp *SFTPStageWorkerStatus) error {
	out, err := s.Impl.StartSFTPStageDownload(req)
	if err != nil {
		return err
	}
	*resp = *out
	return nil
}

func (s *namespaceServiceRPCServer) StopSFTPStageDownload(jobID int64, resp *SFTPStageWorkerStatus) error {
	out, err := s.Impl.StopSFTPStageDownload(jobID)
	if err != nil {
		return err
	}
	*resp = *out
	return nil
}

func (s *namespaceServiceRPCServer) GetSFTPStageDownloadStatus(jobID int64, resp *SFTPStageWorkerStatus) error {
	out, err := s.Impl.GetSFTPStageDownloadStatus(jobID)
	if err != nil {
		return err
	}
	*resp = *out
	return nil
}

func (s *namespaceServiceRPCServer) StartSFTPStageUpload(req StartSFTPStageUploadRequest, resp *SFTPStageWorkerStatus) error {
	out, err := s.Impl.StartSFTPStageUpload(req)
	if err != nil {
		return err
	}
	*resp = *out
	return nil
}

func (s *namespaceServiceRPCServer) StopSFTPStageUpload(jobID int64, resp *SFTPStageWorkerStatus) error {
	out, err := s.Impl.StopSFTPStageUpload(jobID)
	if err != nil {
		return err
	}
	*resp = *out
	return nil
}

func (s *namespaceServiceRPCServer) GetSFTPStageUploadStatus(jobID int64, resp *SFTPStageWorkerStatus) error {
	out, err := s.Impl.GetSFTPStageUploadStatus(jobID)
	if err != nil {
		return err
	}
	*resp = *out
	return nil
}

func (s *namespaceServiceRPCServer) StopHTTP(_ struct{}, _ *struct{}) error {
	return s.Impl.StopHTTP()
}

func (s *namespaceServiceRPCServer) StopSFTP(_ struct{}, _ *struct{}) error {
	return s.Impl.StopSFTP()
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

func (c *namespaceServiceRPCClient) StartSFTP(port int) (*StartSFTPResponse, error) {
	var out StartSFTPResponse
	err := c.client.Call("Plugin.StartSFTP", port, &out)
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

func (c *namespaceServiceRPCClient) SFTPFetchChunk(req SFTPFetchChunkRequest) (*SFTPFetchChunkResponse, error) {
	var out SFTPFetchChunkResponse
	err := c.client.Call("Plugin.SFTPFetchChunk", req, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) SFTPPush(req SFTPPushRequest) (*SFTPPushResponse, error) {
	var out SFTPPushResponse
	err := c.client.Call("Plugin.SFTPPush", req, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) SFTPPushChunk(req SFTPPushChunkRequest) (*SFTPPushChunkResponse, error) {
	var out SFTPPushChunkResponse
	err := c.client.Call("Plugin.SFTPPushChunk", req, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) SFTPDelete(req SFTPDeleteRequest) (*SFTPDeleteResponse, error) {
	var out SFTPDeleteResponse
	err := c.client.Call("Plugin.SFTPDelete", req, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) StartSFTPStageDownload(req StartSFTPStageDownloadRequest) (*SFTPStageWorkerStatus, error) {
	var out SFTPStageWorkerStatus
	err := c.client.Call("Plugin.StartSFTPStageDownload", req, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) StopSFTPStageDownload(jobID int64) (*SFTPStageWorkerStatus, error) {
	var out SFTPStageWorkerStatus
	err := c.client.Call("Plugin.StopSFTPStageDownload", jobID, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) GetSFTPStageDownloadStatus(jobID int64) (*SFTPStageWorkerStatus, error) {
	var out SFTPStageWorkerStatus
	err := c.client.Call("Plugin.GetSFTPStageDownloadStatus", jobID, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) StartSFTPStageUpload(req StartSFTPStageUploadRequest) (*SFTPStageWorkerStatus, error) {
	var out SFTPStageWorkerStatus
	err := c.client.Call("Plugin.StartSFTPStageUpload", req, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) StopSFTPStageUpload(jobID int64) (*SFTPStageWorkerStatus, error) {
	var out SFTPStageWorkerStatus
	err := c.client.Call("Plugin.StopSFTPStageUpload", jobID, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) GetSFTPStageUploadStatus(jobID int64) (*SFTPStageWorkerStatus, error) {
	var out SFTPStageWorkerStatus
	err := c.client.Call("Plugin.GetSFTPStageUploadStatus", jobID, &out)
	return &out, err
}

func (c *namespaceServiceRPCClient) StopHTTP() error {
	var out struct{}
	return c.client.Call("Plugin.StopHTTP", struct{}{}, &out)
}

func (c *namespaceServiceRPCClient) StopSFTP() error {
	var out struct{}
	return c.client.Call("Plugin.StopSFTP", struct{}{}, &out)
}

func (c *namespaceServiceRPCClient) Status() (*StatusResponse, error) {
	var out StatusResponse
	err := c.client.Call("Plugin.Status", struct{}{}, &out)
	return &out, err
}
