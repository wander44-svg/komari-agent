package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/komari-monitor/komari-agent/dnsresolver"
	"github.com/komari-monitor/komari-agent/monitoring"
	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
	"github.com/komari-monitor/komari-agent/utils"
	"github.com/komari-monitor/komari-agent/ws"
)

var (
	v2AckMu       sync.Mutex
	v2AckEventIDs []string
	v2SeenEvents  = make(map[string]struct{})
)

const maxV2SeenEvents = 4096

func EstablishWebSocketConnection() {
	var conn *ws.SafeConn
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	var err error
	interval := math.Max(1, flags.Interval)

	dataTicker := time.NewTicker(time.Duration(interval * float64(time.Second)))
	defer dataTicker.Stop()

	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	var readDone <-chan struct{}

	for {
		select {
		case <-dataTicker.C:
			if conn == nil {
				log.Println("Attempting to connect to WebSocket...")
				retry := 0
				for retry <= flags.MaxRetries {
					if retry > 0 {
						log.Println("Retrying websocket connection, attempt:", retry)
					}
					websocketEndpoint := buildWebSocketEndpoint()
					conn, err = connectWebSocket(websocketEndpoint)
					if err == nil {
						log.Printf("WebSocket connected using v2 protocol")
						done := make(chan struct{})
						readDone = done
						go handleWebSocketMessages(conn, done)
						break
					} else {
						log.Println("Failed to connect to WebSocket:", err)
					}
					retry++
					time.Sleep(time.Duration(flags.ReconnectInterval) * time.Second)
				}

				if retry > flags.MaxRetries {
					log.Println("Max retries reached.")
					conn, err = runPostFallback(buildWebSocketEndpoint(), interval)
					if err != nil {
						log.Println("POST fallback stopped:", err)
						return
					}
					log.Println("WebSocket recovered from POST fallback")
					done := make(chan struct{})
					readDone = done
					go handleWebSocketMessages(conn, done)
				}
			}

			data := v2.BuildReportPayload(monitoring.GenerateReport())
			err = conn.WriteMessage(websocket.TextMessage, data)
			if err != nil {
				log.Println("Failed to send WebSocket message:", err)
				conn.Close()
				conn = nil // Mark connection as dead
				readDone = nil
				continue
			}
		case <-heartbeatTicker.C:
			if conn != nil {
				err := conn.WriteMessage(websocket.PingMessage, nil)
				if err != nil {
					log.Println("Failed to send heartbeat:", err)
					conn.Close()
					conn = nil // Mark connection as dead
					readDone = nil
				}
			}
		case <-readDone:
			log.Println("WebSocket disconnected")
			if conn != nil {
				conn.Close()
				conn = nil
			}
			readDone = nil
		}
	}
}

func buildWebSocketEndpoint() string {
	path := "/api/clients/v2/rpc"
	websocketEndpoint := strings.TrimSuffix(flags.Endpoint, "/") + path
	websocketEndpoint = "ws" + strings.TrimPrefix(websocketEndpoint, "http")
	if convertedEndpoint, err := utils.ConvertIDNToASCII(websocketEndpoint); err == nil {
		return convertedEndpoint
	} else {
		log.Printf("Warning: Failed to convert WebSocket IDN to ASCII: %v", err)
	}
	return websocketEndpoint
}

func runPostFallback(websocketEndpoint string, interval float64) (*ws.SafeConn, error) {
	log.Println("Entering v2 POST fallback mode")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pullErr := make(chan error, 1)
	go runV2PullLoop(ctx, pullErr)

	reportTicker := time.NewTicker(time.Duration(interval * float64(time.Second)))
	defer reportTicker.Stop()
	reconnectTicker := time.NewTicker(time.Duration(flags.ReconnectInterval) * time.Second)
	defer reconnectTicker.Stop()

	for {
		select {
		case <-reportTicker.C:
			reportID := fmt.Sprintf("report-%d", time.Now().UnixNano())
			ackIDs := snapshotV2AckEventIDs()
			resp, err := postV2Request(v2.BuildReportRequest(reportID, monitoring.GenerateReport(), ackIDs))
			if err != nil {
				log.Println("Failed to POST v2 report:", err)
				continue
			}
			clearV2AckEventIDs(ackIDs)
			processV2ResponseEvents(resp)
		case <-reconnectTicker.C:
			conn, err := connectWebSocket(websocketEndpoint)
			if err == nil {
				return conn, nil
			}
			log.Println("POST fallback WebSocket recovery failed:", err)
		case err := <-pullErr:
			return nil, err
		}
	}
}

func runV2PullLoop(ctx context.Context, errCh chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		pullID := fmt.Sprintf("pull-%d", time.Now().UnixNano())
		ackIDs := snapshotV2AckEventIDs()
		payload := v2.NewRequest(pullID, v2.MethodAgentPull, map[string]interface{}{
			"capabilities":  []string{"ping"},
			"ack_event_ids": ackIDs,
		})
		resp, err := postV2RequestContext(ctx, payload)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Println("Failed to POST v2 pull:", err)
			time.Sleep(time.Duration(flags.ReconnectInterval) * time.Second)
			continue
		}
		clearV2AckEventIDs(ackIDs)
		processV2ResponseEvents(resp)
	}
}

func postV2Request(payload []byte) (*v2.Response, error) {
	return postV2RequestContext(context.Background(), payload)
}

func postV2RequestContext(ctx context.Context, payload []byte) (*v2.Response, error) {
	endpoint := strings.TrimSuffix(flags.Endpoint, "/") + "/api/clients/v2/rpc"
	body := payload
	compressed := false
	if !flags.DisableCompression {
		if gz, err := gzipBytes(payload); err == nil {
			body = gz
			compressed = true
		}
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+flags.Token)
	if compressed {
		req.Header.Set("Content-Encoding", "gzip")
	}
	client := dnsresolver.GetHTTPClientWithPreference(35*time.Second, flags.PreferIPVersion)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bytesBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &httpStatusError{StatusCode: resp.StatusCode, Status: resp.Status, Body: string(bytesBody)}
	}
	rpcResp, err := parseV2Response(bytesBody)
	if err != nil {
		return nil, err
	}
	return rpcResp, nil
}

func processV2ResponseEvents(resp *v2.Response) {
	if resp == nil || resp.Result == nil {
		return
	}
	var result v2.EventResult
	if err := v2.BindResult(resp.Result, &result); err != nil {
		log.Println("Failed to bind v2 event result:", err)
		return
	}
	for _, event := range result.Events {
		if processV2Event(nil, event.Method, event.Params, event.ID) {
			addV2AckEventID(event.ID)
		}
	}
}

func snapshotV2AckEventIDs() []string {
	v2AckMu.Lock()
	defer v2AckMu.Unlock()
	return append([]string{}, v2AckEventIDs...)
}

func clearV2AckEventIDs(sent []string) {
	if len(sent) == 0 {
		return
	}
	sentSet := make(map[string]struct{}, len(sent))
	for _, id := range sent {
		sentSet[id] = struct{}{}
	}
	v2AckMu.Lock()
	defer v2AckMu.Unlock()
	remaining := v2AckEventIDs[:0]
	for _, id := range v2AckEventIDs {
		if _, ok := sentSet[id]; !ok {
			remaining = append(remaining, id)
		}
	}
	v2AckEventIDs = remaining
}

func addV2AckEventID(id string) {
	if id == "" {
		return
	}
	v2AckMu.Lock()
	defer v2AckMu.Unlock()
	if len(v2AckEventIDs) >= maxV2SeenEvents {
		v2AckEventIDs = v2AckEventIDs[len(v2AckEventIDs)-maxV2SeenEvents+1:]
	}
	v2AckEventIDs = append(v2AckEventIDs, id)
}

func markV2EventSeen(id string) bool {
	if id == "" {
		return true
	}
	v2AckMu.Lock()
	defer v2AckMu.Unlock()
	if _, ok := v2SeenEvents[id]; ok {
		return false
	}
	if len(v2SeenEvents) >= maxV2SeenEvents {
		for oldID := range v2SeenEvents {
			delete(v2SeenEvents, oldID)
			break
		}
	}
	v2SeenEvents[id] = struct{}{}
	return true
}

func connectWebSocket(websocketEndpoint string) (*ws.SafeConn, error) {
	dialer := newWSDialer()

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+flags.Token)
	conn, resp, err := dialer.Dial(websocketEndpoint, headers)
	if err != nil {
		if resp != nil && resp.StatusCode != 101 {
			return nil, &httpStatusError{StatusCode: resp.StatusCode, Status: resp.Status}
		}
		return nil, err
	}

	return ws.NewSafeConn(conn), nil
}

func handleWebSocketMessages(conn *ws.SafeConn, done chan<- struct{}) {
	defer close(done)
	for {
		conn.SetReadLimit(1 << 20)
		_, message_raw, err := conn.ReadMessage()
		if err != nil {
			log.Println("WebSocket read error:", err)
			return
		}
		var message struct {
			JSONRPC string      `json:"jsonrpc,omitempty"`
			Method  string      `json:"method,omitempty"`
			Params  interface{} `json:"params,omitempty"`
		}
		err = json.Unmarshal(message_raw, &message)
		if err != nil {
			log.Println("Bad ws message:", err)
			continue
		}
		if message.JSONRPC == v2.Version {
			processV2Event(conn, message.Method, message.Params, "")
			continue
		}
		log.Printf("ignored non-v2 websocket message")
	}
}

func processV2Event(conn *ws.SafeConn, method string, params interface{}, eventID string) bool {
	if !markV2EventSeen(eventID) {
		return true
	}
	switch method {
	case v2.MethodAgentPing:
		var p struct {
			TaskID uint   `json:"ping_task_id"`
			Type   string `json:"ping_type"`
			Target string `json:"ping_target"`
		}
		if err := v2.BindParams(params, &p); err == nil {
			go NewPingTask(conn, p.TaskID, p.Type, p.Target)
			return true
		} else {
			log.Printf("bad v2 ping params: %v", err)
		}
	default:
		log.Printf("unknown v2 event method %s", method)
	}
	return false
}

// connectWebSocket attempts to establish a WebSocket connection and upload basic info

// newWSDialer 构造统一的 WebSocket 拨号器（自定义解析、IPv4/IPv6 动态排序、可选 TLS 忽略）
func newWSDialer() *websocket.Dialer {
	d := &websocket.Dialer{
		HandshakeTimeout:  15 * time.Second,
		NetDialContext:    dnsresolver.GetDialContextWithPreference(15*time.Second, flags.PreferIPVersion),
		Proxy:             http.ProxyFromEnvironment,
		EnableCompression: !flags.DisableCompression,
	}
	if flags.IgnoreUnsafeCert {
		d.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return d
}
