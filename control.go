package flowhawk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Remote-control client: polls the control plane's OpAMP endpoint (JSON over HTTP) and applies the
// returned config. Never panics or blocks the host app; until a config arrives the SDK keeps
// everything and tags nothing. Same protocol as the Node and Python SDKs.

// SDKID identifies this SDK to the control plane.
const SDKID = "flowhawk-go/0.1.1"

type configStatus struct {
	Hash   string `json:"last_remote_config_hash"`
	Status string `json:"status"`
	Error  string `json:"error_message,omitempty"`
}

type serverToAgent struct {
	PollIntervalS *float64 `json:"poll_interval_s"`
	RemoteConfig  *struct {
		Hash   string          `json:"config_hash"`
		Config json.RawMessage `json:"config"`
	} `json:"remote_config"`
}

type controlClient struct {
	url      string
	apiKey   string
	service  string
	version  string
	client   *http.Client
	uid      string
	seq      int64
	status   *configStatus
	failures int
	lastWarn time.Time
	cancel   context.CancelFunc
	done     chan struct{}
	once     sync.Once
}

func newControlClient(url, service, version, apiKey string) *controlClient {
	return &controlClient{
		url: strings.TrimRight(url, "/"), service: service, version: version, apiKey: apiKey,
		// A plain client: the SDK's own traffic must not be traced.
		client: &http.Client{Timeout: 3 * time.Second},
		uid:    uuid.NewString(),
		done:   make(chan struct{}),
	}
}

// insecureControlURL says why the ingest key must not go to this control URL, or "" when it may: plain http
// sends it in the clear, so it is allowed only to this machine (localhost, 127.x, ::1) or with
// FLOWHAWK_ALLOW_INSECURE_CONTROL_URL=true (a private network). Without a key nothing secret is sent.
func insecureControlURL(raw, apiKey string, allow bool) string {
	if apiKey == "" || allow {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "control URL " + raw + " is not a URL"
	}
	if u.Scheme == "https" {
		return ""
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); u.Scheme == "http" && (host == "localhost" || strings.HasSuffix(host, ".localhost") || (ip != nil && ip.IsLoopback())) {
		return ""
	}
	return fmt.Sprintf("refusing to send the ingest key to %s://%s over plain http: use https, or set FLOWHAWK_ALLOW_INSECURE_CONTROL_URL=true on a private network", u.Scheme, u.Host)
}

// plainHTTPKeyWarning is a warning when telemetry carries the ingest key over plain http to another machine, or "".
// Unlike the control URL this is not refused: a collector on the team's own network often listens on plain http. The
// same check as insecureControlURL, and FLOWHAWK_ALLOW_INSECURE_CONTROL_URL=true silences it.
func plainHTTPKeyWarning(endpoint, apiKey string, allow bool) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || insecureControlURL(endpoint, apiKey, allow) == "" {
		return ""
	}
	return fmt.Sprintf("sending the ingest key to http://%s over plain http, where anyone on the network can read it: use https, or set FLOWHAWK_ALLOW_INSECURE_CONTROL_URL=true if this is a collector on your private network", u.Host)
}

func (c *controlClient) start() {
	if why := insecureControlURL(c.url, c.apiKey, os.Getenv("FLOWHAWK_ALLOW_INSECURE_CONTROL_URL") == "true"); why != "" {
		c.warn(why + "; remote config is off")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	go func() {
		defer close(c.done)
		for {
			next, err := c.safePoll(ctx)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				// Server gone: the last config stays applied (its redaction with it) until it returns. Dropping it would
				// export what the workspace's own redact and drop rules remove; only the defaults apply without a config.
				c.failures++
				c.warn(fmt.Sprintf("control plane unreachable at %s: %v", c.url, err))
			} else {
				c.failures = 0
			}
			if next <= 0 {
				next = 5 * time.Second
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(max(time.Second, next)):
			}
		}
	}()
}

func (c *controlClient) stop() {
	c.once.Do(func() {
		if c.cancel != nil {
			c.cancel()
			<-c.done
		}
	})
}

func (c *controlClient) safePoll(ctx context.Context) (next time.Duration, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return c.poll(ctx)
}

// poll sends one OpAMP message and applies a new config; it returns the server's poll interval (0 when unset).
func (c *controlClient) poll(ctx context.Context) (time.Duration, error) {
	c.seq++
	desc := map[string]string{"service": c.service, "sdk": SDKID}
	if c.version != "" {
		desc["version"] = c.version
	}
	msg := map[string]any{
		"instance_uid":      c.uid,
		"sequence_num":      c.seq,
		"agent_description": desc,
		"health":            map[string]any{"healthy": true, "spans_exported": stats.kept.Load(), "spans_dropped": stats.dropped.Load()},
	}
	if c.status != nil {
		msg["remote_config_status"] = c.status
	}
	body, _ := json.Marshal(msg)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/v1/opamp", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("content-type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("authorization", "Bearer "+c.apiKey)
	}
	res, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return 0, err
	}
	if res.StatusCode == http.StatusUnauthorized {
		if c.apiKey != "" {
			return 0, errors.New("HTTP 401: the ingest key was rejected")
		}
		return 0, errors.New("HTTP 401: set FLOWHAWK_API_KEY to a workspace ingest key")
	}
	if res.StatusCode/100 != 2 {
		return 0, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	var out serverToAgent
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return 0, err
		}
	}
	if rc := out.RemoteConfig; rc != nil {
		curHash, _ := CurrentConfig()
		if rc.Hash != curHash {
			if cfg, err := ParseRemoteConfig(rc.Config); err != nil {
				// Keep the previous config; report the failure on the next poll.
				e := err.Error()
				if len(e) > 500 {
					e = e[:500]
				}
				c.status = &configStatus{Hash: rc.Hash, Status: "FAILED", Error: e}
				c.warn(fmt.Sprintf("rejected remote config %s: %v", rc.Hash, err))
			} else {
				setApplied(rc.Hash, cfg)
				c.status = &configStatus{Hash: rc.Hash, Status: "APPLIED"}
			}
		}
	}
	if out.PollIntervalS != nil {
		return time.Duration(*out.PollIntervalS * float64(time.Second)), nil
	}
	return 0, nil
}

// warn writes at most one warning per minute.
func (c *controlClient) warn(text string) {
	if !c.lastWarn.IsZero() && time.Since(c.lastWarn) < time.Minute {
		return
	}
	c.lastWarn = time.Now()
	fmt.Fprintf(os.Stderr, "[flowhawk-sdk] %s\n", text)
}
