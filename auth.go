package g07control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const eventKind = "works.relux.keeper.g07.v1"

type authenticated struct {
	grant                         Grant
	eventID, eventSHA, requestSHA string
}

func selectedOrigin(s string) bool {
	u, e := url.Parse(s)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.Hostname() != "" && u.User == nil && u.Path == "" && u.RawPath == "" && u.RawQuery == "" && u.Fragment == "" && u.Opaque == "" && !u.ForceQuery && !strings.ContainsAny(s, "\r\n\\") && u.String() == s
}

func transport(roots *x509.CertPool) *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		MaxResponseHeaderBytes: 8192,
		DisableCompression:     true,
		DisableKeepAlives:      true,
	}
}

func (c *Control) authenticate(ctx context.Context, eventID string, tokenFD *os.File) (authenticated, error) {
	var zero authenticated
	if !matrixEvent.MatchString(eventID) || tokenFD == nil {
		return zero, refuse("AUTH_REFUSED")
	}
	// The keeper supplies this explicit descriptor. No environment/credential
	// lookup, identity discovery, redirects, alternate origin or search exists.
	token, e := readBounded(tokenFD, 4096)
	if e != nil || len(token) == 0 {
		return zero, refuse("AUTH_REFUSED")
	}
	defer clear(token)
	for _, b := range token {
		if b < 0x21 || b > 0x7e {
			return zero, refuse("AUTH_REFUSED")
		}
	}
	endpoint := c.policy.Origin + "/_matrix/client/v3/rooms/" + url.PathEscape(c.policy.Room) + "/event/" + url.PathEscape(eventID)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if e != nil {
		return zero, refuse("AUTH_REFUSED")
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Transport: c.http, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		return zero, refuse("AUTH_REFUSED")
	}
	b, e := readResponse(resp)
	if e != nil {
		return zero, refuse("AUTH_REFUSED")
	}
	a, e := c.verifyEvent(b, eventID)
	if e != nil {
		return zero, refuse("AUTH_REFUSED")
	}
	return a, nil
}

func readResponse(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, refuse("AUTH_REFUSED")
	}
	b, readErr := readBounded(resp.Body, maxEvent)
	closeErr := resp.Body.Close()
	media, parameters, mediaErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if readErr != nil || closeErr != nil || resp.StatusCode != http.StatusOK || resp.ContentLength > maxEvent || (resp.ContentLength >= 0 && resp.ContentLength != int64(len(b))) || resp.Header.Get("Content-Encoding") != "" || len(resp.Header.Values("Content-Type")) != 1 || mediaErr != nil || media != "application/json" || len(parameters) > 1 || (len(parameters) == 1 && strings.ToLower(parameters["charset"]) != "utf-8") {
		return nil, refuse("AUTH_REFUSED")
	}
	return b, nil
}

func decodeString(b json.RawMessage) string { var s string; _ = json.Unmarshal(b, &s); return s }

func (c *Control) verifyEvent(b []byte, eventID string) (authenticated, error) {
	var zero authenticated
	m, e := object(b, []string{"event_id", "room_id", "sender", "type", "origin_server_ts", "content"}, []string{"unsigned"})
	if e != nil {
		return zero, e
	}
	if decodeString(m["event_id"]) != eventID || decodeString(m["room_id"]) != c.policy.Room || decodeString(m["sender"]) != c.policy.Issuer || decodeString(m["type"]) != eventKind {
		return zero, refuse("EVENT_BINDING")
	}
	if raw, ok := m["unsigned"]; ok {
		u, e := object(raw, nil, []string{"age"})
		if e != nil {
			return zero, e
		}
		if age, ok := u["age"]; ok {
			var n int64
			if json.Unmarshal(age, &n) != nil || n < 0 || strings.TrimSpace(string(age)) != strconv.FormatInt(n, 10) {
				return zero, refuse("EVENT_METADATA")
			}
		}
	}
	content, e := object(m["content"], []string{"body"}, nil)
	if e != nil {
		return zero, e
	}
	// Canonical grant bytes live in a string: homeserver JSON reserialization
	// may reorder objects, but cannot reorder characters inside content.body.
	var body string
	if json.Unmarshal(content["body"], &body) != nil {
		return zero, refuse("EVENT_BODY")
	}
	var g Grant
	if e = canonical([]byte(body), &g, maxGrant); e != nil {
		return zero, e
	}
	if e = c.checkGrant(g); e != nil {
		return zero, e
	}
	var stamp int64
	if json.Unmarshal(m["origin_server_ts"], &stamp) != nil || stamp <= 0 || stamp/1000 < g.IssuedAt || stamp/1000 >= g.StartNoLaterThan || stamp > c.now().UnixMilli() {
		return zero, refuse("EVENT_TIME")
	}
	// Normalize the authenticated event core. Server-provided unsigned.age is
	// transient and cannot make the same event a new request or a retry conflict.
	core, _ := json.Marshal(struct {
		Event     string `json:"event_id"`
		Room      string `json:"room_id"`
		Sender    string `json:"sender"`
		Kind      string `json:"type"`
		Timestamp int64  `json:"origin_server_ts"`
		Grant     Grant  `json:"grant"`
	}{eventID, c.policy.Room, c.policy.Issuer, eventKind, stamp, g})
	return authenticated{grant: g, eventID: eventID, eventSHA: digest(core), requestSHA: digest([]byte(body))}, nil
}

func (c *Control) checkGrant(g Grant) error {
	p := c.policy
	if g.Schema != "g07-grant/1" || !identifier.MatchString(g.Operation) || g.Issuer != p.Issuer || g.Custodian != p.Custodian || g.Executor != p.Executor || g.Recipient != p.Executor || g.Task != p.Task || g.Slot != p.Slot || g.Binding != p.Binding || g.EntryCount != 1 || !g.InspectThenInvoke || g.OuterSeconds != 1260 {
		return refuse("GRANT_BINDING")
	}
	for _, spent := range p.SpentOperations {
		if g.Operation == spent {
			return refuse("HISTORIC_SPENT")
		}
	}
	return c.checkClock(g)
}

func (c *Control) checkClock(g Grant) error {
	// Positive bounded Unix seconds avoid overflow in timestamp arithmetic.
	if g.IssuedAt <= 0 || g.IssuedAt > 253402300799 || g.StartNoLaterThan <= g.IssuedAt || g.StartNoLaterThan-g.IssuedAt > 600 || g.StartNoLaterThan > 253402300799 {
		return refuse("CLOCK_REFUSED")
	}
	n := c.now()
	if n.Before(time.Unix(g.IssuedAt, 0)) || !n.Before(time.Unix(g.StartNoLaterThan, 0)) {
		return refuse("CLOCK_REFUSED")
	}
	return nil
}
