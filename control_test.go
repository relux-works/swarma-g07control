package g07control

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// All authority, domains, tokens, TLS certificates and stores here are
// synthetic fixtures. No fixture is a production prerequisite disposition.
type fixture struct {
	t          *testing.T
	dir        string
	policy     Policy
	grant      Grant
	server     *httptest.Server
	mu         sync.Mutex
	body       []byte
	status     int
	header     http.Header
	requests   atomic.Int32
	badRequest atomic.Bool
	policyPath string
	gate       chan struct{}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func put(t *testing.T, path string, b []byte) {
	t.Helper()
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir, e := os.MkdirTemp("/private/tmp", "g07-fixture-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := os.RemoveAll(dir); e != nil {
			t.Error("fixture cleanup", e)
		}
	})
	if e = os.Mkdir(filepath.Join(dir, "store"), 0700); e != nil {
		t.Fatal(e)
	}
	x := &fixture{t: t, dir: dir, status: 200, header: make(http.Header)}
	x.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := x.requests.Add(1)
		expected := "/_matrix/client/v3/rooms/" + x.policy.Room + "/event/$synthetic-event"
		if r.Method != "GET" || r.URL.Path != expected || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer synthetic-fixture-token" {
			x.badRequest.Store(true)
			w.WriteHeader(403)
			return
		}
		x.mu.Lock()
		gate := x.gate
		x.mu.Unlock()
		if gate != nil {
			if n == 2 {
				close(gate)
			}
			select {
			case <-gate:
			case <-time.After(5 * time.Second):
				w.WriteHeader(503)
				return
			}
		}
		x.mu.Lock()
		defer x.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		for k, v := range x.header {
			w.Header()[k] = v
		}
		w.WriteHeader(x.status)
		_, _ = w.Write(x.body)
	}))
	x.server.Config.ErrorLog = nil
	x.server.StartTLS()
	t.Cleanup(x.server.Close)
	p := Policy{Schema: "g07-policy/1", Origin: x.server.URL, TLSRootsPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x.server.Certificate().Raw})), Room: "!synthetic-room:fixture.invalid", Issuer: "@synthetic_keeper:fixture.invalid", Custodian: "@synthetic_keeper:fixture.invalid", Executor: "@synthetic_keeper:fixture.invalid", Task: "TASK-synthetic-host", Slot: "synthetic-frozen-execution-slot", RuntimeRoots: [3]string{"/unopened-runtime-R", "/unopened-runtime-E", "/unopened-runtime-K"}, SpentOperations: []string{"host091-u27-20261105T224419Z"}}
	b := Binding{}
	// Distinct pins make field transposition detectable.
	b = Binding{digest([]byte("revision")), digest([]byte("source")), digest([]byte("control-source")), digest([]byte("qualification")), digest([]byte("compiler")), digest([]byte("build-argv")), digest([]byte("build-env")), digest([]byte("artifact")), digest([]byte("artifact-locator")), digest([]byte("entry-argv")), digest([]byte("entry-env")), digest([]byte("entry-command")), digest([]byte(p.RuntimeRoots[0])), digest([]byte(p.RuntimeRoots[1])), digest([]byte(p.RuntimeRoots[2])), digest([]byte("ledger")), digest([]byte("operations")), digest([]byte("boundary")), digest([]byte("source-agreement")), digest([]byte("immutable-inputs"))}
	p.Binding = b
	s, e := os.Stat(filepath.Join(dir, "store"))
	if e != nil {
		t.Fatal(e)
	}
	ss := s.Sys().(*syscall.Stat_t)
	p.Store = StoreAnchor{filepath.Join(dir, "store"), uint64(ss.Dev), ss.Ino}
	custody := Custody{"g07-custody/1", "ADMITTED_SOURCE_REVIEW_QUALIFICATION_BOUNDARY", "ADMITTED_META_TO_KEEPER_SOURCE_CUSTODY_ATTESTATION", p.Custodian, p.Executor, p.Task, p.Slot, p.Binding, digest([]byte("attestation")), digest([]byte("source-review")), digest([]byte("control-review")), digest([]byte("execution-acceptance")), digest([]byte("root-inspection"))}
	cb := mustJSON(t, custody)
	p.CustodySHA256 = digest(cb)
	put(t, filepath.Join(dir, "store", "custody.json"), cb)
	x.policy = p
	x.policyPath = filepath.Join(dir, "policy.json")
	x.savePolicy()
	now := time.Now().Unix()
	x.grant = Grant{"g07-grant/1", "synthetic-operation-1", p.Issuer, p.Custodian, p.Executor, p.Executor, p.Task, p.Slot, 1, true, p.Binding, now - 1, now + 300, 1260}
	x.setGrant(x.grant)
	return x
}

func (x *fixture) savePolicy() { put(x.t, x.policyPath, mustJSON(x.t, x.policy)) }
func (x *fixture) event(g Grant) []byte {
	return mustJSON(x.t, struct {
		Event     string `json:"event_id"`
		Room      string `json:"room_id"`
		Sender    string `json:"sender"`
		Type      string `json:"type"`
		Timestamp int64  `json:"origin_server_ts"`
		Content   struct {
			Body string `json:"body"`
		} `json:"content"`
	}{"$synthetic-event", x.policy.Room, x.policy.Issuer, eventKind, g.IssuedAt * 1000, struct {
		Body string `json:"body"`
	}{string(mustJSON(x.t, g))}})
}
func alterGrant(t *testing.T, b []byte, change func([]byte) []byte) []byte {
	t.Helper()
	var event map[string]any
	if e := json.Unmarshal(b, &event); e != nil {
		t.Fatal(e)
	}
	content := event["content"].(map[string]any)
	content["body"] = string(change([]byte(content["body"].(string))))
	return mustJSON(t, event)
}
func (x *fixture) setGrant(g Grant) { x.setBody(x.event(g)) }
func (x *fixture) setBody(b []byte) { x.mu.Lock(); x.body = b; x.mu.Unlock() }

func openFixture(t *testing.T, policyPath string) *Control {
	t.Helper()
	f, e := os.Open(policyPath)
	if e != nil {
		t.Fatal(e)
	}
	c, e := Open(f)
	_ = f.Close()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func (x *fixture) open() *Control { return openFixture(x.t, x.policyPath) }

func token(t *testing.T, value string) *os.File {
	t.Helper()
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = w.WriteString(value); e != nil {
		t.Fatal(e)
	}
	_ = w.Close()
	t.Cleanup(func() { _ = r.Close() })
	return r
}
func consume(t *testing.T, c *Control) (Receipt, error) {
	t.Helper()
	return c.Consume(context.Background(), "$synthetic-event", token(t, "synthetic-fixture-token"))
}
func noClaim(t *testing.T, x *fixture) {
	t.Helper()
	_, e := os.Lstat(filepath.Join(x.policy.Store.Path, claimName(x.policy.Slot)))
	if !os.IsNotExist(e) {
		t.Fatal("refusal created a claim")
	}
}
func code(e error) string {
	var r *Refusal
	if errors.As(e, &r) {
		return r.Code
	}
	if e == nil {
		return ""
	}
	return "OTHER"
}
func assertNoAuthority(t *testing.T, r Receipt, e error) {
	t.Helper()
	if r.Outcome == "NEWLY_CONSUMED" || e == nil {
		t.Fatalf("expected refusal without authority: outcome=%s code=%s", r.Outcome, code(e))
	}
}

func TestAuthenticatedOneUse(t *testing.T) {
	x := newFixture(t)
	c := x.open()
	r, e := consume(t, c)
	if e != nil || r.Outcome != "NEWLY_CONSUMED" || r.EventID != "$synthetic-event" || r.RequestSHA256 != digest(mustJSON(t, x.grant)) || r.SlotSHA256 != digest([]byte(x.policy.Slot)) {
		t.Fatalf("valid neighbor: %s %s", r.Outcome, code(e))
	}
	b, e := os.ReadFile(filepath.Join(x.policy.Store.Path, claimName(x.policy.Slot)))
	if e != nil || digest(b) != r.RecordSHA256 {
		t.Fatal("receipt record binding")
	}
	r, e = consume(t, c)
	if e != nil || r.Outcome != "INSPECTION_ONLY" {
		t.Fatalf("matching retry must inspect only: %s %s", r.Outcome, code(e))
	}
	g := x.grant
	g.Operation = "synthetic-operation-2"
	x.setGrant(g)
	r, e = consume(t, c)
	assertNoAuthority(t, r, e)
	if code(e) != "SLOT_CONFLICT" {
		t.Fatal("changed operation must conflict", code(e))
	}
	x.setGrant(x.grant)
	r, e = consume(t, c)
	if e != nil || r.Outcome != "INSPECTION_ONLY" {
		t.Fatal("conflict must not reset slot")
	}
	if x.badRequest.Load() || x.requests.Load() != 4 {
		t.Fatal("exact endpoint/token not used")
	}
}

func TestAuthenticationRequired(t *testing.T) {
	// Valid neighbor runs in a distinct store immediately before the plant target.
	x := newFixture(t)
	c := x.open()
	r, e := consume(t, c)
	if e != nil || r.Outcome != "NEWLY_CONSUMED" {
		t.Fatal("valid neighbor failed")
	}
	y := newFixture(t)
	d := y.open()
	y.setBody(bytes.Replace(y.event(y.grant), []byte(`"sender":"`+y.policy.Issuer+`"`), []byte(`"sender":"@impostor:fixture.invalid"`), 1))
	r, e = consume(t, d)
	assertNoAuthority(t, r, e)
	noClaim(t, y)
}

func TestGrantRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Grant)
	}{
		{"issuer", func(g *Grant) { g.Issuer = "@impostor:fixture.invalid" }},
		{"custodian", func(g *Grant) { g.Custodian = "@impostor:fixture.invalid" }},
		{"executor", func(g *Grant) { g.Executor = "@impostor:fixture.invalid" }},
		{"recipient", func(g *Grant) { g.Recipient = "@impostor:fixture.invalid" }},
		{"task", func(g *Grant) { g.Task = "TASK-other" }},
		{"slot", func(g *Grant) { g.Slot = "other-slot" }},
		{"digest", func(g *Grant) { g.Binding.Artifact = digest([]byte("other")) }},
		{"uppercase_digest", func(g *Grant) { g.Binding.Revision = strings.ToUpper(g.Binding.Revision) }},
		{"count", func(g *Grant) { g.EntryCount = 2 }},
		{"inspect", func(g *Grant) { g.InspectThenInvoke = false }},
		{"runtime_deadline", func(g *Grant) { g.OuterSeconds = 1261 }},
		{"spent", func(g *Grant) { g.Operation = "host091-u27-20261105T224419Z" }},
		{"unbounded_id", func(g *Grant) { g.Operation = strings.Repeat("x", 129) }},
		{"future", func(g *Grant) { g.IssuedAt = time.Now().Unix() + 100; g.StartNoLaterThan = g.IssuedAt + 100 }},
		{"expired", func(g *Grant) { g.IssuedAt = time.Now().Unix() - 100; g.StartNoLaterThan = time.Now().Unix() - 1 }},
		{"zero_window", func(g *Grant) { g.StartNoLaterThan = g.IssuedAt }},
		{"overlong_window", func(g *Grant) { g.StartNoLaterThan = g.IssuedAt + 601 }},
		{"negative", func(g *Grant) { g.IssuedAt = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := newFixture(t)
			g := x.grant
			tc.change(&g)
			x.setGrant(g)
			r, e := consume(t, x.open())
			assertNoAuthority(t, r, e)
			noClaim(t, x)
		})
	}
}

func TestEvidenceRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func([]byte, *fixture) []byte
	}{
		{"wrong_sender", func(b []byte, x *fixture) []byte {
			return bytes.Replace(b, []byte(`"sender":"`+x.policy.Issuer+`"`), []byte(`"sender":"@impostor:fixture.invalid"`), 1)
		}},
		{"wrong_room", func(b []byte, x *fixture) []byte {
			return bytes.Replace(b, []byte(`"room_id":"`+x.policy.Room+`"`), []byte(`"room_id":"!other"`), 1)
		}},
		{"wrong_event", func(b []byte, _ *fixture) []byte {
			return bytes.Replace(b, []byte("$synthetic-event"), []byte("$other-event"), 1)
		}},
		{"wrong_kind", func(b []byte, _ *fixture) []byte {
			return bytes.Replace(b, []byte(eventKind), []byte("m.room.message"), 1)
		}},
		{"redacted", func(b []byte, _ *fixture) []byte {
			return append(append([]byte{}, b[:len(b)-1]...), []byte(`,"unsigned":{"redacted_because":{}}}`)...)
		}},
		{"relation", func(b []byte, _ *fixture) []byte {
			return bytes.Replace(b, []byte(`"content":{`), []byte(`"content":{"m.relates_to":{},`), 1)
		}},
		{"duplicate_sender", func(b []byte, _ *fixture) []byte {
			return append([]byte(`{"sender":"@impostor:fixture.invalid",`), b[1:]...)
		}},
		{"duplicate_grant", func(b []byte, x *fixture) []byte {
			return alterGrant(x.t, b, func(g []byte) []byte {
				return bytes.Replace(g, []byte(`"entry_count":1`), []byte(`"entry_count":1,"entry_count":1`), 1)
			})
		}},
		{"unknown_grant", func(b []byte, x *fixture) []byte {
			return alterGrant(x.t, b, func(g []byte) []byte {
				return bytes.Replace(g, []byte(`"entry_count":1`), []byte(`"unknown":true,"entry_count":1`), 1)
			})
		}},
		{"case_alias", func(b []byte, _ *fixture) []byte { return bytes.Replace(b, []byte(`"sender"`), []byte(`"Sender"`), 1) }},
		{"missing_grant_field", func(b []byte, x *fixture) []byte {
			return alterGrant(x.t, b, func(g []byte) []byte { return bytes.Replace(g, []byte(`"entry_count":1,`), nil, 1) })
		}},
		{"noncanonical_grant", func(b []byte, x *fixture) []byte {
			return alterGrant(x.t, b, func(g []byte) []byte {
				return bytes.Replace(g, []byte(`"entry_count":1`), []byte(`"entry_count": 1`), 1)
			})
		}},
		{"truncated", func(b []byte, _ *fixture) []byte { return b[:len(b)/2] }},
		{"oversized", func(_ []byte, _ *fixture) []byte { return bytes.Repeat([]byte(" "), maxEvent+1) }},
		{"trailing", func(b []byte, _ *fixture) []byte { return append(b, []byte(`{}`)...) }},
		{"null_content", func(b []byte, _ *fixture) []byte {
			return bytes.Replace(b, []byte(`"content":{`), []byte(`"content":null,"other":{`), 1)
		}},
		{"bad_unsigned", func(b []byte, _ *fixture) []byte {
			return append(append([]byte{}, b[:len(b)-1]...), []byte(`,"unsigned":{"age":-1}}`)...)
		}},
		{"null_age", func(b []byte, _ *fixture) []byte {
			return append(append([]byte{}, b[:len(b)-1]...), []byte(`,"unsigned":{"age":null}}`)...)
		}},
		{"unknown_metadata", func(b []byte, _ *fixture) []byte {
			return append(append([]byte{}, b[:len(b)-1]...), []byte(`,"state_key":""}`)...)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := newFixture(t)
			x.setBody(tc.change(x.body, x))
			r, e := consume(t, x.open())
			assertNoAuthority(t, r, e)
			noClaim(t, x)
		})
	}
}

func TestHomeserverReserialization(t *testing.T) {
	x := newFixture(t)
	c := x.open()
	var event map[string]any
	if e := json.Unmarshal(x.body, &event); e != nil {
		t.Fatal(e)
	}
	event["unsigned"] = map[string]any{"age": 10}
	b, e := json.MarshalIndent(event, "", " ")
	if e != nil {
		t.Fatal(e)
	}
	x.setBody(b)
	r, e := consume(t, c)
	if e != nil || r.Outcome != "NEWLY_CONSUMED" {
		t.Fatal("server object serialization must preserve canonical string body", code(e))
	}
	event["unsigned"] = map[string]any{"age": 20}
	x.setBody(mustJSON(t, event))
	r, e = consume(t, c)
	if e != nil || r.Outcome != "INSPECTION_ONLY" {
		t.Fatal("unsigned age must not change event identity", code(e))
	}
}

func TestPolicyRefusals(t *testing.T) {
	for _, name := range []string{"http", "url_path", "url_query", "url_user", "url_fragment", "bad_ca", "empty_ca", "missing_room", "missing_issuer", "missing_slot", "missing_digest", "policy_mode", "policy_duplicate", "policy_unknown", "missing_descriptor"} {
		t.Run(name, func(t *testing.T) {
			x := newFixture(t)
			switch name {
			case "http":
				x.policy.Origin = strings.Replace(x.policy.Origin, "https:", "http:", 1)
			case "url_path":
				x.policy.Origin += "/alternate"
			case "url_query":
				x.policy.Origin += "?alternate=1"
			case "url_user":
				x.policy.Origin = strings.Replace(x.policy.Origin, "https://", "https://caller@", 1)
			case "url_fragment":
				x.policy.Origin += "#alternate"
			case "bad_ca":
				x.policy.TLSRootsPEM = "not a certificate"
			case "empty_ca":
				x.policy.TLSRootsPEM = ""
			case "missing_room":
				x.policy.Room = ""
			case "missing_issuer":
				x.policy.Issuer = ""
			case "missing_slot":
				x.policy.Slot = ""
			case "missing_digest":
				x.policy.Binding.Qualification = ""
			}
			x.savePolicy()
			if name == "policy_mode" {
				if e := os.Chmod(x.policyPath, 0644); e != nil {
					t.Fatal(e)
				}
			}
			if name == "policy_duplicate" || name == "policy_unknown" {
				b, e := os.ReadFile(x.policyPath)
				if e != nil {
					t.Fatal(e)
				}
				prefix := `{"schema":"g07-policy/1",`
				if name == "policy_unknown" {
					prefix = `{"caller_authorized":true,`
				}
				put(t, x.policyPath, append([]byte(prefix), b[1:]...))
			}
			var f *os.File
			var e error
			if name != "missing_descriptor" {
				f, e = os.Open(x.policyPath)
				if e != nil {
					t.Fatal(e)
				}
				defer f.Close()
			}
			c, e := Open(f)
			if c != nil {
				c.Close()
			}
			if code(e) != "POLICY_REFUSED" {
				t.Fatal("caller policy granted authority", code(e))
			}
			noClaim(t, x)
		})
	}
}

func TestExplicitTrustIgnoresAmbient(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", "/private/no-ambient-certificate")
	t.Setenv("SSL_CERT_DIR", "/private/no-ambient-certificate-directory")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	x := newFixture(t)
	r, e := consume(t, x.open())
	if e != nil || r.Outcome != "NEWLY_CONSUMED" {
		t.Fatal("explicit custodian roots and direct selected origin required", code(e))
	}
}

func TestTransportRefusals(t *testing.T) {
	for _, name := range []string{"untrusted_tls", "wrong_tls_name", "redirect", "http_error", "compressed", "wrong_mime", "malformed_mime", "duplicate_mime", "truncated_wire", "unavailable", "token", "missing_token"} {
		t.Run(name, func(t *testing.T) {
			x := newFixture(t)
			c := x.open()
			switch name {
			case "untrusted_tls":
				c.http.TLSClientConfig.RootCAs = x509.NewCertPool()
			case "wrong_tls_name":
				c.http.TLSClientConfig.ServerName = "wrong.fixture.invalid"
			case "redirect":
				x.status = 302
				x.header.Set("Location", x.server.URL+"/alternate")
			case "http_error":
				x.status = 503
			case "compressed":
				x.header.Set("Content-Encoding", "gzip")
			case "wrong_mime":
				x.header.Set("Content-Type", "text/plain")
			case "malformed_mime":
				x.header.Set("Content-Type", "application/json; charset=\"")
			case "duplicate_mime":
				x.header["Content-Type"] = []string{"application/json", "application/json"}
			case "truncated_wire":
				x.header.Set("Content-Length", fmt.Sprint(len(x.body)+20))
			case "unavailable":
				x.server.Close()
			}
			var r Receipt
			var e error
			if name == "token" {
				r, e = c.Consume(context.Background(), "$synthetic-event", token(t, "bad token\n"))
			} else if name == "missing_token" {
				r, e = c.Consume(context.Background(), "$synthetic-event", nil)
			} else {
				r, e = consume(t, c)
			}
			assertNoAuthority(t, r, e)
			noClaim(t, x)
			if x.requests.Load() > 1 {
				t.Fatal("redirect followed or request retried")
			}
		})
	}
}

func TestClockRecheckedAfterDurability(t *testing.T) {
	x := newFixture(t)
	c := x.open()
	now := time.Unix(x.grant.IssuedAt+2, 0)
	c.now = func() time.Time { return now }
	c.checkpoint = func(stage string) error {
		if stage == "after_dir_sync" {
			now = time.Unix(x.grant.StartNoLaterThan, 0)
		}
		return nil
	}
	r, e := consume(t, c)
	assertNoAuthority(t, r, e)
	if code(e) != "CLOCK_REFUSED" {
		t.Fatal("expected expiry at final boundary", code(e))
	}
	if _, e = os.Stat(filepath.Join(x.policy.Store.Path, claimName(x.policy.Slot))); e != nil {
		t.Fatal("expiry must retain durable slot")
	}
	c.checkpoint = func(string) error { return nil }
	now = time.Unix(x.grant.IssuedAt+2, 0)
	r, e = consume(t, c)
	if e != nil || r.Outcome != "INSPECTION_ONLY" {
		t.Fatal("clock refusal cannot reset claim")
	}
}

func TestClockEdges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int64
		window int64
		want   bool
	}{{"issued_equal", 0, 600, true}, {"before_latest", 599, 600, true}, {"latest_equal", 600, 600, false}, {"before_issued", -1, 600, false}} {
		t.Run(tc.name, func(t *testing.T) {
			x := newFixture(t)
			g := x.grant
			g.StartNoLaterThan = g.IssuedAt + tc.window
			x.setGrant(g)
			c := x.open()
			c.now = func() time.Time { return time.Unix(g.IssuedAt+tc.offset, 0) }
			r, e := consume(t, c)
			if tc.want {
				if e != nil || r.Outcome != "NEWLY_CONSUMED" {
					t.Fatal("clock valid neighbor", code(e))
				}
			} else {
				assertNoAuthority(t, r, e)
				noClaim(t, x)
			}
		})
	}
}

func TestClockNanosecondBeforeLatest(t *testing.T) {
	x := newFixture(t)
	c := x.open()
	c.now = func() time.Time { return time.Unix(x.grant.StartNoLaterThan, 0).Add(-time.Nanosecond) }
	r, e := consume(t, c)
	if e != nil || r.Outcome != "NEWLY_CONSUMED" || r.StartNoLaterThan != x.grant.StartNoLaterThan {
		t.Fatal("last nanosecond remains within the start window", code(e))
	}
}

func TestFsyncRequired(t *testing.T) {
	// Both valid neighbors use actual file and directory fsync.
	x := newFixture(t)
	r, e := consume(t, x.open())
	if e != nil || r.Outcome != "NEWLY_CONSUMED" {
		t.Fatal("valid fsync neighbor")
	}
	for _, name := range []string{"file", "directory"} {
		t.Run(name, func(t *testing.T) {
			y := newFixture(t)
			c := y.open()
			if name == "file" {
				c.fileSync = func(*os.File) error { return syscall.EIO }
			} else {
				c.dirSync = func(*os.File) error { return syscall.EIO }
			}
			r, e := consume(t, c)
			assertNoAuthority(t, r, e)
			if code(e) != "HELD_UNCERTAIN" {
				t.Fatal("fsync failure must hold")
			}
			c.fileSync = (*os.File).Sync
			c.dirSync = (*os.File).Sync
			r, e = consume(t, c)
			if r.Outcome == "NEWLY_CONSUMED" {
				t.Fatal("failed fsync claim reused")
			}
			if e != nil && code(e) != "HELD_UNCERTAIN" {
				t.Fatal(code(e))
			}
		})
	}
}

func TestWriteAndBoundaryFailures(t *testing.T) {
	for _, name := range []string{"short_write", "write_error", "after_create", "after_write", "after_file_sync", "after_dir_sync", "before_receipt"} {
		t.Run(name, func(t *testing.T) {
			x := newFixture(t)
			c := x.open()
			if name == "short_write" {
				c.write = func(f *os.File, b []byte) (int, error) { return f.Write(b[:len(b)/2]) }
			} else if name == "write_error" {
				c.write = func(*os.File, []byte) (int, error) { return 0, syscall.ENOSPC }
			} else {
				c.checkpoint = func(stage string) error {
					if stage == name {
						return syscall.EIO
					}
					return nil
				}
			}
			r, e := consume(t, c)
			assertNoAuthority(t, r, e)
			c.checkpoint = func(string) error { return nil }
			c.write = (*os.File).Write
			r, e = consume(t, c)
			if r.Outcome == "NEWLY_CONSUMED" {
				t.Fatal("partial claim replayed")
			}
			if e == nil && r.Outcome != "INSPECTION_ONLY" {
				t.Fatal("bad inspection outcome")
			}
		})
	}
}

func TestExistingClaimsHold(t *testing.T) {
	for _, name := range []string{"empty", "partial", "invalid", "oversize", "directory", "symlink", "hardlink", "mode"} {
		t.Run(name, func(t *testing.T) {
			x := newFixture(t)
			path := filepath.Join(x.policy.Store.Path, claimName(x.policy.Slot))
			switch name {
			case "directory":
				if e := os.Mkdir(path, 0700); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Symlink("custody.json", path); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(filepath.Join(x.policy.Store.Path, "custody.json"), path); e != nil {
					t.Fatal(e)
				}
			default:
				b := []byte{}
				if name == "partial" {
					b = []byte(`{"schema":`)
				}
				if name == "invalid" {
					b = []byte(`{}`)
				}
				if name == "oversize" {
					b = bytes.Repeat([]byte("x"), maxRecord+1)
				}
				put(t, path, b)
				if name == "mode" {
					if e := os.Chmod(path, 0644); e != nil {
						t.Fatal(e)
					}
				}
			}
			// A custody hardlink also invalidates the prerequisite, conservatively.
			f, e := os.Open(x.policyPath)
			if e != nil {
				t.Fatal(e)
			}
			c, e := Open(f)
			_ = f.Close()
			if e != nil {
				if name != "hardlink" {
					t.Fatal("unexpected open refusal", code(e))
				}
				return
			}
			defer c.Close()
			r, e := consume(t, c)
			assertNoAuthority(t, r, e)
			if code(e) != "HELD_UNCERTAIN" {
				t.Fatal("existing damaged claim must hold", code(e))
			}
		})
	}
}

func TestPrerequisites(t *testing.T) {
	for _, name := range []string{"missing", "changed", "unadmitted", "wrong_route", "wrong_binding", "incomplete_review", "untrusted_pin"} {
		t.Run(name, func(t *testing.T) {
			x := newFixture(t)
			path := filepath.Join(x.policy.Store.Path, "custody.json")
			b, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			var v Custody
			if e = json.Unmarshal(b, &v); e != nil {
				t.Fatal(e)
			}
			switch name {
			case "missing":
				if e = os.Remove(path); e != nil {
					t.Fatal(e)
				}
			case "changed":
				put(t, path, append(b, ' '))
			case "unadmitted":
				v.State = "PREPARATION_ONLY"
			case "wrong_route":
				v.Route = "DIRECT_SOURCE_READ"
			case "wrong_binding":
				v.Binding.SourceAgreement = digest([]byte("replacement"))
			case "incomplete_review":
				v.ControlReview = ""
			case "untrusted_pin":
				x.policy.CustodySHA256 = digest([]byte("other"))
				x.savePolicy()
			}
			if name == "unadmitted" || name == "wrong_route" || name == "wrong_binding" || name == "incomplete_review" {
				b = mustJSON(t, v)
				put(t, path, b)
				x.policy.CustodySHA256 = digest(b)
				x.savePolicy()
			}
			f, e := os.Open(x.policyPath)
			if e != nil {
				t.Fatal(e)
			}
			c, e := Open(f)
			_ = f.Close()
			if c != nil {
				c.Close()
			}
			if code(e) != "PREREQUISITE_REFUSED" {
				t.Fatal("prerequisite admitted", code(e))
			}
			noClaim(t, x)
			if x.requests.Load() != 0 {
				t.Fatal("authentication before prerequisite")
			}
		})
	}
}

func TestAnchors(t *testing.T) {
	for _, name := range []string{"missing_store", "symlink_store", "wrong_inode", "writable_ancestor", "mode_store", "overlap_R", "overlap_E", "overlap_K", "replace_before_auth", "replace_after_write", "replace_after_sync", "custody_changed_after_open"} {
		t.Run(name, func(t *testing.T) {
			x := newFixture(t)
			switch name {
			case "missing_store":
				if e := os.Rename(x.policy.Store.Path, x.policy.Store.Path+"-old"); e != nil {
					t.Fatal(e)
				}
			case "symlink_store":
				if e := os.Rename(x.policy.Store.Path, x.policy.Store.Path+"-old"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(x.policy.Store.Path+"-old", x.policy.Store.Path); e != nil {
					t.Fatal(e)
				}
			case "wrong_inode":
				x.policy.Store.Inode++
				x.savePolicy()
			case "writable_ancestor":
				if e := os.Chmod(x.dir, 0770); e != nil {
					t.Fatal(e)
				}
			case "mode_store":
				if e := os.Chmod(x.policy.Store.Path, 0755); e != nil {
					t.Fatal(e)
				}
			case "overlap_R", "overlap_E", "overlap_K":
				i := map[string]int{"overlap_R": 0, "overlap_E": 1, "overlap_K": 2}[name]
				x.policy.RuntimeRoots[i] = x.policy.Store.Path
				x.savePolicy()
			}
			if strings.HasPrefix(name, "replace_") || name == "custody_changed_after_open" {
				c := x.open()
				replace := func() {
					if e := os.Rename(x.policy.Store.Path, x.policy.Store.Path+"-old"); e != nil {
						t.Fatal(e)
					}
					if e := os.Mkdir(x.policy.Store.Path, 0700); e != nil {
						t.Fatal(e)
					}
				}
				if name == "replace_before_auth" {
					replace()
				} else if name == "custody_changed_after_open" {
					put(t, filepath.Join(x.policy.Store.Path, "custody.json"), []byte(`{}`))
				} else {
					stage := "after_write"
					if name == "replace_after_sync" {
						stage = "after_dir_sync"
					}
					c.checkpoint = func(s string) error {
						if s == stage {
							replace()
						}
						return nil
					}
				}
				r, e := consume(t, c)
				assertNoAuthority(t, r, e)
			} else {
				f, e := os.Open(x.policyPath)
				if e != nil {
					t.Fatal(e)
				}
				c, e := Open(f)
				_ = f.Close()
				if c != nil {
					c.Close()
				}
				if e == nil {
					t.Fatal("bad anchor admitted")
				}
				if strings.HasPrefix(name, "overlap_") && code(e) != "OWN_ANCHOR_INCOMPATIBILITY" {
					t.Fatal("runtime overlap requires explicit OWN-ANCHOR refusal", code(e))
				}
			}
		})
	}
}

// Subprocess helpers inherit only this already isolated namespace. They use the
// same actual TLS fetch/Consume path, with a synthetic CA installed by test code.
func TestProcessHelper(t *testing.T) {
	if os.Getenv("G07_CHILD") != "1" {
		return
	}
	c := openFixture(t, os.Getenv("G07_POLICY"))
	stage := os.Getenv("G07_CRASH")
	c.checkpoint = func(s string) error {
		if s == stage {
			os.Exit(73)
		}
		return nil
	}
	r, e := consume(t, c)
	fmt.Printf("CHILD_OUTCOME=%s CODE=%s\n", r.Outcome, code(e))
}

func child(x *fixture, stage string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessHelper$", "-test.timeout=20s")
	cmd.Env = append(os.Environ(), "G07_CHILD=1", "G07_POLICY="+x.policyPath, "G07_CRASH="+stage)
	return cmd
}

func TestConcurrentProcesses(t *testing.T) {
	x := newFixture(t)
	x.mu.Lock()
	x.gate = make(chan struct{})
	x.mu.Unlock()
	first, second := child(x, ""), child(x, "")
	var a, b bytes.Buffer
	first.Stdout = &a
	first.Stderr = &a
	second.Stdout = &b
	second.Stderr = &b
	if e := first.Start(); e != nil {
		t.Fatal(e)
	}
	if e := second.Start(); e != nil {
		t.Fatal(e)
	}
	e1, e2 := first.Wait(), second.Wait()
	if e1 != nil || e2 != nil {
		t.Fatalf("child failure: %v %v %s %s", e1, e2, a.String(), b.String())
	}
	out := a.String() + b.String()
	if strings.Count(out, "CHILD_OUTCOME=NEWLY_CONSUMED ") != 1 || strings.Count(out, "CHILD_OUTCOME=INSPECTION_ONLY ") != 1 {
		t.Fatalf("exactly one concurrent new receipt required: %s", out)
	}
	x.mu.Lock()
	x.gate = nil
	x.mu.Unlock()
	r, e := consume(t, x.open())
	if e != nil || r.Outcome != "INSPECTION_ONLY" {
		t.Fatal("post-process retry authority")
	}
}

func TestDurableSyscalls(t *testing.T) {
	x := newFixture(t)
	tracePath := filepath.Join(x.dir, "synthetic-syscalls.txt")
	cmd := child(x, "")
	args := append([]string{"-f", "-qq", "-yy", "-s", "0", "-e", "trace=fsync,openat,write,flock", "-o", tracePath}, cmd.Args...)
	traced := exec.Command("/usr/bin/strace", args...)
	traced.Env = cmd.Env
	out, e := traced.CombinedOutput()
	if e != nil {
		t.Fatalf("syscall witness helper failed: %v %s", e, out)
	}
	if !bytes.Contains(out, []byte("CHILD_OUTCOME=NEWLY_CONSUMED ")) {
		t.Fatal("syscall valid neighbor did not consume")
	}
	b, e := os.ReadFile(tracePath)
	if e != nil {
		t.Fatal(e)
	}
	claimSync, dirSync, receiptWrite := -1, -1, -1
	for i, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "fsync(") && strings.Contains(line, x.policy.Store.Path+"/"+claimName(x.policy.Slot)) && strings.Contains(line, "= 0") {
			claimSync = i
		}
		if strings.Contains(line, "fsync(") && strings.Contains(line, x.policy.Store.Path+">") && strings.Contains(line, "= 0") {
			dirSync = i
		}
		if strings.Contains(line, "write(1<") && receiptWrite < 0 {
			receiptWrite = i
		}
	}
	if claimSync < 0 || dirSync <= claimSync || receiptWrite <= dirSync {
		t.Fatalf("actual file fsync < directory fsync < receipt write required; observed %d %d %d", claimSync, dirSync, receiptWrite)
	}
	t.Log("actual traced syscalls: claim fsync precedes store-directory fsync precedes receipt output")
}

func TestCrashBoundaries(t *testing.T) {
	for _, stage := range []string{"before_create", "after_create", "after_write", "after_file_sync", "after_dir_sync", "before_receipt"} {
		t.Run(stage, func(t *testing.T) {
			x := newFixture(t)
			out, e := child(x, stage).CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 73 {
				t.Fatalf("expected deliberate crash 73: %v %s", e, out)
			}
			if bytes.Contains(out, []byte("NEWLY_CONSUMED")) {
				t.Fatal("receipt before crash")
			}
			r, e := consume(t, x.open())
			if stage == "before_create" {
				if e != nil || r.Outcome != "NEWLY_CONSUMED" {
					t.Fatal("absence before claim should remain available")
				}
			} else if r.Outcome == "NEWLY_CONSUMED" {
				t.Fatal("crash allowed a second admission")
			} else if e == nil && r.Outcome != "INSPECTION_ONLY" {
				t.Fatal("invalid retry outcome")
			}
		})
	}
}

func TestLockCancellation(t *testing.T) {
	x := newFixture(t)
	a, b := x.open(), x.open()
	if e := syscall.Flock(int(a.store().Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	r, e := b.Consume(ctx, "$synthetic-event", token(t, "synthetic-fixture-token"))
	assertNoAuthority(t, r, e)
	noClaim(t, x)
	if e = syscall.Flock(int(a.store().Fd()), syscall.LOCK_UN); e != nil {
		t.Fatal(e)
	}
	r, e = consume(t, b)
	if e != nil || r.Outcome != "NEWLY_CONSUMED" {
		t.Fatal("lock valid neighbor")
	}
}

func TestNoRuntimeEffects(t *testing.T) {
	x := newFixture(t)
	r, e := consume(t, x.open())
	if e != nil || r.Outcome != "NEWLY_CONSUMED" {
		t.Fatal(code(e))
	}
	for _, root := range x.policy.RuntimeRoots {
		if _, e := os.Lstat(root); !os.IsNotExist(e) {
			t.Fatal("runtime namespace effect")
		}
	}
	entries, e := os.ReadDir(x.policy.Store.Path)
	if e != nil || len(entries) != 2 {
		t.Fatal("store should contain only custody and slot claim")
	}
}

type failedBody struct{ io.Reader }

func (failedBody) Close() error { return syscall.EIO }

func TestBoundedReadErrors(t *testing.T) {
	if _, e := readBounded(io.MultiReader(strings.NewReader("prefix"), errorReader{}), 20); e == nil {
		t.Fatal("partial read accepted")
	}
	if _, e := readBounded(strings.NewReader(strings.Repeat("x", 21)), 20); e == nil {
		t.Fatal("oversize accepted")
	}
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: failedBody{strings.NewReader(`{}`)}}
	if _, e := readResponse(resp); e == nil {
		t.Fatal("failed evidence close accepted")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, syscall.EIO }
