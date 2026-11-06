package g07control

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type anchor struct {
	file *os.File
	name string
	dev  uint64
	ino  uint64
}

// Control owns directory descriptors until Close. Do not copy a Control. Its
// mutex covers same-object calls; flock covers independent objects/processes.
// There is no exported clock, HTTP provider, durability or prerequisite bypass.
type Control struct {
	mu         sync.Mutex
	policy     Policy
	chain      []anchor
	http       *http.Transport
	now        func() time.Time
	checkpoint func(string) error
	fileSync   func(*os.File) error
	dirSync    func(*os.File) error
	write      func(*os.File, []byte) (int, error)
}

// Open reads a private custodian-owned policy descriptor and anchors an already
// provisioned store. It does not create any directory or file. Policy and
// custody admission are explicitly trusted external keeper responsibilities.
func Open(policyFD *os.File) (*Control, error) {
	b, e := readPrivate(policyFD, maxPolicy)
	if e != nil {
		return nil, refuse("POLICY_REFUSED")
	}
	var p Policy
	if canonical(b, &p, maxPolicy) != nil {
		return nil, refuse("POLICY_REFUSED")
	}
	for _, root := range p.RuntimeRoots {
		if cleanAbsolute(root) && cleanAbsolute(p.Store.Path) && overlaps(root, p.Store.Path) {
			return nil, refuse("OWN_ANCHOR_INCOMPATIBILITY")
		}
	}
	if !validPolicy(p) {
		return nil, refuse("POLICY_REFUSED")
	}
	// Explicit custodian-selected public TLS roots prevent environment variables
	// or ambient root-file discovery from replacing the selected trust policy.
	roots := x509.NewCertPool()
	if len(p.TLSRootsPEM) > 8192 || !roots.AppendCertsFromPEM([]byte(p.TLSRootsPEM)) {
		return nil, refuse("POLICY_REFUSED")
	}
	c := &Control{policy: p, http: transport(roots), now: time.Now, checkpoint: func(string) error { return nil }, fileSync: (*os.File).Sync, dirSync: (*os.File).Sync, write: (*os.File).Write}
	if e = c.openAnchors(); e != nil {
		c.Close()
		return nil, refuse("STORE_REFUSED")
	}
	if e = c.validateCustody(); e != nil {
		c.Close()
		return nil, refuse("PREREQUISITE_REFUSED")
	}
	return c, nil
}

func validPolicy(p Policy) bool {
	if p.Schema != "g07-policy/1" || !selectedOrigin(p.Origin) || !matrixRoom.MatchString(p.Room) || !matrixUser.MatchString(p.Issuer) || p.Custodian != p.Issuer || p.Executor != p.Issuer || !identifier.MatchString(p.Task) || !identifier.MatchString(p.Slot) || !validBinding(p.Binding) || !hex64.MatchString(p.CustodySHA256) || !cleanAbsolute(p.Store.Path) || p.Store.Inode == 0 || len(p.SpentOperations) == 0 || len(p.SpentOperations) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, s := range p.SpentOperations {
		if !identifier.MatchString(s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	for i, r := range p.RuntimeRoots {
		if !cleanAbsolute(r) || overlaps(r, p.Store.Path) {
			return false
		}
		for j := 0; j < i; j++ {
			if overlaps(r, p.RuntimeRoots[j]) {
				return false
			}
		}
	}
	return p.Binding.OwnedRoot == digest([]byte(p.RuntimeRoots[0])) && p.Binding.Export == digest([]byte(p.RuntimeRoots[1])) && p.Binding.KeeperSibling == digest([]byte(p.RuntimeRoots[2]))
}

func cleanAbsolute(p string) bool {
	return len(p) > 1 && len(p) <= 4096 && filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n")
}
func overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func stat(f *os.File) (*syscall.Stat_t, error) {
	var s syscall.Stat_t
	e := syscall.Fstat(int(f.Fd()), &s)
	return &s, e
}
func privateFile(f *os.File) error {
	s, e := stat(f)
	if e != nil || s.Mode&syscall.S_IFMT != syscall.S_IFREG || s.Uid != uint32(os.Geteuid()) || s.Mode&07777 != 0600 || s.Nlink != 1 {
		return errors.New("private file required")
	}
	return nil
}

func directory(f *os.File, leaf bool) error {
	s, e := stat(f)
	if e != nil || s.Mode&syscall.S_IFMT != syscall.S_IFDIR || s.Mode&07022 != 0 || (s.Uid != 0 && s.Uid != uint32(os.Geteuid())) {
		return errors.New("protected directory required")
	}
	if leaf && (s.Uid != uint32(os.Geteuid()) || s.Mode&07777 != 0700) {
		return errors.New("private owned store required")
	}
	return nil
}

func openDirAt(parent int, name string) (*os.File, error) {
	fd, e := syscall.Openat(parent, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), "control-directory"), nil
}

func (c *Control) openAnchors() error {
	f, e := openDirAt(-100, "/")
	if e != nil {
		return e
	} // Linux AT_FDCWD.
	s, e := stat(f)
	if e != nil {
		f.Close()
		return e
	}
	c.chain = append(c.chain, anchor{file: f, dev: uint64(s.Dev), ino: s.Ino})
	if e = directory(f, false); e != nil {
		return e
	}
	parts := strings.Split(strings.TrimPrefix(c.policy.Store.Path, "/"), "/")
	for i, name := range parts {
		f, e = openDirAt(int(c.chain[len(c.chain)-1].file.Fd()), name)
		if e != nil {
			return e
		}
		s, e = stat(f)
		if e != nil {
			f.Close()
			return e
		}
		c.chain = append(c.chain, anchor{file: f, name: name, dev: uint64(s.Dev), ino: s.Ino})
		if e = directory(f, i == len(parts)-1); e != nil {
			return e
		}
	}
	last := c.chain[len(c.chain)-1]
	if last.dev != c.policy.Store.Device || last.ino != c.policy.Store.Inode {
		return errors.New("store anchor mismatch")
	}
	return c.checkAnchors()
}

func (c *Control) checkAnchors() error {
	if len(c.chain) == 0 {
		return errors.New("closed control")
	}
	for i, a := range c.chain {
		if e := directory(a.file, i == len(c.chain)-1); e != nil {
			return e
		}
		s, e := stat(a.file)
		if e != nil || uint64(s.Dev) != a.dev || s.Ino != a.ino {
			return errors.New("anchor changed")
		}
		if i > 0 {
			f, e := openDirAt(int(c.chain[i-1].file.Fd()), a.name)
			if e != nil {
				return e
			}
			s, e = stat(f)
			ce := f.Close()
			if e != nil || ce != nil || uint64(s.Dev) != a.dev || s.Ino != a.ino {
				return errors.New("path replaced")
			}
		}
	}
	return nil
}

func (c *Control) store() *os.File { return c.chain[len(c.chain)-1].file }

func (c *Control) readOwned(name string, limit int) ([]byte, error) {
	fd, e := syscall.Openat(int(c.store().Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "control-record")
	b, e := readPrivate(f, limit)
	ce := f.Close()
	if e != nil {
		return nil, e
	}
	if ce != nil {
		return nil, ce
	}
	return b, nil
}

func (c *Control) validateCustody() error {
	if e := c.checkAnchors(); e != nil {
		return e
	}
	b, e := c.readOwned("custody.json", maxRecord)
	if e != nil {
		return e
	}
	var v Custody
	if digest(b) != c.policy.CustodySHA256 || canonical(b, &v, maxRecord) != nil {
		return errors.New("custody pin refused")
	}
	p := c.policy
	if v.Schema != "g07-custody/1" || v.State != "ADMITTED_SOURCE_REVIEW_QUALIFICATION_BOUNDARY" || v.Route != "ADMITTED_META_TO_KEEPER_SOURCE_CUSTODY_ATTESTATION" || v.Custodian != p.Custodian || v.Executor != p.Executor || v.Task != p.Task || v.Slot != p.Slot || v.Binding != p.Binding {
		return errors.New("custody disposition refused")
	}
	for _, s := range []string{v.SourceAttestation, v.SourceReview, v.ControlReview, v.ExecutionAcceptance, v.Inspection} {
		if !hex64.MatchString(s) {
			return errors.New("incomplete custody")
		}
	}
	return nil
}

type claim struct {
	Schema           string `json:"schema"`
	Slot             string `json:"slot"`
	Operation        string `json:"operation"`
	EventID          string `json:"event_id"`
	EventSHA         string `json:"event_sha256"`
	RequestSHA       string `json:"request_sha256"`
	CustodySHA       string `json:"custody_sha256"`
	IssuedAt         int64  `json:"issued_at"`
	StartNoLaterThan int64  `json:"start_no_later_than"`
}

func claimFor(a authenticated, p Policy) claim {
	return claim{"g07-claim/1", p.Slot, a.grant.Operation, a.eventID, a.eventSHA, a.requestSHA, p.CustodySHA256, a.grant.IssuedAt, a.grant.StartNoLaterThan}
}
func claimName(slot string) string { return digest([]byte(slot)) + ".claim" }

func (c *Control) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.http != nil {
		c.http.CloseIdleConnections()
	}
	var result error
	for i := len(c.chain) - 1; i >= 0; i-- {
		if e := c.chain[i].file.Close(); e != nil {
			result = e
		}
	}
	c.chain = nil
	return result
}

func (c *Control) lock(ctx context.Context) error {
	for {
		e := syscall.Flock(int(c.store().Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			return nil
		}
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// Consume composes server authentication, pinned prerequisite validation and
// durable one-use consumption. Only NEWLY_CONSUMED may be considered for one
// later inspect-then-invoke action by the actual custodian. It does not execute.
// Any existing claim holds its slot, regardless of validity or delivery status.
func (c *Control) Consume(ctx context.Context, eventID string, tokenFD *os.File) (result Receipt, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var zero Receipt
	if c.validateCustody() != nil {
		return zero, refuse("PREREQUISITE_REFUSED")
	}
	a, e := c.authenticate(ctx, eventID, tokenFD)
	if e != nil {
		return zero, e
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if e = c.lock(ctx); e != nil {
		return zero, refuse("LOCK_REFUSED")
	}
	defer func() {
		if e := syscall.Flock(int(c.store().Fd()), syscall.LOCK_UN); e != nil {
			result = zero
			err = refuse("HELD_UNCERTAIN")
			return
		}
		if result.Outcome == "NEWLY_CONSUMED" {
			if e := c.checkClock(a.grant); e != nil {
				result = zero
				err = e
			}
		}
	}()
	if c.validateCustody() != nil {
		return zero, refuse("PREREQUISITE_REFUSED")
	}
	if e = c.checkClock(a.grant); e != nil {
		return zero, e
	}
	if e = c.checkpoint("before_create"); e != nil {
		return zero, refuse("STORE_REFUSED")
	}
	want := claimFor(a, c.policy)
	b, e := json.Marshal(want)
	if e != nil {
		return zero, refuse("STORE_REFUSED")
	}
	name := claimName(c.policy.Slot)
	fd, e := syscall.Openat(int(c.store().Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e == syscall.EEXIST {
		return c.inspect(name, want)
	}
	if e != nil {
		return zero, refuse("STORE_REFUSED")
	}
	f := os.NewFile(uintptr(fd), "slot-claim")
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()
	// From O_EXCL onward, ANY error leaves the claim in place. No unlink,
	// rename-overwrite, truncate, resend or recovery-execution path exists.
	if e = c.checkpoint("after_create"); e != nil {
		return zero, refuse("HELD_UNCERTAIN")
	}
	if privateFile(f) != nil {
		return zero, refuse("HELD_UNCERTAIN")
	}
	n, e := c.write(f, b)
	if e != nil || n != len(b) {
		return zero, refuse("HELD_UNCERTAIN")
	}
	if e = c.checkpoint("after_write"); e != nil {
		return zero, refuse("HELD_UNCERTAIN")
	}
	if e = c.fileSync(f); e != nil {
		return zero, refuse("HELD_UNCERTAIN")
	}
	if e = c.checkpoint("after_file_sync"); e != nil {
		return zero, refuse("HELD_UNCERTAIN")
	}
	if e = f.Close(); e != nil {
		closed = true
		return zero, refuse("HELD_UNCERTAIN")
	}
	closed = true
	if e = c.dirSync(c.store()); e != nil {
		return zero, refuse("HELD_UNCERTAIN")
	}
	if e = c.checkpoint("after_dir_sync"); e != nil {
		return zero, refuse("HELD_UNCERTAIN")
	}
	if c.validateCustody() != nil {
		return zero, refuse("HELD_UNCERTAIN")
	}
	// Re-read the owned record to refuse replacement/corruption before receipt.
	actual, e := c.readOwned(name, maxRecord)
	if e != nil || string(actual) != string(b) {
		return zero, refuse("HELD_UNCERTAIN")
	}
	if e = c.checkpoint("before_receipt"); e != nil {
		return zero, refuse("HELD_UNCERTAIN")
	}
	if c.checkAnchors() != nil {
		return zero, refuse("HELD_UNCERTAIN")
	}
	if e = c.checkClock(a.grant); e != nil {
		return zero, e
	}
	return receipt("NEWLY_CONSUMED", want, digest(b)), nil
}

func receipt(outcome string, v claim, recordSHA string) Receipt {
	return Receipt{outcome, v.EventID, v.RequestSHA, digest([]byte(v.Slot)), recordSHA, v.Operation, v.IssuedAt, v.StartNoLaterThan}
}

func (c *Control) inspect(name string, want claim) (Receipt, error) {
	var zero Receipt
	b, e := c.readOwned(name, maxRecord)
	if e != nil {
		return zero, refuse("HELD_UNCERTAIN")
	}
	var v claim
	if canonical(b, &v, maxRecord) != nil || v.Schema != "g07-claim/1" || v.Slot != c.policy.Slot || !identifier.MatchString(v.Operation) || !matrixEvent.MatchString(v.EventID) || !hex64.MatchString(v.EventSHA) || !hex64.MatchString(v.RequestSHA) || !hex64.MatchString(v.CustodySHA) {
		return zero, refuse("HELD_UNCERTAIN")
	}
	if v != want {
		return zero, refuse("SLOT_CONFLICT")
	}
	// Presence is observable, but prior interruption may have preceded fsync.
	// Therefore inspection never asserts past durability or executable authority.
	return receipt("INSPECTION_ONLY", v, digest(b)), nil
}
