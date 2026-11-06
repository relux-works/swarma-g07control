// Package g07control prepares keeper control admission. It neither starts Host
// nor writes runtime artifacts. Open's policy descriptor is a trusted input
// supplied by the actual custodian, never authority supplied by a grant caller.
package g07control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"regexp"
)

const (
	maxPolicy = 16384
	maxEvent  = 32768
	maxGrant  = 8192
	maxRecord = 8192
)

// Binding contains digests, never private execution locators. The custodian
// pins every field before issuance; none is selected by a Consume caller.
type Binding struct {
	Revision         string `json:"revision_sha256"`
	Source           string `json:"source_sha256"`
	ControlSource    string `json:"control_source_sha256"`
	Qualification    string `json:"qualification_sha256"`
	Compiler         string `json:"compiler_sha256"`
	BuildArgv        string `json:"build_argv_sha256"`
	BuildEnvironment string `json:"build_environment_sha256"`
	Artifact         string `json:"artifact_sha256"`
	ArtifactLocator  string `json:"artifact_locator_sha256"`
	EntryArgv        string `json:"entry_argv_sha256"`
	EntryEnvironment string `json:"entry_environment_sha256"`
	EntryCommand     string `json:"entry_command_sha256"`
	OwnedRoot        string `json:"owned_root_sha256"`
	Export           string `json:"export_sha256"`
	KeeperSibling    string `json:"keeper_sibling_sha256"`
	Ledger           string `json:"ledger_sha256"`
	Operations       string `json:"operation_bindings_sha256"`
	Boundary         string `json:"boundary_sha256"`
	SourceAgreement  string `json:"source_agreement_sha256"`
	ImmutableInputs  string `json:"immutable_inputs_sha256"`
}

type StoreAnchor struct {
	Path   string `json:"path"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

// Policy must be provisioned and pinned by the custodian through the later
// admitted installation route. A caller-created policy proves no prerequisite.
// RuntimeRoots are R/E/K, used only for lexical separation, never opened.
type Policy struct {
	Schema          string      `json:"schema"`
	Origin          string      `json:"origin"`
	TLSRootsPEM     string      `json:"tls_roots_pem"`
	Room            string      `json:"room"`
	Issuer          string      `json:"issuer"`
	Custodian       string      `json:"custodian"`
	Executor        string      `json:"executor"`
	Task            string      `json:"task"`
	Slot            string      `json:"slot"`
	Binding         Binding     `json:"binding"`
	Store           StoreAnchor `json:"store"`
	RuntimeRoots    [3]string   `json:"runtime_roots"`
	CustodySHA256   string      `json:"custody_sha256"`
	SpentOperations []string    `json:"spent_operations"`
}

// Custody is a record of separately admitted prerequisites, not an assertion
// inferred from the Matrix event. Its complete bytes must match Policy's pin.
// The named evidence digests require external custodian verification/admission.
type Custody struct {
	Schema              string  `json:"schema"`
	State               string  `json:"state"`
	Route               string  `json:"route"`
	Custodian           string  `json:"custodian"`
	Executor            string  `json:"executor"`
	Task                string  `json:"task"`
	Slot                string  `json:"slot"`
	Binding             Binding `json:"binding"`
	SourceAttestation   string  `json:"source_attestation_sha256"`
	SourceReview        string  `json:"source_review_sha256"`
	ControlReview       string  `json:"control_review_sha256"`
	ExecutionAcceptance string  `json:"execution_acceptance_sha256"`
	Inspection          string  `json:"inspection_sha256"`
}

// Grant is encoded exactly as json.Marshal(Grant), with no whitespace, omitted
// fields, duplicate fields, alternate ordering or unknown fields. Times are
// integral Unix seconds. The selected server authenticates the outer event.
type Grant struct {
	Schema            string  `json:"schema"`
	Operation         string  `json:"operation"`
	Issuer            string  `json:"issuer"`
	Custodian         string  `json:"custodian"`
	Executor          string  `json:"executor"`
	Recipient         string  `json:"recipient"`
	Task              string  `json:"task"`
	Slot              string  `json:"slot"`
	EntryCount        int     `json:"entry_count"`
	InspectThenInvoke bool    `json:"inspect_then_invoke"`
	Binding           Binding `json:"binding"`
	IssuedAt          int64   `json:"issued_at"`
	StartNoLaterThan  int64   `json:"start_no_later_than"`
	OuterSeconds      int     `json:"outer_seconds"`
}

type Receipt struct {
	Outcome          string `json:"outcome"`
	EventID          string `json:"event_id"`
	RequestSHA256    string `json:"request_sha256"`
	SlotSHA256       string `json:"slot_sha256"`
	RecordSHA256     string `json:"record_sha256"`
	Operation        string `json:"operation"`
	IssuedAt         int64  `json:"issued_at"`
	StartNoLaterThan int64  `json:"start_no_later_than"`
}

// Refusal exposes a bounded classification only. Underlying HTTP errors may
// contain URLs, headers or tokens and are deliberately not propagated.
type Refusal struct{ Code string }

func (r *Refusal) Error() string { return r.Code }
func refuse(code string) error   { return &Refusal{Code: code} }

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var matrixUser = regexp.MustCompile(`^@[a-z0-9._=-]{1,128}:[a-z0-9.-]{1,190}$`)
var matrixRoom = regexp.MustCompile(`^![A-Za-z0-9_.:-]{1,250}$`)
var matrixEvent = regexp.MustCompile(`^\$[A-Za-z0-9_.:-]{1,250}$`)

func validBinding(b Binding) bool {
	v := reflect.ValueOf(b)
	for i := 0; i < v.NumField(); i++ {
		if !hex64.MatchString(v.Field(i).String()) {
			return false
		}
	}
	return true
}

// canonical also rejects duplicates, case aliases, unknown/missing fields and
// numeric aliases: decoding must round-trip to the exact closed wire encoding.
func canonical(b []byte, target any, limit int) error {
	if len(b) == 0 || len(b) > limit {
		return errors.New("bounded encoding")
	}
	if err := json.Unmarshal(b, target); err != nil {
		return errors.New("invalid encoding")
	}
	out, err := json.Marshal(target)
	if err != nil || string(out) != string(b) {
		return errors.New("noncanonical encoding")
	}
	return nil
}

// object permits server JSON whitespace/key ordering while recursively rejecting
// duplicate keys. Exact member names and closed shapes are checked separately.
func object(b []byte, required, optional []string) (map[string]json.RawMessage, error) {
	if len(b) == 0 || len(b) > maxEvent {
		return nil, errors.New("bounded object")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if err := uniqueJSON(d, 0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		return nil, errors.New("expected object")
	}
	allowed := map[string]bool{}
	for _, k := range required {
		allowed[k] = true
		if _, ok := m[k]; !ok {
			return nil, errors.New("missing member")
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return nil, errors.New("unknown member")
		}
	}
	return m, nil
}

func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 12 {
		return errors.New("JSON depth")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return e
				}
				k, ok := key.(string)
				if !ok || seen[k] {
					return errors.New("duplicate member")
				}
				seen[k] = true
				if e = uniqueJSON(d, depth+1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := uniqueJSON(d, depth+1); e != nil {
					return e
				}
			}
		default:
			return errors.New("unexpected delimiter")
		}
		_, err = d.Token()
	}
	return err
}

func readBounded(r io.Reader, limit int) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, int64(limit+1)))
	if e != nil || len(b) > limit {
		return nil, errors.New("bounded read refused")
	}
	return b, nil
}

func readPrivate(f *os.File, limit int) ([]byte, error) {
	if f == nil {
		return nil, errors.New("descriptor required")
	}
	if err := privateFile(f); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return readBounded(f, limit)
}
