package bridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type CredentialRecord struct {
	CredID          string `json:"cred_id"`
	KeyHandle       string `json:"key_handle"`
	RPID            string `json:"rp_id"`
	RPIDHash        string `json:"rp_id_hash"`
	UserID          string `json:"user_id"`
	UserName        string `json:"user_name"`
	UserDisplayName string `json:"user_display_name"`
	PubKeyX         string `json:"pubkey_x"`
	PubKeyY         string `json:"pubkey_y"`
	RKSlot          int    `json:"rk_slot"`
	CreatedAt       int64  `json:"created_at"`
}

type CredentialStore struct {
	path string
	mu   sync.Mutex
}

func DefaultConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "yubiesp")
}

func NewCredentialStore(path string) (*CredentialStore, error) {
	if path == "" {
		path = filepath.Join(DefaultConfigDir(), "credentials.json")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	s := &CredentialStore{path: path}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		_ = s.write([]CredentialRecord{})
	}
	return s, nil
}

func (s *CredentialStore) read() []CredentialRecord {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return []CredentialRecord{}
	}
	var items []CredentialRecord
	if err := json.Unmarshal(data, &items); err != nil {
		return []CredentialRecord{}
	}
	if items == nil {
		return []CredentialRecord{}
	}
	return items
}

func (s *CredentialStore) write(items []CredentialRecord) error {
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *CredentialStore) ListAll() []CredentialRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read()
}

func (s *CredentialStore) FindByRP(rpID string) []CredentialRecord {
	sum := sha256.Sum256([]byte(rpID))
	rpHash := hex.EncodeToString(sum[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []CredentialRecord
	for _, c := range s.read() {
		if c.RPID == rpID || c.RPIDHash == rpHash {
			out = append(out, c)
		}
	}
	return out
}

func (s *CredentialStore) FindByCredID(credID string) *CredentialRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.read() {
		if c.CredID == credID {
			rec := c
			return &rec
		}
	}
	return nil
}

func (s *CredentialStore) Upsert(rec CredentialRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := s.read()
	filtered := make([]CredentialRecord, 0, len(items)+1)
	filtered = append(filtered, rec)
	for _, c := range items {
		if c.CredID != rec.CredID {
			filtered = append(filtered, c)
		}
	}
	_ = s.write(filtered)
}

func (s *CredentialStore) Delete(credID string) *CredentialRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := s.read()
	kept := make([]CredentialRecord, 0, len(items))
	var removed *CredentialRecord
	for _, c := range items {
		if c.CredID == credID {
			cp := c
			removed = &cp
		} else {
			kept = append(kept, c)
		}
	}
	_ = s.write(kept)
	return removed
}
