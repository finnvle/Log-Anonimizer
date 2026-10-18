package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

const (
	fileFormat  = "log_anonimizer-map"
	fileVersion = 1
)

// Argon2id parameters (RFC 9106, second recommended option). Variables so
// tests can lower the cost.
var (
	KDFTime    uint32 = 3
	KDFMemory  uint32 = 64 * 1024 // KiB
	KDFThreads uint8  = 4
)

// ErrWrongPassphrase is returned when the map cannot be decrypted.
var ErrWrongPassphrase = errors.New("wrong passphrase or corrupted map file")

// ErrNeedPassphrase is returned by a PassphraseFunc that has no passphrase.
var ErrNeedPassphrase = errors.New("map is encrypted: passphrase required")

type kdfParams struct {
	Name    string `json:"name"`
	Salt    []byte `json:"salt"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
}

type envelope struct {
	Format     string     `json:"format"`
	Version    int        `json:"version"`
	Encrypted  bool       `json:"encrypted"`
	KDF        *kdfParams `json:"kdf,omitempty"`
	Nonce      []byte     `json:"nonce,omitempty"`
	Ciphertext []byte     `json:"ciphertext,omitempty"`
	Vault      *Vault     `json:"vault,omitempty"`
}

func aad() []byte { return []byte(fmt.Sprintf("%s/%d", fileFormat, fileVersion)) }

func deriveKey(pass []byte, k *kdfParams) []byte {
	return argon2.IDKey(pass, k.Salt, k.Time, k.Memory, k.Threads, 32)
}

// Save writes the vault to path. With a non-empty passphrase the content is
// encrypted with AES-256-GCM using an Argon2id-derived key; with an empty
// passphrase it is written as plain JSON. The file is written atomically with
// 0600 permissions.
func Save(path string, v *Vault, passphrase []byte) error {
	plain, err := json.Marshal(v)
	if err != nil {
		return err
	}
	env := envelope{Format: fileFormat, Version: fileVersion}
	if len(passphrase) == 0 {
		env.Vault = v
	} else {
		k := &kdfParams{Name: "argon2id", Salt: make([]byte, 16), Time: KDFTime, Memory: KDFMemory, Threads: KDFThreads}
		if _, err := rand.Read(k.Salt); err != nil {
			return err
		}
		block, err := aes.NewCipher(deriveKey(passphrase, k))
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		env.Encrypted = true
		env.KDF = k
		env.Nonce = nonce
		env.Ciphertext = gcm.Seal(nil, nonce, plain, aad())
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".anonmap-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// PassphraseFunc supplies the passphrase when a map turns out to be encrypted.
type PassphraseFunc func() ([]byte, error)

// Info describes a map file without its content.
type Info struct {
	Encrypted bool
}

// Stat reads only the envelope header.
func Stat(path string) (Info, error) {
	env, err := readEnvelope(path)
	if err != nil {
		return Info{}, err
	}
	return Info{Encrypted: env.Encrypted}, nil
}

func readEnvelope(path string) (*envelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("%s is not a log_anonimizer map: %w", path, err)
	}
	if env.Format != fileFormat {
		return nil, fmt.Errorf("%s is not a log_anonimizer map", path)
	}
	if env.Version != fileVersion {
		return nil, fmt.Errorf("%s: unsupported map version %d", path, env.Version)
	}
	return &env, nil
}

// Load reads a map. pass is called only if the file is encrypted. The
// passphrase that was used is returned so the caller can re-save with it.
func Load(path string, pass PassphraseFunc) (*Vault, []byte, error) {
	env, err := readEnvelope(path)
	if err != nil {
		return nil, nil, err
	}
	if !env.Encrypted {
		if env.Vault == nil {
			return nil, nil, fmt.Errorf("%s: empty map", path)
		}
		env.Vault.reindex()
		return env.Vault, nil, nil
	}
	if env.KDF == nil || env.KDF.Name != "argon2id" {
		return nil, nil, fmt.Errorf("%s: unsupported key derivation", path)
	}
	p, err := pass()
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(deriveKey(p, env.KDF))
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	plain, err := gcm.Open(nil, env.Nonce, env.Ciphertext, aad())
	if err != nil {
		return nil, nil, ErrWrongPassphrase
	}
	v := &Vault{}
	if err := json.Unmarshal(plain, v); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	v.reindex()
	return v, p, nil
}
