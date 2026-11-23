package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type FileEntry struct {
	Path string `json:"path"`
	Hash string `json:"hash"` // hex SHA-256
	Size int64  `json:"size"`
}

type SealPack struct {
	Version   string      `json:"version"`
	Domain    string      `json:"domain"`
	CreatedAt string      `json:"created_at"` // ISO8601, for human only; not in hash
	Files     []FileEntry `json:"files"`
	Root      string      `json:"root"` // Merkle root hex
	ProofNote string      `json:"proof_note"`
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func merkleRoot(hashes []string) string {
	if len(hashes) == 0 {
		return ""
	}
	// Sort for determinism
	sort.Strings(hashes)
	for len(hashes) > 1 {
		var next []string
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := hashes[i] + hashes[i+1]
				h := sha256.Sum256([]byte(combined))
				next = append(next, hex.EncodeToString(h[:]))
			} else {
				// promote unpaired
				next = append(next, hashes[i])
			}
		}
		hashes = next
	}
	return hashes[0]
}

func seal(dir string) (*SealPack, error) {
	var entries []FileEntry
	var hashes []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		hash, size, err := hashFile(path)
		if err != nil {
			return err
		}
		entries = append(entries, FileEntry{Path: rel, Hash: hash, Size: size})
		hashes = append(hashes, hash)
		return nil
	})
	if err != nil {
		return nil, err
	}
	root := merkleRoot(hashes)
	pack := &SealPack{
		Version:   "1.0",
		Domain:    "op-seal/v1",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Files:     entries,
		Root:      root,
		ProofNote: "PROOF NOT PROMISE. Offline deterministic seal. Verify with op-seal verify.",
	}
	return pack, nil
}

func verify(packPath string, dir string) error {
	data, err := os.ReadFile(packPath)
	if err != nil {
		return err
	}
	var pack SealPack
	if err := json.Unmarshal(data, &pack); err != nil {
		return err
	}
	// Recompute
	var hashes []string
	for _, e := range pack.Files {
		full := filepath.Join(dir, e.Path)
		hash, size, err := hashFile(full)
		if err != nil || hash != e.Hash || size != e.Size {
			return fmt.Errorf("FAIL: mismatch on %s", e.Path)
		}
		hashes = append(hashes, hash)
	}
	root := merkleRoot(hashes)
	if root != pack.Root {
		return fmt.Errorf("FAIL: root mismatch expected %s got %s", pack.Root, root)
	}
	fmt.Println("PASS")
	return nil
}

func main() {
	sealCmd := flag.NewFlagSet("seal", flag.ExitOnError)
	dir := sealCmd.String("dir", ".", "directory to seal")
	out := sealCmd.String("out", "sealpack.json", "output pack path")

	verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
	pack := verifyCmd.String("pack", "sealpack.json", "pack to verify")
	vdir := verifyCmd.String("dir", ".", "directory to check against")

	if len(os.Args) < 2 {
		fmt.Println("Usage: op-seal seal|verify")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "seal":
		sealCmd.Parse(os.Args[2:])
		p, err := seal(*dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(p, "", "  ")
		os.WriteFile(*out, b, 0644)
		fmt.Printf("Sealed. Root: %s\nWrote %s\n", p.Root, *out)
	case "verify":
		verifyCmd.Parse(os.Args[2:])
		if err := verify(*pack, *vdir); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		fmt.Println("Unknown command")
		os.Exit(1)
	}
}
