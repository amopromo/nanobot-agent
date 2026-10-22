package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) (string, []byte) {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	return base64.StdEncoding.EncodeToString(k), k
}

func TestEncryptRoundTrip(t *testing.T) {
	_, key := testKey(t)
	for _, size := range []int{0, 1, cryptChunkSize - 1, cryptChunkSize, cryptChunkSize + 1, 3*cryptChunkSize + 5} {
		plain := make([]byte, size)
		rand.Read(plain)
		var enc, dec bytes.Buffer
		if err := encryptStream(&enc, bytes.NewReader(plain), key); err != nil {
			t.Fatal(err)
		}
		chunks := max(1, (size+cryptChunkSize-1)/cryptChunkSize)
		if size > 0 && size%cryptChunkSize == 0 {
			chunks = size / cryptChunkSize
		}
		if want := cryptHeaderSize + size + chunks*cryptTagSize; enc.Len() != want {
			t.Fatalf("tamanho %d: cifrado %d, esperado %d", size, enc.Len(), want)
		}
		if bytes.Contains(enc.Bytes()[cryptHeaderSize:], plain[:min(size, 64)]) && size >= 64 {
			t.Fatalf("tamanho %d: texto aberto no arquivo", size)
		}
		if err := decryptStream(&dec, bytes.NewReader(enc.Bytes()), [][]byte{key}); err != nil || !bytes.Equal(dec.Bytes(), plain) {
			t.Fatalf("tamanho %d: %v", size, err)
		}
	}
}

func TestEncryptTamper(t *testing.T) {
	_, key := testKey(t)
	_, other := testKey(t)
	plain := bytes.Repeat([]byte("linha de log secreta\n"), cryptChunkSize/10) // ~2 blocos
	var enc bytes.Buffer
	encryptStream(&enc, bytes.NewReader(plain), key)
	raw := enc.Bytes()
	open := func(b []byte, keys ...[]byte) error {
		return decryptStream(&bytes.Buffer{}, bytes.NewReader(b), keys)
	}
	flipped := bytes.Clone(raw)
	flipped[len(flipped)/2] ^= 1
	if open(flipped, key) == nil {
		t.Fatal("arquivo alterado abriu")
	}
	// Cortado exatamente no fim do primeiro bloco: sem a marca de último bloco, não abre
	if open(raw[:cryptHeaderSize+cryptChunkSize+cryptTagSize], key) == nil {
		t.Fatal("arquivo cortado abriu")
	}
	if open(raw[:len(raw)-1], key) == nil {
		t.Fatal("arquivo sem o último byte abriu")
	}
	header := bytes.Clone(raw)
	header[25] = 1 // byte reservado do cabeçalho (vai na AAD)
	if open(header, key) == nil {
		t.Fatal("cabeçalho alterado abriu")
	}
	if err := open(raw, other); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("chave errada: %v", err)
	}
	if err := open(raw, other, key); err != nil {
		t.Fatalf("chave antiga na lista: %v", err)
	}
	if open([]byte("PAR1 qualquer coisa"), key) == nil {
		t.Fatal("arquivo sem criptografia abriu como criptografado")
	}
}

func TestCryptBlob(t *testing.T) {
	dir := t.TempDir()
	keyB64, _ := testKey(t)
	oldB64, _ := testKey(t)
	inner := localBlob{root: dir + "/bucket"}
	b, err := newCryptBlob(inner, &Credentials{EncryptionKey: keyB64, PreviousEncryptionKeys: []string{oldB64}}, dir+"/tmp")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	src := dir + "/a.parquet"
	os.WriteFile(src, []byte("PAR1 dados secretos PAR1"), 0o600)
	if err := b.Put(ctx, "c/logs/dt=2026-10-22/hh=10/1.parquet", src); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(dir + "/bucket/c/logs/dt=2026-10-22/hh=10/1.parquet")
	if !bytes.HasPrefix(raw, []byte(cryptMagic)) || bytes.Contains(raw, []byte("secretos")) {
		t.Fatalf("arquivo no bucket não está criptografado: %q", raw[:8])
	}
	if err := b.Get(ctx, "c/logs/dt=2026-10-22/hh=10/1.parquet", dir+"/back.parquet"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dir + "/back.parquet"); string(got) != "PAR1 dados secretos PAR1" {
		t.Fatalf("leitura: %q", got)
	}
	// Parquet antigo (antes da chave): lido como está; JSON sem criptografia: recusado
	os.MkdirAll(dir+"/bucket/c/old", 0o755)
	os.WriteFile(dir+"/bucket/c/old/1.parquet", []byte("PAR1 antigo"), 0o644)
	os.WriteFile(dir+"/bucket/c/_config/security.json", nil, 0o644)
	os.MkdirAll(dir+"/bucket/c/_config", 0o755)
	os.WriteFile(dir+"/bucket/c/_config/security.json", []byte(`{"enabled":true}`), 0o644)
	if err := b.Get(ctx, "c/old/1.parquet", dir+"/old.parquet"); err != nil {
		t.Fatalf("parquet antigo: %v", err)
	}
	if err := b.Get(ctx, "c/_config/security.json", dir+"/cfg.json"); !errors.Is(err, errNotEncrypted) {
		t.Fatalf("JSON sem criptografia: %v", err)
	}
	if _, err := newCryptBlob(inner, &Credentials{EncryptionKey: "curta"}, dir+"/tmp"); err == nil {
		t.Fatal("chave inválida aceita")
	}
	if entries, _ := os.ReadDir(dir + "/tmp"); len(entries) != 0 {
		t.Fatalf("arquivos temporários ficaram: %d", len(entries))
	}
}

// Spool, upload, compactação e leitura com a criptografia ligada: nada aberto no bucket.
func TestEncryptedStore(t *testing.T) {
	cfg, creds := testConfig(t)
	if creds != nil {
		t.Skip("só no diretório local")
	}
	keyB64, _ := testKey(t)
	blob, _ := NewBlob(cfg, nil)
	cb, err := newCryptBlob(blob, &Credentials{EncryptionKey: keyB64}, filepath.Join(cfg.BufferDir, "crypt"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(cfg, cb)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	base := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	for i := range 3 {
		s.T.Logs.Append(logRow(base.Add(time.Duration(i)*time.Minute), "mensagem secreta"))
		if err := s.Flush(ctx); err != nil {
			t.Fatal(err)
		}
	}
	now := base.Add(3 * time.Hour)
	s.now = func() time.Time { return now }
	if err := s.Maintain(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _ := readTable[LogRow](t, s, "logs")
	if len(rows) != 3 {
		t.Fatalf("linhas: %d", len(rows))
	}
	filepath.WalkDir(cfg.StoragePath, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			raw, _ := os.ReadFile(p)
			if !bytes.HasPrefix(raw, []byte(cryptMagic)) || bytes.Contains(raw, []byte("secreta")) {
				t.Errorf("%s sem criptografia", p)
			}
		}
		return nil
	})
}
