package main

// Criptografia dos arquivos no storage (AES-256-GCM), ligada pelo encryption_key das credenciais. O arquivo inteiro é
// criptografado antes de subir e descriptografado ao baixar: quem tem acesso ao bucket sem a chave não lê nada (logs,
// uso, vulnerabilidades) e não consegue forjar a configuração gravada pelo Nanobot (o GCM autentica cada bloco).
//
// A criptografia própria do Parquet não serve: a do parquet-go e a do DuckDB (Nanobot) não leem os arquivos uma da
// outra. O Nanobot usa este mesmo formato:
//
//	cabeçalho (32 bytes): "NBE1" | key id (8) | nonce prefix (8, aleatório) | tamanho do bloco (4, big endian) | zeros (8)
//	blocos: AES-256-GCM(bloco de até chunkSize bytes), nonce = nonce prefix | contador (4, big endian),
//	        AAD = cabeçalho | 1 no último bloco, 0 nos outros (um arquivo cortado ou com blocos trocados não abre)
//
// O key id (8 primeiros bytes do SHA-256 de "nanobot-k8s-key-id" + chave) escolhe a chave na leitura: as chaves antigas
// (previous_encryption_keys) continuam lendo os arquivos já gravados depois de uma troca de chave.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	cryptMagic      = "NBE1"
	cryptHeaderSize = 32
	cryptChunkSize  = 1 << 20
	cryptTagSize    = 16
)

var errNotEncrypted = errors.New("file in the storage is not encrypted (refused: the cluster has an encryption key)")

// parseKey: a chave vem em base64 (32 bytes).
func parseEncryptionKey(v string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil || len(k) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes in base64 (openssl rand -base64 32)")
	}
	return k, nil
}

func keyID(key []byte) []byte {
	h := sha256.Sum256(append([]byte("nanobot-k8s-key-id"), key...))
	return h[:8]
}

func chunkNonce(prefix []byte, n uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[8:], n)
	return nonce
}

func chunkAAD(header []byte, final bool) []byte {
	aad := make([]byte, len(header)+1)
	copy(aad, header)
	if final {
		aad[len(header)] = 1
	}
	return aad
}

// encryptStream criptografa r inteiro em w.
func encryptStream(w io.Writer, r io.Reader, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	header := make([]byte, cryptHeaderSize)
	copy(header, cryptMagic)
	copy(header[4:12], keyID(key))
	if _, err := rand.Read(header[12:20]); err != nil {
		return err
	}
	binary.BigEndian.PutUint32(header[20:24], cryptChunkSize)
	if _, err := w.Write(header); err != nil {
		return err
	}
	br := bufio.NewReaderSize(r, cryptChunkSize)
	buf := make([]byte, cryptChunkSize)
	out := make([]byte, 0, cryptChunkSize+cryptTagSize)
	for n := uint32(0); ; n++ {
		read, err := io.ReadFull(br, buf)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return err
		}
		// Último bloco: o que sobrou não encheu o buffer ou não há mais nada depois dele
		final := read < cryptChunkSize
		if !final {
			if _, perr := br.Peek(1); errors.Is(perr, io.EOF) {
				final = true
			}
		}
		out = gcm.Seal(out[:0], chunkNonce(header[12:20], n), buf[:read], chunkAAD(header, final))
		if _, err := w.Write(out); err != nil {
			return err
		}
		if final {
			return nil
		}
		if n == ^uint32(0) {
			return errors.New("file too large to encrypt")
		}
	}
}

// decryptStream descriptografa r em w com a chave do key id do cabeçalho (entre keys).
func decryptStream(w io.Writer, r io.Reader, keys [][]byte) error {
	header := make([]byte, cryptHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil || string(header[:4]) != cryptMagic {
		return errors.New("not an encrypted file")
	}
	var key []byte
	for _, k := range keys {
		if bytes.Equal(keyID(k), header[4:12]) {
			key = k
			break
		}
	}
	if key == nil {
		return errors.New("file encrypted with an unknown key (add the old key to previous_encryption_keys)")
	}
	size := binary.BigEndian.Uint32(header[20:24])
	if size == 0 || size > 64<<20 {
		return errors.New("invalid encrypted file header")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	br := bufio.NewReaderSize(r, int(size)+cryptTagSize)
	buf := make([]byte, int(size)+cryptTagSize)
	out := make([]byte, 0, size)
	for n := uint32(0); ; n++ {
		read, err := io.ReadFull(br, buf)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return err
		}
		if read < cryptTagSize {
			return errors.New("encrypted file truncated")
		}
		final := read < len(buf)
		if !final {
			if _, perr := br.Peek(1); errors.Is(perr, io.EOF) {
				final = true
			}
		}
		out, err = gcm.Open(out[:0], chunkNonce(header[12:20], n), buf[:read], chunkAAD(header, final))
		if err != nil {
			return errors.New("encrypted file is corrupted, truncated or was changed")
		}
		if _, err := w.Write(out); err != nil {
			return err
		}
		if final {
			return nil
		}
	}
}

func isEncryptedFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	magic := make([]byte, 4)
	_, err = io.ReadFull(f, magic)
	return err == nil && string(magic) == cryptMagic
}

// cryptBlob criptografa no Put e descriptografa no Get; List e Delete passam direto. Arquivos Parquet antigos, gravados
// antes da chave, ainda são lidos (a compactação e o Nanobot os aceitam); os JSON (configuração da varredura) não.
type cryptBlob struct {
	inner  Blob
	key    []byte
	keys   [][]byte // a atual e as antigas (só leitura)
	tmpDir string
}

func newCryptBlob(inner Blob, creds *Credentials, tmpDir string) (*cryptBlob, error) {
	key, err := parseEncryptionKey(creds.EncryptionKey)
	if err != nil {
		return nil, err
	}
	os.RemoveAll(tmpDir) // restos de um restart no meio de uma gravação
	b := &cryptBlob{inner: inner, key: key, keys: [][]byte{key}, tmpDir: tmpDir}
	for _, old := range creds.PreviousEncryptionKeys {
		k, err := parseEncryptionKey(old)
		if err != nil {
			return nil, fmt.Errorf("previous_encryption_keys: %w", err)
		}
		b.keys = append(b.keys, k)
	}
	return b, nil
}

func (b *cryptBlob) temp() (string, error) {
	if err := os.MkdirAll(b.tmpDir, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(b.tmpDir, "crypt-*")
	if err != nil {
		return "", err
	}
	f.Close()
	return f.Name(), nil
}

func (b *cryptBlob) Put(ctx context.Context, key, file string) error {
	tmp, err := b.temp()
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	in, err := os.Open(file)
	if err != nil {
		return err
	}
	err = writeAtomicFile(tmp, func(w io.Writer) error { return encryptStream(w, in, b.key) })
	in.Close()
	if err != nil {
		return err
	}
	return b.inner.Put(ctx, key, tmp)
}

func (b *cryptBlob) Get(ctx context.Context, key, file string) error {
	tmp, err := b.temp()
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := b.inner.Get(ctx, key, tmp); err != nil {
		return err
	}
	if !isEncryptedFile(tmp) {
		if !strings.HasSuffix(key, ".parquet") {
			return fmt.Errorf("%s: %w", key, errNotEncrypted)
		}
		return copyFile(tmp, file)
	}
	in, err := os.Open(tmp)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := writeAtomicFile(file, func(w io.Writer) error { return decryptStream(w, in, b.keys) }); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	return nil
}

func (b *cryptBlob) List(ctx context.Context, prefix string) ([]string, error) {
	return b.inner.List(ctx, prefix)
}
func (b *cryptBlob) Delete(ctx context.Context, key string) error { return b.inner.Delete(ctx, key) }

// writeAtomicFile grava em <path>.tmp e renomeia (o destino nunca fica pela metade).
func writeAtomicFile(path string, fn func(io.Writer) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeAtomic(path, fn)
}
