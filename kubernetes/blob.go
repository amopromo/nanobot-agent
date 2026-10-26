package main

// Acesso ao storage: bucket S3 compatível (AWS ou qualquer S3 genérico: MinIO, Ceph...), GCS pela interoperabilidade S3 (chave HMAC),
// Cloudflare R2 ou um diretório local (desenvolvimento e testes). Só o necessário: subir, baixar, listar e apagar.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type Blob interface {
	Put(ctx context.Context, key, file string) error
	Get(ctx context.Context, key, file string) error
	List(ctx context.Context, prefix string) ([]string, error) // chaves completas, recursivo
	Delete(ctx context.Context, key string) error
}

func NewBlob(cfg *Config, creds *Credentials) (Blob, error) {
	if !cfg.Remote() {
		return localBlob{root: cfg.StoragePath}, nil
	}
	scheme, rest, _ := strings.Cut(cfg.StoragePath, "://")
	bucket, _, _ := strings.Cut(rest, "/")
	if creds == nil {
		return nil, fmt.Errorf("storage %s sem credenciais", scheme)
	}
	endpoint := strings.TrimRight(creds.Endpoint, "/")
	secure := creds.UseSSL == nil || *creds.UseSSL
	if after, ok := strings.CutPrefix(endpoint, "http://"); ok {
		endpoint, secure = after, false
	} else {
		endpoint = strings.TrimPrefix(endpoint, "https://")
	}
	region := creds.Region
	if endpoint == "" {
		switch creds.Type {
		case "gcs":
			endpoint = "storage.googleapis.com"
		case "r2":
			if creds.AccountID == "" {
				return nil, fmt.Errorf("r2 sem account_id")
			}
			endpoint = creds.AccountID + ".r2.cloudflarestorage.com"
		default:
			endpoint = "s3.amazonaws.com"
		}
	}
	if creds.Type == "r2" && region == "" {
		region = "auto"
	}
	lookup := minio.BucketLookupAuto
	switch creds.URLStyle {
	case "path":
		lookup = minio.BucketLookupPath
	case "vhost":
		lookup = minio.BucketLookupDNS
	}
	c, err := minio.New(endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(creds.KeyID, creds.Secret, creds.SessionToken),
		Secure:       secure,
		Region:       region,
		BucketLookup: lookup,
	})
	if err != nil {
		return nil, err
	}
	return &s3Blob{c: c, bucket: bucket}, nil
}

type s3Blob struct {
	c      *minio.Client
	bucket string
}

func (b *s3Blob) Put(ctx context.Context, key, file string) error {
	// Uma parte por vez: o multipart padrão do minio-go guarda várias partes de 16 MiB em memória
	_, err := b.c.FPutObject(ctx, b.bucket, key, file, minio.PutObjectOptions{
		ContentType: "application/vnd.apache.parquet", NumThreads: 1, PartSize: 16 << 20,
	})
	return err
}

func (b *s3Blob) Get(ctx context.Context, key, file string) error {
	return b.c.FGetObject(ctx, b.bucket, key, file, minio.GetObjectOptions{})
}

func (b *s3Blob) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	for o := range b.c.ListObjects(ctx, b.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if o.Err != nil {
			return nil, o.Err
		}
		keys = append(keys, o.Key)
	}
	return keys, nil
}

// Delete apaga um objeto por vez: o GCS não aceita o DeleteObjects (vários de uma vez) da API S3.
func (b *s3Blob) Delete(ctx context.Context, key string) error {
	return b.c.RemoveObject(ctx, b.bucket, key, minio.RemoveObjectOptions{})
}

// localBlob grava num diretório: STORAGE_PATH sem esquema (desenvolvimento e testes).
type localBlob struct{ root string }

func (b localBlob) path(key string) string { return filepath.Join(b.root, filepath.FromSlash(key)) }

func (b localBlob) Put(_ context.Context, key, file string) error {
	dst := b.path(key)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return copyFile(file, dst)
}

func (b localBlob) Get(_ context.Context, key, file string) error { return copyFile(b.path(key), file) }

func (b localBlob) List(_ context.Context, prefix string) ([]string, error) {
	var keys []string
	err := filepath.WalkDir(b.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || strings.HasSuffix(p, ".tmp") {
			return nil
		}
		rel, err := filepath.Rel(b.root, p)
		if err != nil {
			return err
		}
		if key := filepath.ToSlash(rel); strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
		return nil
	})
	sort.Strings(keys)
	return keys, err
}

func (b localBlob) Delete(_ context.Context, key string) error {
	err := os.Remove(b.path(key))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	// Remove as pastas que ficaram vazias (o S3 não tem pastas)
	for dir := filepath.Dir(b.path(key)); dir != b.root && strings.HasPrefix(dir, b.root); dir = filepath.Dir(dir) {
		if os.Remove(dir) != nil {
			break
		}
	}
	return err
}

// copyFile copia via arquivo temporário + rename: quem lista nunca vê um arquivo pela metade.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
