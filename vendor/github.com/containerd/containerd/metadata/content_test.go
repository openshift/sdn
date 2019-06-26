package metadata

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/boltdb/bolt"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/content/local"
	"github.com/containerd/containerd/content/testsuite"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/leases"
	"github.com/containerd/containerd/namespaces"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
)

func createContentStore(ctx context.Context, root string) (context.Context, content.Store, func() error, error) {
	// TODO: Use mocked or in-memory store
	cs, err := local.NewStore(root)
	if err != nil {
		return nil, nil, nil, err
	}

	db, err := bolt.Open(filepath.Join(root, "metadata.db"), 0660, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	return ctx, NewDB(db, cs, nil).ContentStore(), func() error {
		return db.Close()
	}, nil
}

func TestContent(t *testing.T) {
	testsuite.ContentSuite(t, "metadata", createContentStore)
}

func TestContentLeased(t *testing.T) {
	ctx, db, cancel := testDB(t)
	defer cancel()

	cs := db.ContentStore()

	blob := []byte("any content")
	expected := digest.FromBytes(blob)

	lctx, _, err := createLease(ctx, db, "lease-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := content.WriteBlob(lctx, cs, "test-1", bytes.NewReader(blob), int64(len(blob)), expected); err != nil {
		t.Fatal(err)
	}
	if err := checkContentLeased(lctx, db, expected); err != nil {
		t.Fatal("lease checked failed:", err)
	}

	lctx, _, err = createLease(ctx, db, "lease-2")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := cs.Writer(lctx, "test-2", int64(len(blob)), expected); err == nil {
		t.Fatal("expected already exist error")
	} else if !errdefs.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	if err := checkContentLeased(lctx, db, expected); err != nil {
		t.Fatal("lease checked failed:", err)
	}
}

func createLease(ctx context.Context, db *DB, name string) (context.Context, func() error, error) {
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := NewLeaseManager(tx).Create(ctx, name, nil)
		return err
	}); err != nil {
		return nil, nil, err
	}
	return leases.WithLease(ctx, name), func() error {
		return db.Update(func(tx *bolt.Tx) error {
			return NewLeaseManager(tx).Delete(ctx, name)
		})
	}, nil
}

func checkContentLeased(ctx context.Context, db *DB, dgst digest.Digest) error {
	ns, ok := namespaces.Namespace(ctx)
	if !ok {
		return errors.New("no namespace in context")
	}
	lease, ok := leases.Lease(ctx)
	if !ok {
		return errors.New("no lease in context")
	}

	return db.View(func(tx *bolt.Tx) error {
		bkt := getBucket(tx, bucketKeyVersion, []byte(ns), bucketKeyObjectLeases, []byte(lease), bucketKeyObjectContent)
		if bkt == nil {
			return errors.Wrapf(errdefs.ErrNotFound, "bucket not found", lease)
		}
		v := bkt.Get([]byte(dgst.String()))
		if v == nil {
			return errors.Wrap(errdefs.ErrNotFound, "object not leased")
		}

		return nil
	})
}
