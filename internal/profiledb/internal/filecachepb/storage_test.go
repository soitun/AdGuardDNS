package filecachepb_test

import (
	"cmp"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/filecachepb"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/profiledbtest"
	"github.com/AdguardTeam/golibs/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStorage returns new Storage and fills its config with given values.
// If conf is nil, default config will be used.
func newTestStorage(tb testing.TB, conf *filecachepb.Config) (storage *filecachepb.Storage) {
	tb.Helper()

	conf = cmp.Or(conf, &filecachepb.Config{})

	storage = filecachepb.New(&filecachepb.Config{
		Logger:           cmp.Or(conf.Logger, profiledbtest.Logger),
		BaseCustomLogger: cmp.Or(conf.BaseCustomLogger, profiledbtest.Logger),
		ProfileAccessConstructor: cmp.Or(
			conf.ProfileAccessConstructor,
			profiledbtest.ProfileAccessConstructor,
		),
		CacheFilePath: cmp.Or(
			conf.CacheFilePath,
			filepath.Join(tb.TempDir(), "profiles.pb"),
		),
		ResponseSizeEstimate: cmp.Or(conf.ResponseSizeEstimate, profiledbtest.RespSzEst),
	})
	require.NotNil(tb, storage)

	return storage
}

func TestStorage(t *testing.T) {
	prof, dev := profiledbtest.NewProfile(t)
	cachePath := filepath.Join(t.TempDir(), "profiles.pb")
	s := newTestStorage(t, &filecachepb.Config{CacheFilePath: cachePath})

	fc := &internal.FileCache{
		SyncTime: time.Now().Round(0).UTC(),
		Profiles: []*agd.Profile{prof},
		Devices:  []*agd.Device{dev},
		Version:  internal.FileCacheVersion,
	}

	ctx := profiledbtest.ContextWithTimeout(t)
	n, err := s.Store(ctx, fc)
	require.NoError(t, err)
	assert.Positive(t, n)

	gotFC, err := s.Load(ctx)
	require.NoError(t, err)
	require.NotNil(t, gotFC)
	require.NotEmpty(t, *gotFC)

	agdtest.AssertEqualProfile(t, fc, gotFC)
}

func TestStorage_Load_noFile(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "profiles.pb")
	s := newTestStorage(t, &filecachepb.Config{CacheFilePath: cachePath})

	ctx := profiledbtest.ContextWithTimeout(t)
	fc, err := s.Load(ctx)
	assert.NoError(t, err)
	assert.Nil(t, fc)
}

func TestStorage_Storage_Sort(t *testing.T) {
	prof1, dev1 := profiledbtest.NewProfile(t)

	prof2, dev2 := profiledbtest.NewProfile(t)
	prof2.ID = "profile_2"
	prof2.AccountID = 5678

	dev2.ID = "device_2"
	dev2.Name = "foo"

	prof2.DeviceIDs = container.NewMapSet(dev2.ID)
	prof1.DeviceIDs.Add(dev2.ID)

	dir := t.TempDir()
	syncTime := time.Now().Round(0).UTC()

	fc1 := &internal.FileCache{
		SyncTime: syncTime,
		Profiles: []*agd.Profile{prof1, prof2},
		Devices:  []*agd.Device{dev1, dev2},
		Version:  internal.FileCacheVersion,
	}

	fc2 := &internal.FileCache{
		SyncTime: syncTime,
		Profiles: []*agd.Profile{prof2, prof1},
		Devices:  []*agd.Device{dev2, dev1},
		Version:  internal.FileCacheVersion,
	}

	data1 := storedData(t, filepath.Join(dir, "cache1.pb"), fc1)
	data2 := storedData(t, filepath.Join(dir, "cache2.pb"), fc2)

	assert.Equal(t, data1, data2)
}

// storedData saves the fileCache to the given path and returns the file's raw
// content.  fileCache must not be nil.
func storedData(tb testing.TB, path string, fileCache *internal.FileCache) (data []byte) {
	tb.Helper()

	storage := newTestStorage(tb, &filecachepb.Config{CacheFilePath: path})

	ctx := profiledbtest.ContextWithTimeout(tb)

	_, err := storage.Store(ctx, fileCache)
	require.NoError(tb, err)

	data, err = os.ReadFile(path)
	require.NoError(tb, err)

	return data
}
