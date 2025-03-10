package rulelist_test

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testReqHost is the request host for tests.
const testReqHost = "blocked.example"

// testRemoteIP is the client IP for tests
var testRemoteIP = netip.MustParseAddr("1.2.3.4")

// testFltListID is the common filter list IDs for tests.
const testFltListID filter.ID = "fl1"

// testBlockRule is the common blocking rule for tests.
const testBlockRule = "||" + testReqHost + "\n"

func TestRefreshable_RulesCount(t *testing.T) {
	rl := rulelist.NewFromString(testBlockRule, testFltListID, "", rulelist.EmptyResultCache{})

	assert.Equal(t, 1, rl.RulesCount())
}

func TestRefreshable_DNSResult_cache(t *testing.T) {
	cache := rulelist.NewResultCache(filtertest.CacheCount, true)
	rl := rulelist.NewFromString(testBlockRule, testFltListID, "", cache)

	const qt = dns.TypeA

	t.Run("blocked", func(t *testing.T) {
		dr := rl.DNSResult(testRemoteIP, "", testReqHost, qt, false)
		require.NotNil(t, dr)

		assert.Len(t, dr.NetworkRules, 1)

		cachedDR := rl.DNSResult(testRemoteIP, "", testReqHost, qt, false)
		require.NotNil(t, cachedDR)

		assert.Same(t, dr, cachedDR)
	})

	t.Run("none", func(t *testing.T) {
		const otherHost = "other.example"

		dr := rl.DNSResult(testRemoteIP, "", otherHost, qt, false)
		assert.Nil(t, dr)

		cachedDR := rl.DNSResult(testRemoteIP, "", otherHost, dns.TypeA, false)
		assert.Nil(t, cachedDR)
	})
}

func TestRefreshable_ID(t *testing.T) {
	const svcID = filter.BlockedServiceID("test_service")
	rl := rulelist.NewFromString(testBlockRule, testFltListID, svcID, rulelist.EmptyResultCache{})

	gotID, gotSvcID := rl.ID()
	assert.Equal(t, testFltListID, gotID)
	assert.Equal(t, svcID, gotSvcID)
}

func TestRefreshable_Refresh(t *testing.T) {
	cachePath, srvURL := filtertest.PrepareRefreshable(t, nil, testBlockRule, http.StatusOK)
	rl, err := rulelist.NewRefreshable(
		&refreshable.Config{
			Logger:    slogutil.NewDiscardLogger(),
			URL:       srvURL,
			ID:        testFltListID,
			CachePath: cachePath,
			Staleness: filtertest.Staleness,
			MaxSize:   filtertest.FilterMaxSize,
		},
		rulelist.NewResultCache(filtertest.CacheCount, true),
	)
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
	err = rl.Refresh(ctx, false)
	require.NoError(t, err)

	assert.Equal(t, 1, rl.RulesCount())

	dr := rl.DNSResult(testRemoteIP, "", testReqHost, dns.TypeA, false)
	require.NotNil(t, dr)

	assert.Len(t, dr.NetworkRules, 1)
}
