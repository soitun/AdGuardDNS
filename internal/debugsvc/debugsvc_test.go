package debugsvc_test

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/debugsvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/httputil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/fakeservice"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO(a.garipov): Improve and split tests.

// testTimeout is a common timeout for tests.
const testTimeout = 1 * time.Second

func TestService_Start(t *testing.T) {
	// TODO(a.garipov): Consider adding an HTTP server constructor as a part of
	// the configuration structure to use net/http/httptest's server in tests.
	const addr = "127.0.0.1:8082"
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		pt := testutil.PanicT{}

		_, err := w.Write([]byte("[]"))
		require.NoError(pt, err)
	})

	var refreshed []string
	refreshers := debugsvc.Refreshers{
		"test": &fakeservice.Refresher{
			OnRefresh: func(_ context.Context) (err error) {
				refreshed = append(refreshed, "test")

				return nil
			},
		},
		"parent/first": &fakeservice.Refresher{
			OnRefresh: func(_ context.Context) (err error) {
				refreshed = append(refreshed, "parent/first")

				return nil
			},
		},
		"parent/second": &fakeservice.Refresher{
			OnRefresh: func(_ context.Context) (err error) {
				refreshed = append(refreshed, "parent/second")

				return nil
			},
		},
	}

	cacheManager := agdcache.NewDefaultManager()
	cacheManager.Add("test", agdcache.Empty[any, any]{})

	const geoIPReqIP = "192.0.2.1"

	geoIPLoc := &geoip.Location{
		Country:        geoip.CountryAD,
		Continent:      geoip.ContinentEU,
		TopSubdivision: "TopSubdivision",
		ASN:            42,
	}

	geoIPSubnet := netip.MustParsePrefix("198.51.100.0/24")

	geoIP := agdtest.NewGeoIP()
	geoIP.OnData = func(
		_ context.Context,
		host string,
		addr netip.Addr,
	) (l *geoip.Location, err error) {
		pt := testutil.PanicT{}

		require.Empty(pt, host)
		require.Equal(pt, geoIPReqIP, addr.String())

		return geoIPLoc, nil
	}
	geoIP.OnSubnetByLocation = func(
		_ context.Context,
		l *geoip.Location,
		fam netutil.AddrFamily,
	) (n netip.Prefix, err error) {
		pt := testutil.PanicT{}

		require.Equal(pt, geoIPLoc, l)

		if fam == netutil.AddrFamilyIPv4 {
			return geoIPSubnet, nil
		}

		return netip.Prefix{}, nil
	}

	c := &debugsvc.Config{
		DNSDBHandler:   h,
		GeoIP:          geoIP,
		Logger:         slogutil.NewDiscardLogger(),
		DNSDBAddr:      addr,
		Manager:        cacheManager,
		Refreshers:     refreshers,
		APIAddr:        addr,
		PprofAddr:      addr,
		PrometheusAddr: addr,
	}

	svc := debugsvc.New(c)
	require.NotNil(t, svc)

	servicetest.RequireRun(t, svc, testTimeout)

	client := agdhttp.NewClient(&agdhttp.ClientConfig{
		Timeout: testTimeout,
	})

	srvURL := &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   addr,
	}

	// Use a context without a timeout, since it is used with agdhttp.Client,
	// which already has a timeout.
	ctx := context.Background()

	// First check health-check service URL.  As the service could not be ready
	// yet, check for it in periodically.
	var resp *http.Response
	healthCheckURL := srvURL.JoinPath(debugsvc.PathPatternHealthCheck)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		var getErr error
		resp, getErr = client.Get(ctx, healthCheckURL)
		assert.NoError(c, getErr)
	}, testTimeout, testTimeout/10)

	body := readRespBody(t, resp)
	assert.Equal(t, "OK\n", body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Check pprof service URL.
	resp, err := client.Get(ctx, srvURL.JoinPath(httputil.PprofBasePath))
	require.NoError(t, err)

	body = readRespBody(t, resp)
	assert.True(t, len(body) > 0)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Check prometheus service URL.
	resp, err = client.Get(ctx, srvURL.JoinPath(debugsvc.PathPatternMetrics))
	require.NoError(t, err)

	body = readRespBody(t, resp)
	assert.True(t, len(body) > 0)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Check refresh API.

	reqBody := strings.NewReader(`{"ids":["test"]}`)
	refreshURL := srvURL.JoinPath(debugsvc.PathPatternDebugAPIRefresh)
	resp, err = client.Post(ctx, refreshURL, agdhttp.HdrValApplicationJSON, reqBody)
	require.NoError(t, err)

	assert.Len(t, refreshed, 1)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	respBody := readRespBody(t, resp)
	assert.JSONEq(t, `{"results":{"test":"ok"}}`, respBody)

	refreshed = []string{}

	reqBody = strings.NewReader(`{"ids":["parent/*"]}`)
	resp, err = client.Post(ctx, refreshURL, agdhttp.HdrValApplicationJSON, reqBody)
	require.NoError(t, err)

	assert.Len(t, refreshed, 2)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	respBody = readRespBody(t, resp)
	assert.JSONEq(t, `{"results":{"parent/first":"ok","parent/second":"ok"}}`, respBody)

	refreshed = []string{}

	reqBody = strings.NewReader(`{"ids":["test","*"]}`)
	resp, err = client.Post(ctx, refreshURL, agdhttp.HdrValApplicationJSON, reqBody)
	require.NoError(t, err)

	assert.Empty(t, refreshed)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	respBody = readRespBody(t, resp)
	assert.Equal(t, `"*" cannot be used with other ids`+"\n", respBody)

	// Check cache purge API.

	const (
		clearReq  = `{"ids":["test"]}`
		clearResp = `{"results":{"test":"ok"}}`
	)

	reqBody = strings.NewReader(clearReq)
	cacheURL := srvURL.JoinPath(debugsvc.PathPatternDebugAPICache)
	resp, err = client.Post(ctx, cacheURL, agdhttp.HdrValApplicationJSON, reqBody)
	require.NoError(t, err)

	respBody = readRespBody(t, resp)
	assert.JSONEq(t, clearResp, respBody)

	// Check GeoIP API.
	geoIPQuery := url.Values{}
	geoIPQuery.Add(debugsvc.QueryKeyGeoIP, geoIPReqIP)

	geoIPURL := srvURL.JoinPath(debugsvc.PathPatternDebugAPIGeoIP)
	geoIPURL.RawQuery = geoIPQuery.Encode()

	resp, err = client.Get(ctx, geoIPURL)
	require.NoError(t, err)

	const wantGeoIPResp = `
		{
		  "data": {
			"192.0.2.1": {
			  "asn": 42,
			  "continent": "EU",
			  "country": "AD",
			  "top_subdivision": "TopSubdivision",
			  "replacement_subnets": {
				"ipv4": "198.51.100.0/24"
			  }
			}
		  }
		}`

	respBody = readRespBody(t, resp)
	assert.JSONEq(t, wantGeoIPResp, respBody)
}

// readRespBody is a helper function that reads and returns body from response.
func readRespBody(t testing.TB, resp *http.Response) (body string) {
	t.Helper()

	buf, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return string(buf)
}
