package rulestat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
)

// statFilterListLegacyID is the ID of the filtering rule list for which we
// collect statistics, as understood and accepted by the current backend.  This
// is a temporary restriction.
//
// TODO(ameshkov): Consider making the backend accept the current IDs.
const statFilterListLegacyID agd.FilterListID = "15"

// HTTP is the filtering rule statistics collector that uploads the statistics
// to the given URL when it's refreshed.
//
// TODO(a.garipov): Add tests.
type HTTP struct {
	url     *url.URL
	http    *agdhttp.Client
	errColl errcoll.Interface

	// mu protects stats and recordedHits.
	mu           *sync.Mutex
	stats        statsSet
	recordedHits int64
}

// statsSet is an alias for the stats set type.
type statsSet = map[agd.FilterListID]map[agd.FilterRuleText]uint64

// HTTPConfig is the configuration structure for the filtering rule statistics
// collector that uploads the statistics to a URL.  All fields are required.
type HTTPConfig struct {
	// ErrColl is used to collect errors during refreshes.
	ErrColl errcoll.Interface

	// URL is the URL to which the statistics is uploaded.
	URL *url.URL
}

// NewHTTP returns a new statistics collector with HTTP upload.
func NewHTTP(c *HTTPConfig) (s *HTTP) {
	return &HTTP{
		url: netutil.CloneURL(c.URL),
		http: agdhttp.NewClient(&agdhttp.ClientConfig{
			// TODO(ameshkov): Consider making configurable.
			Timeout: 30 * time.Second,
		}),
		errColl: c.ErrColl,

		mu:    &sync.Mutex{},
		stats: statsSet{},
	}
}

// type check
var _ Interface = (*HTTP)(nil)

// Collect implements the Interface interface for *HTTP.
func (s *HTTP) Collect(_ context.Context, id agd.FilterListID, text agd.FilterRuleText) {
	if id != agd.FilterListIDAdGuardDNS {
		return
	}

	id = statFilterListLegacyID

	s.mu.Lock()
	defer s.mu.Unlock()

	s.recordedHits++
	metrics.RuleStatCacheSize.Set(float64(s.recordedHits))

	texts := s.stats[id]
	if texts != nil {
		texts[text]++

		return
	}

	s.stats[id] = map[agd.FilterRuleText]uint64{
		text: 1,
	}
}

// type check
var _ agdservice.Refresher = (*HTTP)(nil)

// Refresh implements the [agdservice.Refresher] interface for *HTTP.  It
// uploads the collected statistics to s.u and starts collecting a new set of
// statistics.
func (s *HTTP) Refresh(ctx context.Context) (err error) {
	// TODO(a.garipov):  Use slog.
	log.Info("rulestat_refresh: started")
	defer log.Info("rulestat_refresh: finished")

	err = s.refresh(ctx)
	if err != nil {
		errcoll.Collectf(ctx, s.errColl, "rulestat_refresh: %w", err)
		metrics.SetStatusGauge(metrics.RuleStatUploadStatus, err)

		return err
	}

	metrics.RuleStatUploadTimestamp.SetToCurrentTime()
	metrics.SetStatusGauge(metrics.RuleStatUploadStatus, nil)

	return nil
}

// refresh uploads the collected statistics and resets the collected stats.
func (s *HTTP) refresh(ctx context.Context) (err error) {
	stats := s.replaceStats()
	req := &filtersReq{
		Filters: stats,
	}

	b, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("encoding filter stats: %w", err)
	}

	httpResp, err := s.http.Post(ctx, s.url, agdhttp.HdrValApplicationJSON, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("uploading filter stats: %w", err)
	}
	defer func() { err = errors.WithDeferred(err, httpResp.Body.Close()) }()

	// Don't wrap the error, because it's informative enough as is.
	return agdhttp.CheckStatus(httpResp, http.StatusOK)
}

// replaceStats replaced the current stats of s with a new set and returns the
// previous one.
func (s *HTTP) replaceStats() (prev statsSet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prev, s.stats = s.stats, statsSet{}
	s.recordedHits = 0

	return prev
}

// filtersReq is the JSON filtering rule list statistics request structure.
type filtersReq struct {
	Filters statsSet `json:"filters"`
}
