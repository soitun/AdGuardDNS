package dnssvc

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/cache"
	dnssrvprom "github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/prometheus"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/devicefinder"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/initial"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/mainmw"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/preservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/preupstream"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/ratelimitmw"
	"github.com/AdguardTeam/AdGuardDNS/internal/ecscache"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// NewHandlers returns the main DNS handlers wrapped in all necessary
// middlewares.  c must not be nil.
func NewHandlers(ctx context.Context, c *HandlersConfig) (handlers Handlers, err error) {
	handler := wrapPreUpstreamMw(ctx, c)

	mainMwMtrc, err := newMainMiddlewareMetrics(c)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	mainMw := mainmw.New(&mainmw.Config{
		Cloner:        c.Cloner,
		Logger:        c.BaseLogger.With(slogutil.KeyPrefix, "mainmw"),
		Messages:      c.Messages,
		BillStat:      c.BillStat,
		ErrColl:       c.ErrColl,
		FilterStorage: c.FilterStorage,
		GeoIP:         c.GeoIP,
		QueryLog:      c.QueryLog,
		Metrics:       mainMwMtrc,
		RuleStat:      c.RuleStat,
	})

	handler = mainMw.Wrap(handler)

	preSvcMw := preservice.New(&preservice.Config{
		Logger:      c.BaseLogger.With(slogutil.KeyPrefix, "presvcmw"),
		Messages:    c.Messages,
		HashMatcher: c.HashMatcher,
		Checker:     c.DNSCheck,
	})

	handler = preSvcMw.Wrap(handler)

	postInitMw := c.PluginRegistry.PostInitialMiddleware()
	if postInitMw != nil {
		handler = postInitMw.Wrap(handler)
	}

	initMw := initial.New(&initial.Config{
		Logger: c.BaseLogger.With(slogutil.KeyPrefix, "initmw"),
	})

	handler = initMw.Wrap(handler)

	return newHandlersForServers(c, handler)
}

// wrapPreUpstreamMw returns the handler wrapped into the pre-upstream
// middlewares.
//
// TODO(a.garipov):  Adapt the cache tests that previously were in package
// preupstream.
func wrapPreUpstreamMw(ctx context.Context, c *HandlersConfig) (wrapped dnsserver.Handler) {
	// TODO(a.garipov):  Use in other places if necessary.
	l := c.BaseLogger.With(slogutil.KeyPrefix, "dnssvc")

	wrapped = c.Handler
	switch conf := c.Cache; conf.Type {
	case CacheTypeNone:
		l.WarnContext(ctx, "cache disabled")
	case CacheTypeSimple:
		l.InfoContext(ctx, "plain cache enabled", "count", conf.NoECSCount)

		cacheMw := cache.NewMiddleware(&cache.MiddlewareConfig{
			// TODO(a.garipov):  Do not use promauto and refactor.
			MetricsListener: dnssrvprom.NewCacheMetricsListener(metrics.Namespace()),
			Count:           conf.NoECSCount,
			MinTTL:          conf.MinTTL,
			OverrideTTL:     conf.OverrideCacheTTL,
		})

		wrapped = cacheMw.Wrap(wrapped)
	case CacheTypeECS:
		l.InfoContext(
			ctx,
			"ecs cache enabled",
			"ecs_count", conf.ECSCount,
			"no_ecs_count", conf.NoECSCount,
		)

		cacheMw := ecscache.NewMiddleware(&ecscache.MiddlewareConfig{
			Cloner:       c.Cloner,
			Logger:       c.BaseLogger.With(slogutil.KeyPrefix, "ecscache"),
			CacheManager: c.CacheManager,
			GeoIP:        c.GeoIP,
			NoECSCount:   conf.NoECSCount,
			ECSCount:     conf.ECSCount,
			MinTTL:       conf.MinTTL,
			OverrideTTL:  conf.OverrideCacheTTL,
		})

		wrapped = cacheMw.Wrap(wrapped)
	default:
		panic(fmt.Errorf("cache type: %w: %d", errors.ErrBadEnumValue, conf.Type))
	}

	preUps := preupstream.New(ctx, &preupstream.Config{
		DB: c.DNSDB,
	})

	wrapped = preUps.Wrap(wrapped)

	return wrapped
}

// newMainMiddlewareMetrics returns a filtering-middleware metrics
// implementation from the config.
func newMainMiddlewareMetrics(c *HandlersConfig) (mainMwMtrc MainMiddlewareMetrics, err error) {
	mainMwMtrc = c.PluginRegistry.MainMiddlewareMetrics()
	if mainMwMtrc != nil {
		return mainMwMtrc, nil
	}

	mainMwMtrc, err = metrics.NewDefaultMainMiddleware(c.MetricsNamespace, c.PrometheusRegisterer)
	if err != nil {
		return nil, fmt.Errorf("mainmw metrics: %w", err)
	}

	return mainMwMtrc, nil
}

// newHandlersForServers returns a handler map for each server group and each
// server.
func newHandlersForServers(c *HandlersConfig, h dnsserver.Handler) (handlers Handlers, err error) {
	rlMwMtrc, err := metrics.NewDefaultRatelimitMiddleware(
		c.MetricsNamespace,
		c.PrometheusRegisterer,
	)
	if err != nil {
		return nil, fmt.Errorf("ratelimit middleware metrics: %w", err)
	}

	handlers = Handlers{}

	rlMwLogger := c.BaseLogger.With(slogutil.KeyPrefix, "ratelimitmw")
	for _, srvGrp := range c.ServerGroups {
		fltGrp, ok := c.FilteringGroups[srvGrp.FilteringGroup]
		if !ok {
			return nil, fmt.Errorf(
				"no filtering group %q for server group %q",
				srvGrp.FilteringGroup,
				srvGrp.Name,
			)
		}

		for _, srv := range srvGrp.Servers {
			rlMw := ratelimitmw.New(&ratelimitmw.Config{
				Logger:           rlMwLogger,
				Messages:         c.Messages,
				FilteringGroup:   fltGrp,
				ServerGroup:      srvGrp,
				Server:           srv,
				StructuredErrors: c.StructuredErrors,
				AccessManager:    c.AccessManager,
				DeviceFinder:     newDeviceFinder(c, srvGrp, srv),
				ErrColl:          c.ErrColl,
				GeoIP:            c.GeoIP,
				Metrics:          rlMwMtrc,
				Limiter:          c.RateLimit,
				Protocols:        []agd.Protocol{agd.ProtoDNS},
				EDEEnabled:       c.EDEEnabled,
			})

			k := HandlerKey{
				Server:      srv,
				ServerGroup: srvGrp,
			}

			handlers[k] = rlMw.Wrap(h)
		}
	}

	return handlers, nil
}

// newDeviceFinder returns a new agd.DeviceFinder for a server based on the
// configuration.  All arguments must not be nil.
func newDeviceFinder(c *HandlersConfig, g *agd.ServerGroup, s *agd.Server) (df agd.DeviceFinder) {
	if !g.ProfilesEnabled {
		return agd.EmptyDeviceFinder{}
	}

	return devicefinder.NewDefault(&devicefinder.Config{
		Logger:        c.BaseLogger.With(slogutil.KeyPrefix, "devicefinder"),
		ProfileDB:     c.ProfileDB,
		HumanIDParser: c.HumanIDParser,
		Server:        s,
		DeviceDomains: g.DeviceDomains,
	})
}
