package debugsvc

import (
	"log/slog"
	"net/http"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil/httputil"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ErrDebugPanic is a default error for panic handler.
const ErrDebugPanic errors.Error = "debug panic"

// Path pattern constants.
const (
	PathPatternDNSDBCSV        = "/dnsdb/csv"
	PathPatternDebugAPICache   = "/debug/api/cache/clear"
	PathPatternDebugAPIGeoIP   = "/debug/api/geoip"
	PathPatternDebugAPIRefresh = "/debug/api/refresh"
	PathPatternDebugPanic      = "/debug/panic"
	PathPatternHealthCheck     = "/health-check"
	PathPatternMetrics         = "/metrics"
)

// Route pattern constants.
const (
	routePatternDNSDBCSV        = http.MethodPost + " " + PathPatternDNSDBCSV
	routePatternDebugAPICache   = http.MethodPost + " " + PathPatternDebugAPICache
	routePatternDebugAPIGeoIP   = http.MethodGet + " " + PathPatternDebugAPIGeoIP
	routePatternDebugAPIRefresh = http.MethodPost + " " + PathPatternDebugAPIRefresh
	routePatternDebugPanic      = http.MethodPost + " " + PathPatternDebugPanic
	routePatternHealthCheck     = http.MethodGet + " " + PathPatternHealthCheck
	routePatternMetrics         = http.MethodGet + " " + PathPatternMetrics
)

// route further initializes the svc.servers field by adding handlers and
// loggers to each server.
//
// TODO(a.garipov):  Consider splitting.
func (svc *Service) route(c *Config) {
	const hdlrGrpKey = "hdlr_grp"

	reqIDMw := httputil.NewRequestIDMiddleware()
	if srv := svc.servers[c.APIAddr]; srv != nil {
		router := srv.http.Handler.(httputil.Router)
		l := svc.logger.With(hdlrGrpKey, handlerGroupAPI)

		router.Handle(
			routePatternHealthCheck,
			httputil.Wrap(
				httputil.HealthCheckHandler,
				reqIDMw,
				httputil.NewLogMiddleware(l, slogutil.LevelTrace),
			),
		)

		infoLogMw := httputil.NewLogMiddleware(l, slog.LevelInfo)
		router.Handle(routePatternDebugAPIRefresh, httputil.Wrap(svc.refrHdlr, reqIDMw, infoLogMw))
		router.Handle(routePatternDebugAPICache, httputil.Wrap(svc.cacheHdlr, reqIDMw, infoLogMw))
		router.Handle(routePatternDebugAPIGeoIP, httputil.Wrap(svc.geoIPHdlr, reqIDMw, infoLogMw))

		panicHdlr := httputil.PanicHandler(ErrDebugPanic)
		router.Handle(routePatternDebugPanic, httputil.Wrap(panicHdlr, reqIDMw, infoLogMw))
	}

	if srv := svc.servers[c.DNSDBAddr]; srv != nil {
		router := srv.http.Handler.(httputil.Router)
		l := svc.logger.With(hdlrGrpKey, handlerGroupDNSDB)

		router.Handle(
			routePatternDNSDBCSV,
			httputil.Wrap(
				svc.dnsDB,
				reqIDMw,
				httputil.NewLogMiddleware(l, slog.LevelInfo),
			),
		)
	}

	if srv := svc.servers[c.PprofAddr]; srv != nil {
		router := srv.http.Handler.(httputil.Router)
		l := svc.logger.With(hdlrGrpKey, handlerGroupPprof)
		mw := httputil.NewLogMiddleware(l, slog.LevelDebug)

		routeWithMw := httputil.RouterFunc(func(pattern string, h http.Handler) {
			router.Handle(pattern, httputil.Wrap(h, reqIDMw, mw))
		})

		httputil.RoutePprof(routeWithMw)
	}

	if srv := svc.servers[c.PrometheusAddr]; srv != nil {
		router := srv.http.Handler.(httputil.Router)
		l := svc.logger.With(hdlrGrpKey, handlerGroupPrometheus)

		router.Handle(
			routePatternMetrics,
			httputil.Wrap(
				promhttp.Handler(),
				reqIDMw,
				httputil.NewLogMiddleware(l, slogutil.LevelTrace)),
		)
	}

	srvHdrMw := httputil.ServerHeaderMiddleware(agdhttp.UserAgent())
	for _, srv := range svc.servers {
		l := svc.logger.With("name", srv.name)
		srv.http.ErrorLog = slog.NewLogLogger(l.Handler(), slog.LevelDebug)
		srv.http.Handler = httputil.Wrap(srv.http.Handler, srvHdrMw, reqIDMw)
	}
}
