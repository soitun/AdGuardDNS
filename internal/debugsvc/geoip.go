package debugsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
)

// QueryKeyGeoIP is the key of the query parameter that contains IP addresses.
const QueryKeyGeoIP = "ip"

// geoIPHandler handles request to GeoIP API endpoint.
type geoIPHandler struct {
	// geoIP is the GeoIP database used to detect geographic data about IP
	// addresses in requests and responses.  It must not be nil.
	geoIP geoip.Interface
}

// geoIPResponse describes the response to the GET /debug/api/geoip HTTP API.
type geoIPResponse struct {
	// Data is a map of IP addresses to their GeoIP results.
	Data map[netip.Addr]*geoIPResult `json:"data"`
}

// geoIPResult describes the result of a GeoIP query for a specific IP address.
type geoIPResult struct {
	Error              error               `json:"error,omitempty"`
	ReplacementSubnets *replacementSubnets `json:"replacement_subnets,omitempty"`
	Country            geoip.Country       `json:"country,omitempty"`
	Continent          geoip.Continent     `json:"continent,omitempty"`
	TopSubdivision     string              `json:"top_subdivision,omitempty"`
	ASN                geoip.ASN           `json:"asn,omitempty"`
}

// replacementSubnets describes the replacement subnets for a specific IP
// address.
type replacementSubnets struct {
	IPv4 *netip.Prefix `json:"ipv4,omitempty"`
	IPv6 *netip.Prefix `json:"ipv6,omitempty"`
}

// type check
var _ http.Handler = (*geoIPHandler)(nil)

// ServeHTTP implements the [http.Handler] interface for *geoIPHandler.
func (h *geoIPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l := slogutil.MustLoggerFromContext(ctx)

	var errs []error
	var reqIPs []netip.Addr
	for i, ipStr := range r.URL.Query()[QueryKeyGeoIP] {
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			errs = append(errs, fmt.Errorf("parsing ip address from query at index %d: %w", i, err))

			continue
		}

		reqIPs = append(reqIPs, addr)
	}

	err := errors.Join(errs...)
	if err != nil {
		l.ErrorContext(ctx, "parsing request parameters", slogutil.KeyError, err)
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	resp := &geoIPResponse{
		Data: make(map[netip.Addr]*geoIPResult, len(reqIPs)),
	}

	for _, addr := range reqIPs {
		resp.Data[addr] = h.queryAddr(ctx, addr)
	}

	w.Header().Set(httphdr.ContentType, agdhttp.HdrValApplicationJSON)
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		l.ErrorContext(ctx, "writing response", slogutil.KeyError, err)
	}
}

// queryAddr returns the result of a GeoIP query for a specific IP address.
func (h *geoIPHandler) queryAddr(ctx context.Context, addr netip.Addr) (res *geoIPResult) {
	res = &geoIPResult{}

	loc, err := h.geoIP.Data(ctx, "", addr)
	if err != nil {
		res.Error = err

		return res
	}

	subnets, err := h.querySubnets(ctx, loc)
	if err != nil {
		res.Error = err

		return res
	}

	res.ReplacementSubnets = subnets
	res.Country = loc.Country
	res.Continent = loc.Continent
	res.TopSubdivision = loc.TopSubdivision
	res.ASN = loc.ASN

	return res
}

// querySubnets returns the replacement subnets for a specific location.  loc
// must not be nil.
func (h *geoIPHandler) querySubnets(
	ctx context.Context,
	loc *geoip.Location,
) (subnets *replacementSubnets, err error) {
	var errs []error

	subnetIPv4, err := h.geoIP.SubnetByLocation(ctx, loc, netutil.AddrFamilyIPv4)
	if err != nil {
		errs = append(errs, err)
	}

	subnetIPv6, err := h.geoIP.SubnetByLocation(ctx, loc, netutil.AddrFamilyIPv6)
	if err != nil {
		errs = append(errs, err)
	}

	err = errors.Join(errs...)
	if err != nil {
		return nil, fmt.Errorf("querying subnets: %w", err)
	}

	omitIPv4 := isUnspecifiedPrefix(subnetIPv4)
	omitIPv6 := isUnspecifiedPrefix(subnetIPv6)

	if omitIPv4 && omitIPv6 {
		return nil, nil
	}

	subnets = &replacementSubnets{}
	if !omitIPv4 {
		subnets.IPv4 = &subnetIPv4
	}
	if !omitIPv6 {
		subnets.IPv6 = &subnetIPv6
	}

	return subnets, nil
}

// isUnspecifiedPrefix returns true the given prefix is zero or not specified.
func isUnspecifiedPrefix(p netip.Prefix) (ok bool) {
	return p == (netip.Prefix{}) || p.Addr().IsUnspecified()
}
