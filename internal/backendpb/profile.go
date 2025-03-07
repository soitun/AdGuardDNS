package backendpb

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/c2h5oh/datasize"
)

// toInternal converts the protobuf-encoded data into a profile structure and
// its device structures.
//
// TODO(a.garipov):  Refactor into methods of [*ProfileStorage].
func (x *DNSProfile) toInternal(
	ctx context.Context,
	bindSet netutil.SubnetSet,
	errColl errcoll.Interface,
	logger *slog.Logger,
	baseCustomLogger *slog.Logger,
	mtrc ProfileDBMetrics,
	respSzEst datasize.ByteSize,
) (profile *agd.Profile, devices []*agd.Device, err error) {
	if x == nil {
		return nil, nil, fmt.Errorf("profile is nil")
	}

	parental, err := x.Parental.toInternal(ctx, errColl, logger)
	if err != nil {
		return nil, nil, fmt.Errorf("parental: %w", err)
	}

	m, err := blockingModeToInternal(x.BlockingMode)
	if err != nil {
		return nil, nil, fmt.Errorf("blocking mode: %w", err)
	}

	devices, deviceIds := devicesToInternal(ctx, x.Devices, bindSet, errColl, logger, mtrc)

	profID, err := agd.NewProfileID(x.DnsId)
	if err != nil {
		return nil, nil, fmt.Errorf("id: %w", err)
	}

	var fltRespTTL time.Duration
	if respTTL := x.FilteredResponseTtl; respTTL != nil {
		fltRespTTL = respTTL.AsDuration()
	}

	customRules := rulesToInternal(ctx, x.CustomRules, errColl, logger)
	customEnabled := len(customRules) > 0

	var customFilter filter.Custom
	if customEnabled {
		customFilter = custom.New(&custom.Config{
			Logger: baseCustomLogger.With("client_id", string(profID)),
			Rules:  customRules,
		})
	}

	custom := &filter.ConfigCustom{
		Filter: customFilter,
		// TODO(a.garipov):  Consider adding an explicit flag to the protocol.
		Enabled: customEnabled,
	}

	return &agd.Profile{
		FilterConfig: &filter.ConfigClient{
			Custom:       custom,
			Parental:     parental,
			RuleList:     x.RuleLists.toInternal(ctx, errColl, logger),
			SafeBrowsing: x.SafeBrowsing.toInternal(),
		},
		Access:              x.Access.toInternal(ctx, errColl, logger),
		BlockingMode:        m,
		Ratelimiter:         x.RateLimit.toInternal(ctx, errColl, logger, respSzEst),
		ID:                  profID,
		DeviceIDs:           deviceIds,
		FilteredResponseTTL: fltRespTTL,
		AutoDevicesEnabled:  x.AutoDevicesEnabled,
		BlockChromePrefetch: x.BlockChromePrefetch,
		BlockFirefoxCanary:  x.BlockFirefoxCanary,
		BlockPrivateRelay:   x.BlockPrivateRelay,
		Deleted:             x.Deleted,
		FilteringEnabled:    x.FilteringEnabled,
		IPLogEnabled:        x.IpLogEnabled,
		QueryLogEnabled:     x.QueryLogEnabled,
	}, devices, nil
}

// toInternal converts a protobuf parental-protection settings structure to an
// internal one.  If x is nil, toInternal returns a disabled configuration.
func (x *ParentalSettings) toInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	logger *slog.Logger,
) (c *filter.ConfigParental, err error) {
	c = &filter.ConfigParental{}
	if x == nil {
		return c, nil
	}

	c.AdultBlockingEnabled = x.BlockAdult
	c.BlockedServices = blockedSvcsToInternal(ctx, errColl, logger, x.BlockedServices)
	c.Enabled = x.Enabled
	c.SafeSearchGeneralEnabled = x.GeneralSafeSearch
	c.SafeSearchYouTubeEnabled = x.YoutubeSafeSearch

	c.PauseSchedule, err = x.Schedule.toInternal()
	if err != nil {
		return nil, fmt.Errorf("pause schedule: %w", err)
	}

	return c, nil
}

// toInternal converts protobuf rate-limiting settings to an internal structure.
// If x is nil, toInternal returns [agd.GlobalRatelimiter].
func (x *RateLimitSettings) toInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	logger *slog.Logger,
	respSzEst datasize.ByteSize,
) (r agd.Ratelimiter) {
	if x == nil || !x.Enabled {
		return agd.GlobalRatelimiter{}
	}

	return agd.NewDefaultRatelimiter(&agd.RatelimitConfig{
		ClientSubnets: cidrRangeToInternal(ctx, errColl, logger, x.ClientCidr),
		RPS:           x.Rps,
		Enabled:       x.Enabled,
	}, respSzEst)
}

// toInternal converts protobuf safe-browsing settings to an internal
// safe-browsing configuration.  If x is nil, toInternal returns a disabled
// configuration.
func (x *SafeBrowsingSettings) toInternal() (c *filter.ConfigSafeBrowsing) {
	c = &filter.ConfigSafeBrowsing{}
	if x == nil {
		return c
	}

	c.Enabled = x.Enabled
	c.DangerousDomainsEnabled = x.BlockDangerousDomains
	c.NewlyRegisteredDomainsEnabled = x.BlockNrd

	return c
}

// toInternal converts protobuf access settings to an internal structure.  If x
// is nil, toInternal returns [access.EmptyProfile].
func (x *AccessSettings) toInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	logger *slog.Logger,
) (a access.Profile) {
	if x == nil || !x.Enabled {
		return access.EmptyProfile{}
	}

	return access.NewDefaultProfile(&access.ProfileConfig{
		AllowedNets:          cidrRangeToInternal(ctx, errColl, logger, x.AllowlistCidr),
		BlockedNets:          cidrRangeToInternal(ctx, errColl, logger, x.BlocklistCidr),
		AllowedASN:           asnToInternal(x.AllowlistAsn),
		BlockedASN:           asnToInternal(x.BlocklistAsn),
		BlocklistDomainRules: x.BlocklistDomainRules,
	})
}

// cidrRangeToInternal is a helper that converts a slice of CidrRange to the
// slice of [netip.Prefix].
func cidrRangeToInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	logger *slog.Logger,
	cidrs []*CidrRange,
) (out []netip.Prefix) {
	for i, c := range cidrs {
		addr, ok := netip.AddrFromSlice(c.Address)
		if !ok {
			err := fmt.Errorf("bad cidr at index %d: %v", i, c.Address)
			errcoll.Collect(ctx, errColl, logger, "converting cidrs", err)

			continue
		}

		out = append(out, netip.PrefixFrom(addr, int(c.Prefix)))
	}

	return out
}

// asnToInternal is a helper that converts a slice of ASNs to the slice of
// [geoip.ASN].
func asnToInternal(asns []uint32) (out []geoip.ASN) {
	for _, asn := range asns {
		out = append(out, geoip.ASN(asn))
	}

	return out
}

// blockedSvcsToInternal is a helper that converts the blocked service IDs from
// the backend response to AdGuard DNS blocked-service IDs.
func blockedSvcsToInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	logger *slog.Logger,
	respSvcs []string,
) (ids []filter.BlockedServiceID) {
	l := len(respSvcs)
	if l == 0 {
		return nil
	}

	ids = make([]filter.BlockedServiceID, 0, l)
	for i, idStr := range respSvcs {
		id, err := filter.NewBlockedServiceID(idStr)
		if err != nil {
			err = fmt.Errorf("at index %d: %w", i, err)
			errcoll.Collect(ctx, errColl, logger, "converting blocked services", err)

			continue
		}

		ids = append(ids, id)
	}

	return ids
}

// toInternal converts a protobuf protection-schedule structure to an internal
// one.  If x is nil, toInternal returns nil.
func (x *ScheduleSettings) toInternal() (c *filter.ConfigSchedule, err error) {
	if x == nil {
		return nil, nil
	}

	c = &filter.ConfigSchedule{
		Week: &filter.WeeklySchedule{},
	}

	c.TimeZone, err = agdtime.LoadLocation(x.Tmz)
	if err != nil {
		return nil, fmt.Errorf("loading timezone: %w", err)
	}

	w := x.WeeklyRange
	days := []*DayRange{w.Sun, w.Mon, w.Tue, w.Wed, w.Thu, w.Fri, w.Sat}
	for i, d := range days {
		if d == nil {
			continue
		}

		ivl := &filter.DayInterval{
			Start: uint16(d.Start.AsDuration().Minutes()),
			End:   uint16(d.End.AsDuration().Minutes() + 1),
		}

		err = ivl.Validate()
		if err != nil {
			return nil, fmt.Errorf("weekday %s: %w", time.Weekday(i), err)
		}

		c.Week[i] = ivl
	}

	return c, nil
}

// toInternal converts a protobuf custom blocking-mode to an internal one.
// Assumes that at least one IP address is specified in the result blocking-mode
// object.
func (pbm *BlockingModeCustomIP) toInternal() (m dnsmsg.BlockingMode, err error) {
	custom := &dnsmsg.BlockingModeCustomIP{}

	// TODO(a.garipov): Only one IPv4 address is supported on protobuf side.
	var ipv4Addr netip.Addr
	err = ipv4Addr.UnmarshalBinary(pbm.Ipv4)
	if err != nil {
		return nil, fmt.Errorf("bad custom ipv4: %w", err)
	} else if ipv4Addr.IsValid() {
		custom.IPv4 = []netip.Addr{ipv4Addr}
	}

	// TODO(a.garipov): Only one IPv6 address is supported on protobuf side.
	var ipv6Addr netip.Addr
	err = ipv6Addr.UnmarshalBinary(pbm.Ipv6)
	if err != nil {
		return nil, fmt.Errorf("bad custom ipv6: %w", err)
	} else if ipv6Addr.IsValid() {
		custom.IPv6 = []netip.Addr{ipv6Addr}
	}

	if len(custom.IPv4)+len(custom.IPv6) == 0 {
		return nil, errors.Error("no valid custom ips found")
	}

	return custom, nil
}

// blockingModeToInternal converts a protobuf blocking-mode sum-type to an
// internal one.  If pbm is nil, blockingModeToInternal returns a null-IP
// blocking mode.
func blockingModeToInternal(pbm isDNSProfile_BlockingMode) (m dnsmsg.BlockingMode, err error) {
	switch pbm := pbm.(type) {
	case nil:
		return &dnsmsg.BlockingModeNullIP{}, nil
	case *DNSProfile_BlockingModeCustomIp:
		return pbm.BlockingModeCustomIp.toInternal()
	case *DNSProfile_BlockingModeNxdomain:
		return &dnsmsg.BlockingModeNXDOMAIN{}, nil
	case *DNSProfile_BlockingModeNullIp:
		return &dnsmsg.BlockingModeNullIP{}, nil
	case *DNSProfile_BlockingModeRefused:
		return &dnsmsg.BlockingModeREFUSED{}, nil
	default:
		// Consider unhandled type-switch cases programmer errors.
		return nil, fmt.Errorf("bad pb blocking mode %T(%[1]v)", pbm)
	}
}

// rulesToInternal is a helper that converts the filter rules from the backend
// response to AdGuard DNS filtering rules.
func rulesToInternal(
	ctx context.Context,
	respRules []string,
	errColl errcoll.Interface,
	logger *slog.Logger,
) (rules []filter.RuleText) {
	l := len(respRules)
	if l == 0 {
		return nil
	}

	rules = make([]filter.RuleText, 0, l)
	for i, r := range respRules {
		text, err := filter.NewRuleText(r)
		if err != nil {
			err = fmt.Errorf("at index %d: %w", i, err)
			errcoll.Collect(ctx, errColl, logger, "converting rules", err)

			continue
		}

		rules = append(rules, text)
	}

	return rules
}

// toInternal is a helper that converts the filter lists from the backend
// response to AdGuard DNS rule-list configuration.  If x is nil, toInternal
// returns a disabled configuration.
func (x *RuleListsSettings) toInternal(
	ctx context.Context,
	errColl errcoll.Interface,
	logger *slog.Logger,
) (c *filter.ConfigRuleList) {
	c = &filter.ConfigRuleList{}
	if x == nil {
		return c
	}

	c.Enabled = x.Enabled
	c.IDs = make([]filter.ID, 0, len(x.Ids))

	for i, idStr := range x.Ids {
		id, err := filter.NewID(idStr)
		if err != nil {
			err = fmt.Errorf("at index %d: %w", i, err)
			errcoll.Collect(ctx, errColl, logger, "converting filter id", err)

			continue
		}

		c.IDs = append(c.IDs, id)
	}

	return c
}
