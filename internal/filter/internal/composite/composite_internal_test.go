package composite

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/urlfilter"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func BenchmarkFilter_FilterReqWithRuleLists(b *testing.B) {
	blockingRL := rulelist.NewFromString(
		filtertest.RuleBlockStr+"\n",
		"test",
		"",
		rulelist.EmptyResultCache{},
	)

	f := New(&Config{
		URLFilterRequest: &urlfilter.DNSRequest{},
		URLFilterResult:  &urlfilter.DNSResult{},
		RuleLists:        []*rulelist.Refreshable{blockingRL},
	})

	ctx := context.Background()
	req := filtertest.NewRequest(b, "", filtertest.HostBlocked, filtertest.IPv4Client, dns.TypeA)

	var res filter.Result

	b.ReportAllocs()
	for b.Loop() {
		res, _ = f.filterReqWithRuleLists(ctx, req)
	}

	assert.NotNil(b, res)

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/composite
	//	cpu: Apple M3
	//  BenchmarkFilter_FilterReqWithRuleLists-8   	 1880119	       634.6 ns/op	     519 B/op	       9 allocs/op
}
