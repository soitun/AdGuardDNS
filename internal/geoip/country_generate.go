//go:build generate

package main

import (
	"context"
	"encoding/csv"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
)

func main() {
	ctx := context.Background()
	logger := slogutil.New(nil)
	defer slogutil.RecoverAndExit(ctx, logger, osutil.ExitCodeFailure)

	c := &http.Client{
		Timeout: 10 * time.Second,
	}

	req := errors.Must(http.NewRequest(http.MethodGet, csvURL, nil))

	req.Header.Add(httphdr.UserAgent, agdhttp.UserAgent())

	resp := errors.Must(c.Do(req))
	defer slogutil.CloseAndLog(ctx, logger, resp.Body, slog.LevelError)

	out := errors.Must(os.OpenFile("./country.go", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o664))
	defer slogutil.CloseAndLog(ctx, logger, out, slog.LevelError)

	r := csv.NewReader(resp.Body)
	rows := errors.Must(r.ReadAll())

	// Skip the first row, as it is a header.
	rows = rows[1:]

	slices.SortFunc(rows, func(a, b []string) (res int) {
		// Sort by the code to make the output more predictable and easier to
		// look through.
		return strings.Compare(a[1], b[1])
	})

	tmpl := template.Must(template.New("main").Parse(tmplStr))

	err := tmpl.Execute(out, rows)
	errors.Check(err)
}

// csvURL is the default URL of the information about country codes.
const csvURL = `https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/master/slim-2/slim-2.csv`

// tmplStr is the template of the generated Go code.
const tmplStr = `// Code generated by go run ./country_generate.go; DO NOT EDIT.

package geoip

import (
	"encoding"
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
)

// Country represents an ISO 3166-1 alpha-2 country code.
type Country string

// Country code constants.  Note that these constants don't include the
// user-assigned ones.
const (
	// CountryNone is an invalid or unknown country code.
	CountryNone Country = ""

	// CountryNotApplicable is the user-assigned ISO 3166-1 alpha-2 code used
	// when a country of origin cannot be determined due to a lack of
	// information, for example a response of the record type that doesn't
	// contain an IP address.
	CountryNotApplicable Country = "QN"

	// CountryXK is the user-assigned ISO 3166-1 alpha-2 code for Republic of
	// Kosovo.  Kosovo does not have a recognized ISO 3166 code, but it is still
	// an entity whose user-assigned code is relatively common.
	CountryXK Country = "XK"
{{ range . }}
	{{ $name := (index . 0) -}}
	{{ $code := (index . 1) -}}
	// Country{{ $code }} is the ISO 3166-1 alpha-2 code for
	// {{ $name }}.
	Country{{ $code }} Country = {{ printf "%q" $code }}
{{- end }}
)

// NewCountry converts s into a Country while also validating it.  Prefer to use
// this instead of a plain conversion.
func NewCountry(s string) (c Country, err error) {
	c = Country(s)
	if isUserAssigned(s) {
		return c, nil
	}

	switch c {
	case
		{{ range . -}}
		{{ $code := (index . 1) -}}
		Country{{ $code }},
		{{ end -}}
		CountryNone:
		return c, nil
	default:
		return CountryNone, &NotACountryError{Code: s}
	}
}

// type check
var _ encoding.TextUnmarshaler = (*Country)(nil)

// UnmarshalText implements the encoding.TextUnmarshaler interface for *Country.
func (c *Country) UnmarshalText(b []byte) (err error) {
	if c == nil {
		return errors.Error("nil country")
	}

	ctry, err := NewCountry(string(b))
	if err != nil {
		return fmt.Errorf("decoding country: %w", err)
	}

	*c = ctry

	return nil
}

// isUserAssigned returns true if s is a user-assigned ISO 3166-1 alpha-2
// country code.
func isUserAssigned(s string) (ok bool) {
	if len(s) != 2 {
		return false
	}

	if s[0] == 'X' || (s[0] == 'Q' && s[1] >= 'M') {
		return true
	}

	switch s {
	case "AA", "OO", "ZZ":
		return true
	default:
		return false
	}
}
`
