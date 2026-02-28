// Package filterstorage defines an interface for a storage of filters as well
// as the default implementation and the filter configuration.
package filterstorage

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
)

// Additional synthetic filter IDs for refreshable indexes.
//
// TODO(a.garipov):  Consider using a separate type.
const (
	FilterIDBlockedServiceIndex   filter.ID = "blocked_service_index"
	FilterIDCategoryDomainsIndex  filter.ID = "category_domains_index"
	FilterIDStandardProfileAccess filter.ID = "standard_profile_access"
)

// Filenames for filter indexes.
const (
	indexFileNameBlockedServices       = "services.json"
	indexFileNameCategoryDomains       = "category_filters.json"
	indexFileNameStandardProfileAccess = "standard_profile_access.json"
)

// cachePrefixSafeSearch is used as a cache prefix for safe-search filters.
const cachePrefixSafeSearch = "filters/safe_search"
