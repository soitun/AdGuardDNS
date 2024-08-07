 #  AdGuard DNS External HTTP API Requirements

AdGuard DNS uses information from external HTTP APIs for filtering and other
pieces of its functionality.  Whenever it makes requests to these services,
AdGuard DNS sets the `User-Agent` header.  All services described in this
document should set the `Server` header in their replies.

<!--
    TODO(a.garipov): Reinspect uses of “should” and “must” throughout this
    document.
-->



##  Contents

 *  [Backend Billing Statistics](#backend-billstat)
 *  [Backend Profiles Service](#backend-profiles)
 *  [Consul Key-Value Storage](#consul)
 *  [Filtering](#filters)
     *  [Blocked Services](#filters-blocked-services)
     *  [Filtering Rule Lists](#filters-lists)
     *  [Safe Search](#filters-safe-search)
 *  [Proxied Linked IP and Dynamic DNS (DDNS) Endpoints](#backend-linkip)
 *  [Rule Statistics Service](#rulestat)



##  <a href="#backend-billstat" id="backend-billstat" name="backend-billstat">Backend Billing Statistics</a>

This is the service to which the [`BILLSTAT_URL`][env-billstat_url] environment
variable points.  Supports `grpc(s)` URLs.  The service must correspond to
`./internal/backendpb/backend.proto`.  This service can be disabled with the
[`PROFILES_ENABLED`][env-profiles_enabled] environment variable.

[env-billstat_url]: environment.md#BILLSTAT_URL
[env-profiles_enabled]: environment.md#PROFILES_ENABLED



##  <a href="#backend-profiles" id="backend-profiles" name="backend-profiles">Backend Profiles Service</a>

This is the service to which the [`PROFILES_URL`][env-profiles_url] environment
variable points.  Supports `grpc(s)` URLs.  The service must correspond to
`./internal/backendpb/backend.proto`.  This service can be disabled with the
[`PROFILES_ENABLED`][env-profiles_enabled] environment variable.

[env-profiles_url]: environment.md#PROFILES_URL



##  <a href="#consul" id="consul" name="consul">Consul Key-Value Storage</a>

A [Consul][consul-io] service can be used for the DNS server check and dynamic
rate-limit allowlist features.  Currently used endpoints can be seen in the
documentation of the [`CONSUL_ALLOWLIST_URL`][env-consul-allowlist],
[`CONSUL_DNSCHECK_KV_URL`][env-consul-dnscheck-kv], and
[`CONSUL_DNSCHECK_SESSION_URL`][env-consul-dnscheck-session] environment
variables.

The `CONSUL_ALLOWLIST_URL` endpoint must respond with a `200 OK` response code
and a JSON document in the following format:

```json
[
  {
    "Address": "1.2.3.4"
  }
]
```

**TODO(a.garipov):** Add examples of other responses.

[consul-io]:                   https://www.consul.io/
[env-consul-allowlist]:        environment.md#CONSUL_ALLOWLIST_URL
[env-consul-dnscheck-kv]:      environment.md#CONSUL_DNSCHECK_KV_URL
[env-consul-dnscheck-session]: environment.md#CONSUL_DNSCHECK_SESSION_URL



##  <a href="#filters" id="filters" name="filters">Filtering</a>

   ###  <a href="#filters-blocked-services" id="filters-blocked-services" name="filters-blocked-services">Blocked Services</a>

This endpoint, defined by [`BLOCKED_SERVICE_INDEX_URL`][env-services], must
respond with a `200 OK` response code and a JSON document in the following
format:

```json
{
  "blocked_services": [
    {
      "id": "my_filter",
      "rules": [
        "||example.com^",
        "||example.net^"
      ]
    }
  ]
}
```

All properties must be filled with valid IDs and rules.  Additional fields in
objects are ignored.



   ###  <a href="#filters-lists" id="filters-lists" name="filters-lists">Filtering Rule Lists</a>

This endpoint, defined by [`FILTER_INDEX_URL`][env-filters], must respond with a
`200 OK` response code and a JSON document in the following format:

```json
{
  "filters": [
    {
      "filterKey": "my_filter",
      "downloadUrl": "https://cdn.example.com/assets/my_filter.txt"
    }
  ]
}
```

All properties must be filled with valid IDs and URLs.  Additional fields in
objects are ignored.



   ###  <a href="#filters-safe-search" id="filters-safe-search" name="filters-safe-search">Safe Search</a>

These endpoints, defined by [`GENERAL_SAFE_SEARCH_URL`][env-general] and
[`YOUTUBE_SAFE_SEARCH_URL`][env-youtube], must respond with a `200 OK` response
code and filtering rule lists with [`$dnsrewrite`][rules-dnsrewrite] rules for
`A`, `AAAA`, or `CNAME` types.  For example, for YouTube:

```none
|m.youtube.com^$dnsrewrite=NOERROR;CNAME;restrictmoderate.youtube.com
|www.youtube-nocookie.com^$dnsrewrite=NOERROR;CNAME;restrictmoderate.youtube.com
|www.youtube.com^$dnsrewrite=NOERROR;CNAME;restrictmoderate.youtube.com
|youtube.googleapis.com^$dnsrewrite=NOERROR;CNAME;restrictmoderate.youtube.com
|youtubei.googleapis.com^$dnsrewrite=NOERROR;CNAME;restrictmoderate.youtube.com
```

[env-filters]:  environment.md#FILTER_INDEX_URL
[env-general]:  environment.md#GENERAL_SAFE_SEARCH_URL
[env-services]: environment.md#BLOCKED_SERVICE_INDEX_URL
[env-youtube]:  environment.md#YOUTUBE_SAFE_SEARCH_URL

<!--
    TODO(a.garipov): Replace with a link to the new KB when it is finished.
-->
[rules-dnsrewrite]: https://github.com/AdguardTeam/AdGuardHome/wiki/Hosts-Blocklists#dnsrewrite



##  <a href="#backend-linkip" id="backend-linkip" name="backend-linkip">Proxied Linked IP and Dynamic DNS (DDNS) Endpoints</a>

The service defined by the [`LINKED_IP_TARGET_URL`][env-linked_ip_target_url]
environment variable should define the following endpoints:

 *  `GET  /linkip/{device_id}/{encrypted}/status`;
 *  `GET  /linkip/{device_id}/{encrypted}`;
 *  `POST /ddns/{device_id}/{encrypted}/{domain}`;
 *  `POST /linkip/{device_id}/{encrypted}`.

The AdGuard DNS proxy will add the `CF-Connecting-IP` header with the IP address
of the original client as well as set the `User-Agent` header to its own value.

[env-linked_ip_target_url]: environment.md#LINKED_IP_TARGET_URL



##  <a href="#rulestat" id="rulestat" name="rulestat">Rule Statistics Service</a>

This endpoint, defined by [`RULESTAT_URL`][env-rulestat], must respond with a
`200 OK` response code and accept a JSON document in the following format:

```json
{
  "filters": [
    {
      "15": {
        "||example.com^": 1234,
        "||example.net^": 5678
      }
    }
  ]
}
```

The objects may include new properties in the future.

[env-rulestat]: environment.md#RULESTAT_URL
