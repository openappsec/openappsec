# components/utils/ Subsystems

Per-subsystem detail. Each entry: what it does, when to reach for it, the public
header(s) to include, the main types, and whether it's a Singleton service or a
plain header helper (which decides how you test it -- see
[README -> Mockability](README.md#mockability----read-this-before-writing-tests)).

Public interface headers live in `components/include/`; implementation lives
under `components/utils/<name>/`.

---

## Singleton-backed services

These sit behind an `I_*` interface; consume with
`Singleton::Consume<I_X>::by<Self>()`.

### generic_rulebase
**What:** Policy engine -- parses the rulebase (zones, triggers, parameters) and
matches rules against the active context at runtime.
**Reach for it when:** you need to query security policy rules, get a zone
(local vs remote), fetch the log trigger for an event, or evaluate a behavioral
parameter by key/value.
**Include:** `i_generic_rulebase.h`, `i_generic_l4_policy.h`,
`generic_rulebase/zone.h`, `generic_rulebase/parameters_config.h`.
**Types:** `I_GenericRulebase` (`i_generic_rulebase.h:24`), `GenericRulebase`
(provides it; consumes `I_Intelligence_IS_V2`).
**Mock:** none shipped.

### geo_location
**What:** GeoIP lookups via the MaxMind GeoIP2 DB (IP -> country/continent
code + name).
**Reach for it when:** you need the geographic origin of an IP for geo-filtering,
access control, or telemetry enrichment.
**Include:** `i_geo_location.h` (interface), `geo_location.h` (component).
**Types:** `I_GeoLocation`, `GeoLocation` (provides it).
**Mock:** **`mock_geo_location.h`** -> `MockGeoLocation`.

### nsaas
**What:** Network-Security-as-a-Service tenant broker -- maps tenant id /
profile to the resolved endpoint config and policy.
**Reach for it when:** you need to resolve which tenant/profile pair applies to
an endpoint, or query tenant<->profile associations.
**Include:** `i_nsaas.h` (interface), `nsaas.h` (component).
**Types:** `I_NSaaS`, `NetworkSecurityAsAService` (provides it; consumes
`I_Ioctl`, `I_MainLoop`, `I_Intelligence_IS_V2`, `I_TenantManager`,
`I_Environment`, `I_AccessControlPolicyLoader`, `I_TimeGet`).
**Mock:** **`mock/mock_nsaas.h`** -> `MockNSaaS`.

### keywords
**What:** Suricata-style keyword rule engine -- compiles and executes chained
keyword conditions (byte extract, compare, jump, PCRE, length, stateop).
**Reach for it when:** you need to compile and run Suricata-compatible IDS rules
with stateful keyword chains.
**Include:** `i_keywords_rule.h` (interface), `keyword_comp.h` (component).
**Types:** `I_KeywordsRule` (`i_keywords_rule.h:9`, with a `VirtualRule`
sub-interface for runtime matching), `KeywordComp` (provides it; consumes
`I_Table`, `I_Environment`), `SingleKeyword` base + `DataKeyword`, `PCREKeyword`,
`LengthKeyword`, `ByteExtractKeyword`, `CompareKeyword`, `StateopKeyword`,
`JumpKeyword`, `NoMatchKeyword`.
**Mock:** none shipped (mock the `I_KeywordsRule::VirtualRule` if needed).

### service_health_status
**What:** Aggregates component health errors and exposes overall service health
over REST.
**Reach for it when:** you need to report a component-level health problem or
expose/query overall service status.
**Include:** `service_health_status.h`.
**Types:** `ServiceHealthStatus` (consumes `I_RestApi`, `I_Environment`;
registers a REST handler).
**Mock:** none shipped.

### kdebug
**What:** Loads kernel debug flags / log levels from JSON into the kernel debug
arrays.
**Reach for it when:** you need to set or read kernel-level debug output config.
**Include:** `kdebug_cfg.h`.
**Types:** `KDebugCfg` (consumes `I_RestApi`, `I_Ioctl`), `KernelDebugConfig`
(the JSON parser, `kdebug/kernel_debug_config.h`).
**Mock:** none shipped.

---

## Header-only helpers (no interface, no mock -- test directly)

### pm (Pattern Matcher)
**What:** KISS Thin-NFA multi-pattern matching engine (with Hyperscan hooks);
full regex with match-offset reporting.
**Reach for it when:** you need to scan a buffer for many patterns at once and
get positions, or compile/run complex regex rules fast.
**Include:** `i_pm_scan.h`, `pm_hook.h`.
**Types:** `I_PMScan` (`i_pm_scan.h:58`), `PMPattern` (`i_pm_scan.h:26`), `PMHook`
(concrete impl, `pm_hook.h:26`), internal `KissThinNFA`.
**Test:** drive `PMHook` directly with patterns + input buffers.

### http_transaction_data
**What:** Container for parsed HTTP request/response metadata (method, host, URI,
client/listening IP:port, compression, WAF tags). Cereal-serializable.
**Reach for it when:** you need the parsed transaction context for logging,
policy evaluation, or telemetry without re-parsing headers.
**Include:** `http_transaction_data.h`, `http_transaction_common.h`.
**Types:** `HttpTransactionData` (`http_transaction_data.h:30`).
**Test:** construct and assert directly.

### ip_utilities
**What:** IPv4/IPv6 parsing, CIDR-to-range expansion, in-range membership, local
interface IP enumeration.
**Reach for it when:** you need to parse/validate IP ranges, test membership, or
list local IPs.
**Include:** `ip_utilities.h`.
**Types:** `IPUtilities::getInterfaceIPs() / createRangeFromCidr() /
isIpAddrInRange()`, `IpAttrFromString` (`ip_utilities.h:62`).
**Test:** call the functions directly.

### checksum
**What:** TCP/RFC-793 16-bit checksum computation and validation.
**Reach for it when:** you need to compute or validate TCP checksums for packet
synthesis or packet-level validation.
**Include:** `TCPCheckSum.h`.
**Types:** `CheckSum::cksumBuf() / cksumTcpPkt() / validTcpCksum()` (namespace,
`TCPCheckSum.h:6`).
**Test:** call directly with known vectors.

### socket_stream
**What:** C++ `iostream`-compatible socket wrapper with buffering.
**Reach for it when:** you want `<<` / `>>` semantics over a socket.
**Include:** `socketstream.h`.
**Types:** `SocketBuf` (`socketstream.h:18`), `SocketStream` (`:44`),
`connectSocket()`, `listenSocket()`.
**Test:** use a loopback/pair socket directly.

### nginx_utils / utilities
**What:** nginx config-file manipulation -- expand `include` globs, merge
hierarchies, validate syntax, reload nginx. `utilities/` holds related helpers
(`nginx_conf_collector`, `FogConnection`).
**Reach for it when:** you need to merge + validate nginx configs or reload the
daemon.
**Include:** `nginx_utils.h`.
**Types:** `NginxConfCollector` (`nginx_utils.h:23`), `NginxUtils` (`:42`,
`Singleton::Consume<I_ShellCmd>` for the reload call -- not a pure-static class,
but it Provides nothing so there's no interface to mock).
**Test:** run against fixture config files directly.

---

## At a glance

| Subsystem | Pattern | Interface header | Mock |
|-----------|---------|------------------|------|
| generic_rulebase | Singleton service | `i_generic_rulebase.h` | -- |
| geo_location | Singleton service | `i_geo_location.h` | `mock_geo_location.h` |
| nsaas | Singleton service | `i_nsaas.h` | `mock/mock_nsaas.h` |
| keywords | Singleton service | `keyword_comp.h` / `i_keywords_rule.h` | -- |
| service_health_status | Singleton (consumer) | `service_health_status.h` | -- |
| kdebug | Singleton (consumer) | `kdebug_cfg.h` | -- |
| pm | header helper | `pm_hook.h` / `i_pm_scan.h` | -- |
| http_transaction_data | data class | `http_transaction_data.h` | -- |
| ip_utilities | header helper | `ip_utilities.h` | -- |
| checksum | header helper | `TCPCheckSum.h` | -- |
| socket_stream | header helper | `socketstream.h` | -- |
| nginx_utils | static helper | `nginx_utils.h` | -- |
