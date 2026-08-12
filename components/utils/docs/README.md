# components/utils/ Documentation

`components/utils/` is a collection of independent utility subsystems used across
the WAAP/agent components. Unlike `core/` (one coherent runtime framework), this
is a grab-bag: some entries are full Singleton-backed services (GeoLocation,
NSaaS, GenericRulebase, KeywordComp), others are plain header-only helpers
(checksum, IP utilities, socket stream, HTTP transaction data).

These docs are **task-oriented**: find your need below, use the subsystem it
points to, read [subsystems.md](subsystems.md) for the API detail.

## "I need to..." -> which util

| When you need to... | Use | Mockable? |
|---------------------|-----|-----------|
| Query security policy rules / zones / log triggers / behavioral parameters | `I_GenericRulebase` (`i_generic_rulebase.h`) | service, no mock shipped |
| Resolve an IP to a country/continent (GeoIP) | `I_GeoLocation` (`i_geo_location.h`) | **yes** -- `mock_geo_location.h` |
| Resolve which tenant/profile applies to an endpoint (NSaaS) | `I_NSaaS` (`i_nsaas.h`) | **yes** -- `mock/mock_nsaas.h` |
| Compile/run Suricata-style keyword (IDS) rules | `I_KeywordsRule` (`keyword_comp.h`) | service, no mock shipped |
| Scan a buffer for many patterns at once (regex/NFA) | `I_PMScan` / `PMHook` (`pm_hook.h`) | header, test directly |
| Hold/access parsed HTTP request/response metadata | `HttpTransactionData` (`http_transaction_data.h`) | data class, test directly |
| Work with IP ranges / CIDR / membership / local IPs | `IPUtilities` (`ip_utilities.h`) | header, test directly |
| Compute/validate TCP checksums | `CheckSum` (`TCPCheckSum.h`) | header, test directly |
| Read/write a socket with C++ stream semantics | `SocketStream` (`socketstream.h`) | header, test directly |
| Merge/validate/reload nginx config files | `NginxUtils` / `NginxConfCollector` (`nginx_utils.h`) | static helper, test directly |
| Report component health / expose health REST status | `ServiceHealthStatus` (`service_health_status.h`) | service (consumes I_RestApi) |
| Configure kernel debug flags from JSON | `KDebugCfg` (`kdebug_cfg.h`) | service (consumes I_RestApi, I_Ioctl) |

## Mockability -- read this before writing tests

Most of `components/utils/` is **not meant to be mocked**, and only two ship a
GoogleMock double. The split follows the design:

- **Singleton-backed services** are the mockable ones in principle (they sit
  behind an `I_*` interface that `Consume`rs look up). Of these, only two have a
  shipped mock today:
  - `MockGeoLocation` -- `components/include/mock_geo_location.h`
  - `MockNSaaS` -- `components/include/mock/mock_nsaas.h`

  `GenericRulebase`, `KeywordComp`, `ServiceHealthStatus`, `KDebugCfg` are
  Singleton services with **no** shipped mock. If a test needs one, the
  convention is to bring up the real component (it's self-contained) or add a
  mock following the `Provide<I_X>::From<MockProvider<I_X>>` pattern from
  `core/`'s mocks -- see
  [core/docs interfaces-and-resources -> Testing with mocks](../../../core/docs/interfaces-and-resources.md#testing-with-mocks).

- **Header-only helpers** (`CheckSum`, `IPUtilities`, `HttpTransactionData`,
  `SocketStream`, `PMHook`, `NginxUtils`) have **no interface and no mock by
  design** -- they're pure functions / value types with no external
  dependencies. Don't mock them: call them directly in the test with real
  inputs and assert on the output. Mocking a checksum or a CIDR check would test
  nothing.

So: "is there a mock?" is the wrong first question here. Ask "is this a service
or a helper?" -- helpers are tested directly; services are tested by standing up
the component (and only GeoLocation/NSaaS give you a ready double).

## Reference

| Doc | Covers |
|-----|--------|
| [subsystems.md](subsystems.md) | Per-subsystem detail: what it does, when to reach for it, the public header(s), the main classes, and the Singleton-vs-header pattern. |
