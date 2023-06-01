# Example values.yaml configurations

The YAML files in this directory provide basic example configurations for
common Kong deployment scenarios on Kubernetes.

* [minimal-kong-controller.yaml](minimal-kong-controller.yaml) installs Kong
  open source with the ingress controller in DB-less mode.

* [minimal-kong-standalone.yaml](minimal-kong-standalone.yaml) installs Kong
  open source and Postgres with no controller.

* [minimal-kong-enterprise-dbless.yaml](minimal-kong-enterprise-dbless.yaml)
  installs Kong for Kubernetes with Kong Enterprise with the ingress controller
  in DB-less mode.

* [minimal-k4k8s-with-kong-enterprise.yaml](minimal-k4k8s-with-kong-enterprise.yaml)
  installs Kong for Kubernetes with Kong Enterprise with the ingress controller
  and PostgreSQL. It does not enable Enterprise features other than Kong
  Manager, and does not expose it or the Admin API via a TLS-secured ingress.

* [full-k4k8s-with-kong-enterprise.yaml](full-k4k8s-with-kong-enterprise.yaml)
  installs Kong for Kubernetes with Kong Enterprise with the ingress controller
  in PostgreSQL. It enables all Enterprise services.

* [minimal-kong-hybrid-control.yaml](minimal-kong-hybrid-control.yaml) and
  [minimal-kong-hybrid-data.yaml](minimal-kong-hybrid-data.yaml) install
  separate releases for hybrid mode control and data plane nodes, using the
  built-in PostgreSQL chart on the control plane release. They require some
  pre-work to [create certificates](https://github.com/Kong/charts/blob/main/charts/kong/README.md#certificates)
  and configure the control plane location. See comments in the file headers
  for additional details.

  Note that you should install the control plane release first if possible:
  data planes must be able to talk with a control plane node before they can
  come online. Starting control planes first is not strictly required (data
  plane nodes will retry their connection for a while before Kubernetes
  restarts them, so starting control planes second, but around the same time
  will usually work), but is the smoothest option.

* [minimal-kong-enterprise-hybrid-control.yaml](minimal-kong-enterprise-hybrid-control.yaml) and
  [minimal-kong-enterprise-hybrid-data.yaml](minimal-kong-enterprise-hybrid-data.yaml) install
  separate releases of Kong Enterprise for hybrid mode control and data plane nodes, using the
  built-in PostgreSQL chart on the control plane release. They require some
  pre-work to [create certificates](https://github.com/Kong/charts/blob/main/charts/kong/README.md#certificates)
  and configure the control plane location. See comments in the file headers
  for additional details.

  Note that you should install the control plane release first if possible:
  data planes must be able to talk with a control plane node before they can
  come online. Starting control planes first is not strictly required (data
  plane nodes will retry their connection for a while before Kubernetes
  restarts them, so starting control planes second, but around the same time
  will usually work), but is the smoothest option.

* [minimal-kong-gd-controller.yaml](minimal-kong-gd-controller.yaml) and
  [minimal-kong-gd-gateway.yaml](minimal-kong-gd-gateway.yaml) install a
  single controller and cluster of gateway instances. The controller release
  configuration must specify the names of the gateway proxy and admin
  Services. The examples use `gw` as the gateway release name. If you wish to
  use another name, set the controller configuration to match. For example, if
  you use `hydrogen` as your gateway release name, set
  `proxy.nameOverride=hydrogen-kong-proxy` and
  `ingressController.adminApiService.name=hydrogen-kong-admin`.

* [minimal-kong-gd-controller-konnect.yaml](minimal-kong-gd-controller-konnect.yaml) and
  [minimal-kong-gd-gateway.yaml](minimal-kong-gd-gateway.yaml) install a single Ingress
  Controller with Kong's Konnect sync feature enabled and a cluster of gateway instances.
  In order to make it work, `ingressController.konnect.runtimeGroupID` has to be
  supplied and a `konnect-client-tls` secret has to be created upfront.

All Enterprise examples require some level of additional user configuration to
install properly. Read the comments at the top of each file for instructions.
