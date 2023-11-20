## Kong for Kubernetes

[Kong for Kubernetes](https://github.com/Kong/kubernetes-ingress-controller)
is an open-source Ingress Controller for Kubernetes that offers
API management capabilities with a plugin architecture.

This chart bootstraps all the components needed to run Kong on a
[Kubernetes](http://kubernetes.io) cluster using the
[Helm](https://helm.sh) package manager.

## TL;DR;

```bash
helm repo add kong https://charts.konghq.com
helm repo update

helm install kong/kong --generate-name
```

## Table of contents

- [Prerequisites](#prerequisites)
- [Install](#install)
- [Uninstall](#uninstall)
- [FAQs](#faqs)
- [Kong Enterprise](#kong-enterprise)
- [Deployment Options](#deployment-options)
  - [Database](#database)
    - [DB-less deployment](#db-less-deployment)
    - [Using the Postgres sub-chart](#using-the-postgres-sub-chart)
      - [Postgres sub-chart considerations for OpenShift](#postgres-sub-chart-considerations-for-openshift)
  - [Runtime package](#runtime-package)
  - [Configuration method](#configuration-method)
  - [Separate admin and proxy nodes](#separate-admin-and-proxy-nodes)
  - [Standalone controller nodes](#standalone-controller-nodes)
  - [Hybrid mode](#hybrid-mode)
    - [Certificates](#certificates)
    - [Control plane node configuration](#control-plane-node-configuration)
    - [Data plane node configuration](#data-plane-node-configuration)
  - [Cert Manager Integration](#cert-manager-integration)
  - [CRD management](#crd-management)
  - [InitContainers](#initcontainers)
  - [HostAliases](#hostaliases)
  - [Sidecar Containers](#sidecar-containers)
  - [Migration Sidecar Containers](#migration-sidecar-containers)
  - [User Defined Volumes](#user-defined-volumes)
  - [User Defined Volume Mounts](#user-defined-volume-mounts)
  - [Removing cluster-scoped permissions](#removing-cluster-scoped-permissions)
  - [Using a DaemonSet](#using-a-daemonset)
  - [Using dnsPolicy and dnsConfig](#using-dnspolicy-and-dnsconfig)
  - [Example configurations](#example-configurations)
- [Configuration](#configuration)
  - [Kong parameters](#kong-parameters)
    - [Kong Service Parameters](#kong-service-parameters)
    - [Admin Service mTLS](#admin-service-mtls)
    - [Stream listens](#stream-listens)
  - [Ingress Controller Parameters](#ingress-controller-parameters)
    - [The `env` section](#the-env-section)
    - [The `customEnv` section](#the-customenv-section)
  - [General Parameters](#general-parameters)
    - [The `env` section](#the-env-section-1)
    - [The `customEnv` section](#the-customenv-section-1)
    - [The `extraLabels` section](#the-extralabels-section)
- [Kong Enterprise Parameters](#kong-enterprise-parameters)
  - [Overview](#overview)
  - [Prerequisites](#prerequisites-1)
    - [Kong Enterprise License](#kong-enterprise-license)
    - [Kong Enterprise Docker registry access](#kong-enterprise-docker-registry-access)
  - [Service location hints](#service-location-hints)
  - [RBAC](#rbac)
  - [Sessions](#sessions)
  - [Email/SMTP](#emailsmtp)
- [Prometheus Operator integration](#prometheus-operator-integration)
- [Argo CD considerations](#argo-cd-considerations)
- [Changelog](https://github.com/Kong/charts/blob/main/charts/kong/CHANGELOG.md)
- [Upgrading](https://github.com/Kong/charts/blob/main/charts/kong/UPGRADE.md)
- [Seeking help](#seeking-help)

## Prerequisites

- Kubernetes 1.17+. Older chart releases support older Kubernetes versions.
  Refer to the [supported version matrix](https://docs.konghq.com/kubernetes-ingress-controller/latest/references/version-compatibility/#kubernetes)
  and the [chart changelog](https://github.com/Kong/charts/blob/main/charts/kong/CHANGELOG.md)
  for information about the default chart controller versions and Kubernetes
  versions supported by controller releases.
- PV provisioner support in the underlying infrastructure if persistence
  is needed for Kong datastore.

## Install

To install Kong:

```bash
helm repo add kong https://charts.konghq.com
helm repo update

helm install kong/kong --generate-name
```

## Uninstall

To uninstall/delete a Helm release `my-release`:

```bash
helm delete my-release
```

The command removes all the Kubernetes components associated with the
chart and deletes the release.

> **Tip**: List all releases using `helm list`

## FAQs

Please read the
[FAQs](https://github.com/Kong/charts/blob/main/charts/kong/FAQs.md)
document.

## Kong Enterprise

If using Kong Enterprise, several additional steps are necessary before
installing the chart:

- Set `enterprise.enabled` to `true` in `values.yaml` file.
- Update values.yaml to use a Kong Enterprise image.
- Satisfy the two prerequisites below for
  [Enterprise License](#kong-enterprise-license) and
  [Enterprise Docker Registry](#kong-enterprise-docker-registry-access).
- (Optional) [set a `password` environment variable](#rbac) to create the
  initial super-admin. Though not required, this is recommended for users that
  wish to use RBAC, as it cannot be done after initial setup.

Once you have these set, it is possible to install Kong Enterprise.

Please read through
[Kong Enterprise considerations](#kong-enterprise-parameters)
to understand all settings that are enterprise specific.

## Deployment Options

Kong is a highly configurable piece of software that can be deployed
in a number of different ways, depending on your use-case.

All combinations of various runtimes, databases and configuration methods are
supported by this Helm chart.
The recommended approach is to use the Ingress Controller based configuration
along-with DB-less mode.

Following sections detail on various high-level architecture options available:

### Database

Kong can run with or without a database (DB-less). By default, this chart
installs Kong without a database.

You can set the database the `env.database` parameter. For more details, please
read the [env](#the-env-section) section.

#### DB-less deployment

When deploying Kong in DB-less mode(`env.database: "off"`)
and without the Ingress Controller(`ingressController.enabled: false`),
you have to provide a [declarative configuration](https://docs.konghq.com/gateway-oss/latest/db-less-and-declarative-config/#the-declarative-configuration-format) for Kong to run.
You can provide an existing ConfigMap
(`dblessConfig.configMap`) or Secret (`dblessConfig.secret`) or place the whole
configuration into `values.yaml` (`dblessConfig.config`) parameter. See the
example configuration in the default values.yaml for more details. You can use
`--set-file dblessConfig.config=/path/to/declarative-config.yaml` in Helm
commands to substitute in a complete declarative config file.

Note that externally supplied ConfigMaps are not hashed or tracked in deployment annotations.
Subsequent ConfigMap updates will require user-initiated new deployment rollouts
to apply the new configuration. You should run `kubectl rollout restart deploy`
after updating externally supplied ConfigMap content.

#### Using the Postgres sub-chart

The chart can optionally spawn a Postgres instance using [Bitnami's Postgres
chart](https://github.com/bitnami/charts/blob/master/bitnami/postgresql/README.md)
as a sub-chart. Set `postgresql.enabled=true` to enable the sub-chart. Enabling
this will auto-populate Postgres connection settings in Kong's environment.

The Postgres sub-chart is best used to quickly provision temporary environments
without installing and configuring your database separately. For longer-lived
environments, we recommend you manage your database outside the Kong Helm
release.

##### Postgres sub-chart considerations for OpenShift

Due to the default `securityContexts` in the postgres sub-chart, you will need to add the following values to the `postgresql` section to get postgres running on OpenShift:

```yaml
  volumePermissions:
    enabled: false
    securityContext:
      runAsUser: "auto"
  primary:
    containerSecurityContext:
      enabled: false
    podSecurityContext:
      enabled: false
```

### Runtime package

There are three different packages of Kong that are available:

- **Kong Gateway**\
  This is the [Open-Source](https://github.com/kong/kong) offering. It is a
  full-blown API Gateway and Ingress solution with a wide-array of functionality.
  When Kong Gateway is combined with the Ingress based configuration method,
  you get Kong for Kubernetes. This is the default deployment for this Helm
  Chart.
- **Kong Enterprise K8S**\
  This package builds up on top of the Open-Source Gateway and bundles in all
  the Enterprise-only plugins as well.
  When Kong Enterprise K8S is combined with the Ingress based
  configuration method, you get Kong for Kubernetes Enterprise.
  This package also comes with 24x7 support from Kong Inc.
- **Kong Enterprise**\
  This is the full-blown Enterprise package which packs with itself all the
  Enterprise functionality like Manager, Portal, Vitals, etc.
  This package can't be run in DB-less mode.

The package to run can be changed via `image.repository` and `image.tag`
parameters. If you would like to run the Enterprise package, please read
the [Kong Enterprise Parameters](#kong-enterprise-parameters) section.

### Configuration method

Kong can be configured via two methods:
- **Ingress and CRDs**\
  The configuration for Kong is done via `kubectl` and Kubernetes-native APIs.
  This is also known as Kong Ingress Controller or Kong for Kubernetes and is
  the default deployment pattern for this Helm Chart. The configuration
  for Kong is managed via Ingress and a few
  [Custom Resources](https://docs.konghq.com/kubernetes-ingress-controller/latest/concepts/custom-resources).
  For more details, please read the
  [documentation](https://docs.konghq.com/kubernetes-ingress-controller/)
  on Kong Ingress Controller.
  To configure and fine-tune the controller, please read the
  [Ingress Controller Parameters](#ingress-controller-parameters) section.
- **Admin API**\
  This is the traditional method of running and configuring Kong.
  By default, the Admin API of Kong is not exposed as a Service. This
  can be controlled via `admin.enabled` and `env.admin_listen` parameters.

### Separate admin and proxy nodes

*Note: although this section is titled "Separate admin and proxy nodes", this
split release technique is generally applicable to any deployment with
different types of Kong nodes. Separating Admin API and proxy nodes is one of
the more common use cases for splitting across multiple releases, but you can
also split releases for split proxy and Developer Portal nodes, multiple groups
of proxy nodes with separate listen configurations for network segmentation, etc.
However, it does not apply to hybrid mode, as only the control plane release
interacts with the database.*

Users may wish to split their Kong deployment into multiple instances that only
run some of Kong's services (i.e. you run `helm install` once for every
instance type you wish to create).

To disable Kong services on an instance, you should set `SVC.enabled`,
`SVC.http.enabled`, `SVC.tls.enabled`, and `SVC.ingress.enabled` all to
`false`, where `SVC` is `proxy`, `admin`, `manager`, `portal`, or `portalapi`.

The standard chart upgrade automation process assumes that there is only a
single Kong release in the Kong cluster, and runs both `migrations up` and
`migrations finish` jobs. To handle clusters split across multiple releases,
you should:
1. Upgrade one of the releases with `helm upgrade RELEASENAME -f values.yaml
   --set migrations.preUpgrade=true --set migrations.postUpgrade=false`.
2. Upgrade all but one of the remaining releases with `helm upgrade RELEASENAME
   -f values.yaml --set migrations.preUpgrade=false --set
   migrations.postUpgrade=false`.
3. Upgrade the final release with `helm upgrade RELEASENAME -f values.yaml
   --set migrations.preUpgrade=false --set migrations.postUpgrade=true`.

This ensures that all instances are using the new Kong package before running
`kong migrations finish`.

Users should note that Helm supports supplying multiple values.yaml files,
allowing you to separate shared configuration from instance-specific
configuration. For example, you may have a shared values.yaml that contains
environment variables and other common settings, and then several
instance-specific values.yamls that contain service configuration only. You can
then create releases with:

```bash
helm install proxy-only -f shared-values.yaml -f only-proxy.yaml kong/kong
helm install admin-only -f shared-values.yaml -f only-admin.yaml kong/kong
```

### Standalone controller nodes

The chart can deploy releases that contain the controller only, with no Kong
container, by setting `deployment.kong.enabled: false` in values.yaml. There
are several controller settings that must be populated manually in this
scenario and several settings that are useful when using multiple controllers:

* `ingressController.env.kong_admin_url` must be set to the Kong Admin API URL.
  If the Admin API is exposed by a service in the cluster, this should look
  something like `https://my-release-kong-admin.kong-namespace.svc:8444`
* `ingressController.env.publish_service` must be set to the Kong proxy
  service, e.g. `namespace/my-release-kong-proxy`.
* `ingressController.ingressClass` should be set to a different value for each
  instance of the controller.
* `ingressController.env.kong_admin_filter_tag` should be set to a different value
  for each instance of the controller.
* If using Kong Enterprise, `ingressController.env.kong_workspace` can
  optionally create configuration in a workspace other than `default`.

Standalone controllers require a database-backed Kong instance, as DB-less mode
requires that a single controller generate a complete Kong configuration.

### Hybrid mode

Kong supports [hybrid mode
deployments](https://docs.konghq.com/2.0.x/hybrid-mode/) as of Kong 2.0.0 and
[Kong Enterprise 2.1.0](https://docs.konghq.com/enterprise/2.1.x/deployment/hybrid-mode/).
These deployments split Kong nodes into control plane (CP) nodes, which provide
the admin API and interact with the database, and data plane (DP) nodes, which
provide the proxy and receive configuration from control plane nodes.

You can deploy hybrid mode Kong clusters by [creating separate releases for each node
type](#separate-admin-and-proxy-nodes), i.e. use separate control and data
plane values.yamls that are then installed separately. The [control
plane](#control-plane-node-configuration) and [data
plane](#data-plane-node-configuration) configuration sections below cover the
values.yaml specifics for each.

Cluster certificates are not generated automatically. You must [create a
certificate and key pair](#certificates) for intra-cluster communication.

When upgrading the Kong version, you must [upgrade the control plane release
first and then upgrade the data plane release](https://docs.konghq.com/gateway/latest/plan-and-deploy/hybrid-mode/#version-compatibility).

#### Certificates

> This example shows how to use Kong Hybrid mode with `cluster_mtls: shared`.
> For an example of `cluster_mtls: pki` see the [hybrid-cert-manager example](https://github.com/Kong/charts/blob/main/charts/kong/example-values/hybrid-cert-manager/)

Hybrid mode uses TLS to secure the CP/DP node communication channel, and
requires certificates for it. You can generate these either using `kong hybrid
gen_cert` on a local Kong installation or using OpenSSL:

```bash
openssl req -new -x509 -nodes -newkey ec:<(openssl ecparam -name secp384r1) \
  -keyout /tmp/cluster.key -out /tmp/cluster.crt \
  -days 1095 -subj "/CN=kong_clustering"
```

You must then place these certificates in a Secret:

```bash
kubectl create secret tls kong-cluster-cert --cert=/tmp/cluster.crt --key=/tmp/cluster.key
```

#### Control plane node configuration

You must configure the control plane nodes to mount the certificate secret on
the container filesystem is serve it from the cluster listen. In values.yaml:

```yaml
secretVolumes:
- kong-cluster-cert
```

```yaml
env:
  role: control_plane
  cluster_cert: /etc/secrets/kong-cluster-cert/tls.crt
  cluster_cert_key: /etc/secrets/kong-cluster-cert/tls.key
```

Furthermore, you must enable the cluster listen and Kubernetes Service, and
should typically disable the proxy:

```yaml
cluster:
  enabled: true
  tls:
    enabled: true
    servicePort: 8005
    containerPort: 8005

proxy:
  enabled: false
```

Enterprise users with Vitals enabled must also enable the cluster telemetry
service:

```yaml
clustertelemetry:
  enabled: true
  tls:
    enabled: true
    servicePort: 8006
    containerPort: 8006
```

If using the ingress controller, you must also specify the DP proxy service as
its publish target to keep Ingress status information up to date:

```
ingressController:
  env:
    publish_service: hybrid/example-release-data-kong-proxy
```

Replace `hybrid` with your DP nodes' namespace and `example-release-data` with
the name of the DP release.

#### Data plane node configuration

Data plane configuration also requires the certificate and `role`
configuration, and the database should always be set to `off`. You must also
trust the cluster certificate and indicate what hostname/port Kong should use
to find control plane nodes.

Though not strictly required, you should disable the admin service (it will not
work on DP nodes anyway, but should be disabled to avoid creating an invalid
Service resource).

```yaml
secretVolumes:
- kong-cluster-cert
```

```yaml
admin:
  enabled: false
```

```yaml
env:
  role: data_plane
  database: "off"
  cluster_cert: /etc/secrets/kong-cluster-cert/tls.crt
  cluster_cert_key: /etc/secrets/kong-cluster-cert/tls.key
  lua_ssl_trusted_certificate: /etc/secrets/kong-cluster-cert/tls.crt
  cluster_control_plane: control-plane-release-name-kong-cluster.hybrid.svc.cluster.local:8005
  cluster_telemetry_endpoint: control-plane-release-name-kong-clustertelemetry.hybrid.svc.cluster.local:8006 # Enterprise-only
```

Note that the `cluster_control_plane` value will differ depending on your
environment. `control-plane-release-name` will change to your CP release name,
`hybrid` will change to whatever namespace it resides in. See [Kubernetes'
documentation on Service
DNS](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/)
for more detail.

If you use multiple Helm releases to manage different data plane configurations
attached to the same control plane, setting the `deployment.hostname` field
will help you keep track of which is which in the `/clustering/data-plane`
endpoint.

### Cert Manager Integration

By default, Kong will create self-signed certificates on start for its TLS
listens if you do not provide your own. The chart can create
[cert-manager](https://cert-manager.io/docs/) Certificates for its Services and
configure them for you. To use this integration, install cert-manager, create
an issuer, set `certificates.enabled: true` in values.yaml, and set your issuer
name in `certificates.issuer` or `certificates.clusterIssuer` depending on the
issuer type. 

If you do not have an issuer available, you can install the example [self-signed ClusterIssuer](https://cert-manager.io/docs/configuration/selfsigned/#bootstrapping-ca-issuers)
and set `certificates.clusterIssuer: selfsigned-issuer` for testing. You
should, however, migrate to an issuer using a CA your clients trust for actual
usage.

The `proxy`, `admin`, `portal`, and `cluster` subsections under `certificates`
let you choose hostnames, override issuers, set `subject` or set `privateKey` on a per-certificate basis for the
proxy, admin API and Manager, Portal and Portal API, and hybrid mode mTLS
services, respectively.

To use hybrid mode, the control and data plane releases must use the same
issuer for their cluster certificates.

### CRD management

Earlier versions of this chart (<2.0) created CRDs associated with the ingress
controller as part of the release. This raised two challenges:

- Multiple release of the chart would conflict with one another, as each would
  attempt to create its own set of CRDs.
- Because deleting a CRD also deletes any custom resources associated with it,
  deleting a release of the chart could destroy user configuration without
  providing any means to restore it.

Helm 3 introduced a simplified CRD management method that was safer, but
requires some manual work when a chart added or modified CRDs: CRDs are created
on install if they are not already present, but are not modified during
release upgrades or deletes. Our chart release upgrade instructions call out
when manual action is necessary to update CRDs. This CRD handling strategy is
recommended for most users.

Some users may wish to manage their CRDs automatically. If you manage your CRDs
this way, we _strongly_ recommend that you back up all associated custom
resources in the event you need to recover from unintended CRD deletion.

While Helm 3's CRD management system is recommended, there is no simple means
of migrating away from release-managed CRDs if you previously installed your
release with the old system (you would need to back up your existing custom
resources, delete your release, reinstall, and restore your custom resources
after). As such, the chart detects if you currently use release-managed CRDs
and continues to use the old CRD templates when using chart version 2.0+. If
you do (your resources will have a `meta.helm.sh/release-name` annotation), we
_strongly_ recommend that you back up all associated custom resources in the
event you need to recover from unintended CRD deletion.

### InitContainers

The chart is able to deploy initContainers along with Kong. This can be very
useful when there's a requirement for custom initialization. The
`deployment.initContainers` field in values.yaml takes an array of objects that
get appended as-is to the existing `spec.template.initContainers` array in the
kong deployment resource.

### HostAliases

The chart is able to inject host aliases into containers. This can be very useful
when it's required to resolve additional domain name which can't be looked-up
directly from dns server. The `deployment.hostAliases` field in values.yaml
takes an array of objects that set to `spec.template.hostAliases` field in the
kong deployment resource.

### Sidecar Containers

The chart can deploy additional containers along with the Kong and Ingress
Controller containers, sometimes referred to as "sidecar containers".  This can
be useful to include network proxies or logging services along with Kong.  The
`deployment.sidecarContainers` field in values.yaml takes an array of objects
that get appended as-is to the existing `spec.template.spec.containers` array
in the Kong deployment resource.

### Migration Sidecar Containers

In the same way sidecar containers are attached to the Kong and Ingress
Controller containers the chart can add sidecars to the containers that runs
the migrations. The
`migrations.sidecarContainers` field in values.yaml takes an array of objects
that get appended as-is to the existing `spec.template.spec.containers` array
in the pre-upgrade-migrations, post-upgrade-migrations and migration resrouces.
Keep in mind the containers should be finite and they should be terminated
with the migration containers, otherwise the migration could get the status
as finished and the deployment of the chart will reach the timeout.

### User Defined Volumes

The chart can deploy additional volumes along with Kong. This can be useful to
include additional volumes which required during iniatilization phase
(InitContainer). The  `deployment.userDefinedVolumes` field in values.yaml
takes an array of objects that get appended as-is to the existing
`spec.template.spec.volumes` array in the kong deployment resource.

### User Defined Volume Mounts

The chart can mount user-defined volumes. The
`deployment.userDefinedVolumeMounts` and
`ingressController.userDefinedVolumeMounts` fields in values.yaml take an array
of object that get appended as-is to the existing
`spec.template.spec.containers[].volumeMounts` and
`spec.template.spec.initContainers[].volumeMounts` array in the kong deployment
resource.

### Removing cluster-scoped permissions

You can limit the controller's access to allow it to only watch specific
namespaces for namespaced resources. By default, the controller watches all
namespaces. Limiting access requires several changes to configuration:

- Set `ingressController.watchNamespaces` to a list of namespaces you want to
  watch. The chart will automatically generate roles for each namespace and
  assign them to the controller's service account.
- Optionally set `ingressController.installCRDs=false` if your user role (the
  role you use when running `helm install`, not the controller service
  account's role) does not have access to get CRDs. By default, the chart
  attempts to look up the controller CRDs for [a legacy behavior
  check](#crd-management).

### Using a DaemonSet

Setting `deployment.daemonset: true` deploys Kong using a [DaemonSet
controller](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/)
instead of a Deployment controller. This runs a Kong Pod on every kubelet in
the Kubernetes cluster. For such configuration it may be desirable to configure
Pods to use the network of the host they run on instead of a dedicated network
namespace. The benefit of this approach is that the Kong can bind ports directly
to Kubernetes nodes' network interfaces, without the extra network translation
imposed by NodePort Services. It can be achieved by setting `deployment.hostNetwork: true`.

### Using dnsPolicy and dnsConfig

The chart able to inject custom DNS configuration into containers. This can be useful when you have EKS cluster with [NodeLocal DNSCache](https://kubernetes.io/docs/tasks/administer-cluster/nodelocaldns/) configured and attach AWS security groups directly to pod using [security groups for pods feature](https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html).

### Example configurations

Several example values.yaml are available in the
[example-values](https://github.com/Kong/charts/blob/main/charts/kong/example-values/)
directory.

## Configuration

### Kong parameters

| Parameter                          | Description                                                                           | Default             |
| ---------------------------------- | ------------------------------------------------------------------------------------- | ------------------- |
| image.repository                   | Kong image                                                                            | `kong`              |
| image.tag                          | Kong image version                                                                    | `3.4`               |
| image.effectiveSemver              | Semantic version to use for version-dependent features (if `tag` is not a semver)     |                     |
| image.pullPolicy                   | Image pull policy                                                                     | `IfNotPresent`      |
| image.pullSecrets                  | Image pull secrets                                                                    | `null`              |
| replicaCount                       | Kong instance count. It has no effect when `autoscaling.enabled` is set to true         | `1`                 |
| plugins                            | Install custom plugins into Kong via ConfigMaps or Secrets                            | `{}`                |
| env                                | Additional [Kong configurations](https://getkong.org/docs/latest/configuration/)      |                     |
| customEnv                          | Custom Environment variables without `KONG_` prefix      |                                |
| migrations.preUpgrade              | Run "kong migrations up" jobs                                                         | `true`              |
| migrations.postUpgrade             | Run "kong migrations finish" jobs                                                     | `true`              |
| migrations.annotations             | Annotations for migration job pods                                                    | `{"sidecar.istio.io/inject": "false" |
| migrations.jobAnnotations          | Additional annotations for migration jobs                                             | `{}`                |
| migrations.backoffLimit            | Override the system backoffLimit                                                      | `{}`                |
| waitImage.enabled                  | Spawn init containers that wait for the database before starting Kong                 | `true`              |
| waitImage.repository               | Image used to wait for database to become ready. Uses the Kong image if none set      |                     |
| waitImage.tag                      | Tag for image used to wait for database to become ready                               |                     |
| waitImage.pullPolicy               | Wait image pull policy                                                                | `IfNotPresent`      |
| postgresql.enabled                 | Spin up a new postgres instance for Kong                                              | `false`             |
| dblessConfig.configMap             | Name of an existing ConfigMap containing the `kong.yml` file. This must have the key `kong.yml`.| `` |
| dblessConfig.config                | Yaml configuration file for the dbless (declarative) configuration of Kong | see in `values.yaml`    |

#### Kong Service Parameters

The various `SVC.*` parameters below are common to the various Kong services
(the admin API, proxy, Kong Manager, the Developer Portal, and the Developer
Portal API) and define their listener configuration, K8S Service properties,
and K8S Ingress properties. Defaults are listed only if consistent across the
individual services: see values.yaml for their individual default values.

`SVC` below can be substituted with each of:
* `proxy`
* `udpProxy`
* `admin`
* `manager`
* `portal`
* `portalapi`
* `cluster`
* `clustertelemetry`
* `status`

`status` is intended for internal use within the cluster. Unlike other
services it cannot be exposed externally, and cannot create a Kubernetes
service or ingress. It supports the settings under `SVC.http` and `SVC.tls`
only.

`cluster` is used on hybrid mode control plane nodes. It does not support the
`SVC.http.*` settings (cluster communications must be TLS-only) or the
`SVC.ingress.*` settings (cluster communication requires TLS client
authentication, which cannot pass through an ingress proxy). `clustertelemetry`
is similar, and used when Vitals is enabled on Kong Enterprise control plane
nodes.

`udpProxy` is used for UDP stream listens (Kubernetes does not yet support
mixed TCP/UDP LoadBalancer Services). It _does not_ support the `http`, `tls`,
or `ingress` sections, as it is used only for stream listens.

| Parameter                          | Description                                                                           | Default                  |
|------------------------------------|---------------------------------------------------------------------------------------|--------------------------|
| SVC.enabled                        | Create Service resource for SVC (admin, proxy, manager, etc.)                         |                          |
| SVC.http.enabled                   | Enables http on the service                                                           |                          |
| SVC.http.servicePort               | Service port to use for http                                                          |                          |
| SVC.http.containerPort             | Container port to use for http                                                        |                          |
| SVC.http.nodePort                  | Node port to use for http                                                             |                          |
| SVC.http.hostPort                  | Host port to use for http                                                             |                          |
| SVC.http.parameters                | Array of additional listen parameters                                                 | `[]`                     |
| SVC.tls.enabled                    | Enables TLS on the service                                                            |                          |
| SVC.tls.containerPort              | Container port to use for TLS                                                         |                          |
| SVC.tls.servicePort                | Service port to use for TLS                                                           |                          |
| SVC.tls.nodePort                   | Node port to use for TLS                                                              |                          |
| SVC.tls.hostPort                   | Host port to use for TLS                                                              |                          |
| SVC.tls.overrideServiceTargetPort  | Override service port to use for TLS without touching Kong containerPort              |                          |
| SVC.tls.parameters                 | Array of additional listen parameters                                                 | `["http2"]`              |
| SVC.type                           | k8s service type. Options: NodePort, ClusterIP, LoadBalancer                          |                          |
| SVC.clusterIP                      | k8s service clusterIP                                                                 |                          |
| SVC.loadBalancerClass              | loadBalancerClass to use for LoadBalancer provisionning                               |                          |
| SVC.loadBalancerSourceRanges       | Limit service access to CIDRs if set and service type is `LoadBalancer`               | `[]`                     |
| SVC.loadBalancerIP                 | Reuse an existing ingress static IP for the service                                   |                          |
| SVC.externalIPs                    | IPs for which nodes in the cluster will also accept traffic for the servic            | `[]`                     |
| SVC.externalTrafficPolicy          | k8s service's externalTrafficPolicy. Options: Cluster, Local                          |                          |
| SVC.ingress.enabled                | Enable ingress resource creation (works with SVC.type=ClusterIP)                      | `false`                  |
| SVC.ingress.ingressClassName       | Set the ingressClassName to associate this Ingress with an IngressClass               |                          |
| SVC.ingress.hostname               | Ingress hostname                                                                      | `""`                     |
| SVC.ingress.path                   | Ingress path.                                                                         | `/`                      |
| SVC.ingress.pathType               | Ingress pathType. One of `ImplementationSpecific`, `Exact` or `Prefix`                | `ImplementationSpecific` |
| SVC.ingress.hosts                  | Slice of hosts configurations, including `hostname`, `path` and `pathType` keys       | `[]`                     |
| SVC.ingress.tls                    | Name of secret resource or slice of `secretName` and `hosts` keys                     |                          |
| SVC.ingress.annotations            | Ingress annotations. See documentation for your ingress controller for details        | `{}`                     |
| SVC.ingress.labels                 | Ingress labels. Additional custom labels to add to the ingress.                       | `{}`                     |
| SVC.annotations                    | Service annotations                                                                   | `{}`                     |
| SVC.labels                         | Service labels                                                                        | `{}`                     |

#### Admin Service mTLS

On top of the common parameters listed above, the `admin` service supports parameters for mTLS client verification. 
If any of `admin.tls.client.caBundle` or `admin.tls.client.secretName` are set, the admin service will be configured to
require mTLS client verification. If both are set, `admin.tls.client.caBundle` will take precedence.

| Parameter                   | Description                                                                                 | Default |
|-----------------------------|---------------------------------------------------------------------------------------------|---------|
| admin.tls.client.caBundle   | CA certificate to use for TLS verification of the Admin API client (PEM-encoded).           | `""`    |
| admin.tls.client.secretName | CA certificate secret name - must contain a `tls.crt` key with the PEM-encoded certificate. | `""`    |

#### Stream listens

The proxy configuration additionally supports creating stream listens. These
are configured using an array of objects under `proxy.stream` and `udpProxy.stream`:

| Parameter                          | Description                                                                           | Default             |
| ---------------------------------- | ------------------------------------------------------------------------------------- | ------------------- |
| protocol                           | The listen protocol, either "TCP" or "UDP"                                            |                     |
| containerPort                      | Container port to use for a stream listen                                             |                     |
| servicePort                        | Service port to use for a stream listen                                               |                     |
| nodePort                           | Node port to use for a stream listen                                                  |                     |
| hostPort                           | Host port to use for a stream listen                                                  |                     |
| parameters                         | Array of additional listen parameters                                                 | `[]`                |

### Ingress Controller Parameters

All of the following properties are nested under the `ingressController`
section of `values.yaml` file:

| Parameter                                  | Description                                                                                                                                              | Default                            |
|--------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------|
| enabled                                    | Deploy the ingress controller, rbac and crd                                                                                                              | true                               |
| image.repository                           | Docker image with the ingress controller                                                                                                                 | kong/kubernetes-ingress-controller |
| image.tag                                  | Version of the ingress controller                                                                                                                        | `3.0`                              |
| image.effectiveSemver                      | Version of the ingress controller used for version-specific features when image.tag is not a valid semantic version                                      |                                    |
| readinessProbe                             | Kong ingress controllers readiness probe                                                                                                                 |                                    |
| livenessProbe                              | Kong ingress controllers liveness probe                                                                                                                  |                                    |
| installCRDs                                | Legacy toggle for Helm 2-style CRD management. Should not be set [unless necessary due to cluster permissions](#removing-cluster-scoped-permissions).    | false                              |
| env                                        | Specify Kong Ingress Controller configuration via environment variables                                                                                  |                                    |
| customEnv                                  | Specify custom environment variables (without the CONTROLLER_ prefix)                                                                                    |                                    |
| ingressClass                               | The name of this controller's ingressClass                                                                                                               | kong                               |
| ingressClassAnnotations                    | The ingress-class value for controller                                                                                                                   | kong                               |
| args                                       | List of ingress-controller cli arguments                                                                                                                 | []                                 |
| watchNamespaces                            | List of namespaces to watch. Watches all namespaces if empty                                                                                             | []                                 |
| admissionWebhook.enabled                   | Whether to enable the validating admission webhook                                                                                                       | true                               |
| admissionWebhook.failurePolicy             | How unrecognized errors from the admission endpoint are handled (Ignore or Fail)                                                                         | Ignore                             |
| admissionWebhook.port                      | The port the ingress controller will listen on for admission webhooks                                                                                    | 8080                               |
| admissionWebhook.address                   | The address the ingress controller will listen on for admission webhooks, if not 0.0.0.0                                                                 |                                    |
| admissionWebhook.annotations               | Annotations for the Validation Webhook Configuration                                                                                                     |                                    |
| admissionWebhook.certificate.provided      | Use a provided certificate. When set to false, the chart will automatically generate a certificate.                                                      | false                              |
| admissionWebhook.certificate.secretName    | Name of the TLS secret for the provided webhook certificate                                                                                              |                                    |
| admissionWebhook.certificate.caBundle      | PEM encoded CA bundle which will be used to validate the provided webhook certificate                                                                    |                                    |
| admissionWebhook.namespaceSelector         | Add namespaceSelector to the webhook. Please go to [Kubernetes doc for the specs](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#matching-requests-namespaceselector)                                                                          |                                    |
| admissionWebhook.timeoutSeconds            | Kubernetes `apiserver`'s timeout when running this webhook. Default: 10 seconds.                                                                         |                                    |
| userDefinedVolumes                         | Create volumes. Please go to Kubernetes doc for the spec of the volumes                                                                                  |                                    |
| userDefinedVolumeMounts                    | Create volumeMounts. Please go to Kubernetes doc for the spec of the volumeMounts                                                                        |                                    |
| terminationGracePeriodSeconds              | Sets the [termination grace period](https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/#hook-handler-execution) for Deployment pod | 30                                 |
| gatewayDiscovery.enabled                   | Enables Kong instance service discovery (for more details see [gatewayDiscovery section][gd_section])                                                    | false                              |
| gatewayDiscovery.generateAdminApiService   | Generate the admin API service name based on the release name (for more details see [gatewayDiscovery section][gd_section])                                                    | false                              |
| gatewayDiscovery.adminApiService.namespace | The namespace of the Kong admin API service (for more details see [gatewayDiscovery section][gd_section])                                                | `.Release.Namespace`               |
| gatewayDiscovery.adminApiService.name      | The name of the Kong admin API service (for more details see [gatewayDiscovery section][gd_section])                                                     | ""                                 |
| konnect.enabled                            | Enable synchronisation of data plane configuration with Konnect Runtime Group                                                                            | false                              |
| konnect.runtimeGroupID                     | Konnect Runtime Group's unique identifier.                                                                                                               |                                    |
| konnect.apiHostname                        | Konnect API hostname. Defaults to a production US-region.                                                                                                | us.kic.api.konghq.com              |
| konnect.tlsClientCertSecretName            | Name of the secret that contains Konnect Runtime Group's client TLS certificate.                                                                         | konnect-client-tls                 |
| konnect.license.enabled                    | Enable automatic license provisioning for Gateways managed by Ingress Controller in Konnect mode.                                                        | false                              |
| adminApi.tls.client.enabled                | Enable TLS client verification for the Admin API. By default, Helm will generate certificates automatically.                                             | false                              |
| adminApi.tls.client.certProvided           | Use user-provided certificates. If set to false, Helm will generate certificates.                                                                        | false                              |
| adminApi.tls.client.secretName             | Client TLS certificate/key pair secret name. Can be also set when `certProvided` is false to enforce a generated secret's name.                          | ""                                 |
| adminApi.tls.client.caSecretName           | CA TLS certificate/key pair secret name. Can be also set when `certProvided` is false to enforce a generated secret's name.                              | ""                                 |

[gd_section]: #the-gatewayDiscovery-section

#### The `env` section
For a complete list of all configuration values you can set in the
`env` section, please read the Kong Ingress Controller's
[configuration document](https://github.com/Kong/docs.konghq.com/blob/main/src/kubernetes-ingress-controller/references/cli-arguments.md).

#### The `customEnv` section

The `customEnv` section can be used to configure all environment variables other than Ingress Controller configuration.
Any key value put under this section translates to environment variables.
Every key is upper-cased before setting the environment variable.

An example:

```yaml
kong:
  ingressController:
    customEnv:
      TZ: "Europe/Berlin"
```

#### The `gatewayDiscovery` section

Kong Ingress Controller v2.9 has introduced gateway discovery which allows
the controller to discover Gateway instances that it should configure using
an Admin API Kubernetes service.

Using this feature requires a split release installation of Gateways and Ingress Controller.
For exemplar `values.yaml` files which use this feature please see: [examples README.md](./example-values/README.md).
or use the [`ingress` chart](../ingress/README.md) which can handle this for you.

##### Configuration

You'll be able to configure this feature through configuration section under
`ingressController.gatewayDiscovery`:

- If `ingressController.gatewayDiscovery.enabled` is set to `false`: the ingress controller
  will control a pre-determined set of Gateway instances based on Admin API URLs
  (provided under the hood via `CONTROLLER_KONG_ADMIN_URL` environment variable).

- If `ingressController.gatewayDiscovery.enabled` is set to `true`: the ingress controller
  will dynamically locate Gateway instances by watching the specified Kubernetes
  service.
  (provided under the hood via `CONTROLLER_KONG_ADMIN_SVC` environment variable).

  The following admin API Service flags have to be present in order for gateway
  discovery to work:

  - `ingressController.gatewayDiscovery.adminApiService.name`
  - `ingressController.gatewayDiscovery.adminApiService.namespace`

  If you set `ingressController.gatewayDiscovery.generateAdminApiService` to `true`,
  the chart will generate values for `name` and `namespace` based on the current release name and
  namespace. This is useful when consuming the `kong` chart as a subchart.

Additionally, you can control the addresses that are generated for your Gateways
via the `--gateway-discovery-dns-strategy` CLI flag that can be set on the Ingress Controller
(or an equivalent environment variable: `CONTROLLER_GATEWAY_DISCOVERY_DNS_STRATEGY`).
It accepts 3 values which change the way that Gateway addresses are generated:
- `service` - for service scoped pod DNS names: `pod-ip-address.service-name.my-namespace.svc.cluster-domain.example`
- `pod` - for namespace scope pod DNS names: `pod-ip-address.my-namespace.pod.cluster-domain.example`
- `ip` (default, retains behavior introduced in v2.9) - for regular IP addresses

When using `gatewayDiscovery`, you should consider configuring the Admin service to use mTLS client verification to make
this interface secure.
Without that, anyone who can access the Admin API from inside the cluster can configure the Gateway instances.

On the controller release side, that can be achieved by setting `ingressController.adminApi.tls.client.enabled` to `true`.
By default, Helm will generate a certificate Secret named `<release name>-admin-api-keypair` and
a CA Secret named `<release name>-admin-api-ca-keypair` for you.

To provide your own cert, set `ingressController.adminApi.tls.client.certProvided` to
`true`, `ingressController.adminApi.tls.client.secretName` to the name of the Secret containing your client cert, and `ingressController.adminApi.tls.client.caSecretName` to the name of the Secret containing your CA cert.

On the Gateway release side, set either `admin.tls.client.secretName` to the name of your CA Secret or set `admin.tls.client.caBundle` to the CA certificate string.

### General Parameters

| Parameter                          | Description                                                                           | Default             |
| ---------------------------------- | ------------------------------------------------------------------------------------- | ------------------- |
| namespace                          | Namespace to deploy chart resources                                                   |                     |
| deployment.kong.enabled            | Enable or disable deploying Kong                                                      | `true`              |
| deployment.minReadySeconds         | Minimum number of seconds for which newly created pods should be ready without any of its container crashing, for it to be considered available. |                     |
| deployment.initContainers          | Create initContainers. Please go to Kubernetes doc for the spec of the initContainers |                     |
| deployment.daemonset               | Use a DaemonSet instead of a Deployment                                               | `false`             |
| deployment.hostname                | Set the Deployment's `.spec.template.hostname`. Kong reports this as its hostname.    |                     |
| deployment.hostNetwork             | Enable hostNetwork, which binds to the ports to the host                              | `false`             |
| deployment.userDefinedVolumes      | Create volumes. Please go to Kubernetes doc for the spec of the volumes               |                     |
| deployment.userDefinedVolumeMounts | Create volumeMounts. Please go to Kubernetes doc for the spec of the volumeMounts     |                     |
| deployment.serviceAccount.create   | Create Service Account for the Deployment / Daemonset and the migrations              | `true`              |
| deployment.serviceAccount.automountServiceAccountToken   | Enable ServiceAccount token automount in Kong deployment        | `false`             |
| deployment.serviceAccount.name     | Name of the Service Account, a default one will be generated if left blank.           | ""                  |
| deployment.serviceAccount.annotations | Annotations for the Service Account                                                | {}                  |
| deployment.test.enabled            | Enable creation of test resources for use with "helm test"                            | `false`             |
| autoscaling.enabled                | Set this to `true` to enable autoscaling                                              | `false`             |
| autoscaling.minReplicas            | Set minimum number of replicas                                                        | `2`                 |
| autoscaling.maxReplicas            | Set maximum number of replicas                                                        | `5`                 |
| autoscaling.behavior               | Sets the [behavior for scaling up and down](https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/#configurable-scaling-behavior) | `{}`                |
| autoscaling.targetCPUUtilizationPercentage | Target Percentage for when autoscaling takes affect. Only used if cluster does not support `autoscaling/v2` or `autoscaling/v2beta2` | `80`  |
| autoscaling.metrics                | metrics used for autoscaling for clusters that supports `autoscaling/v2` or `autoscaling/v2beta2`           | See [values.yaml](values.yaml) |
| updateStrategy                     | update strategy for deployment                                                        | `{}`                |
| readinessProbe                     | Kong readiness probe                                                                  |                     |
| livenessProbe                      | Kong liveness probe                                                                   |                     |
| startupProbe                       | Kong startup probe                                                                    |                     |
| lifecycle                          | Proxy container lifecycle hooks                                                       | see `values.yaml`   |
| terminationGracePeriodSeconds      | Sets the [termination grace period](https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/#hook-handler-execution) for Deployment pods | 30                  |
| affinity                           | Node/pod affinities                                                                   |                     |
| topologySpreadConstraints          | Control how Pods are spread across cluster among failure-domains                      |                     |
| nodeSelector                       | Node labels for pod assignment                                                        | `{}`                |
| deploymentAnnotations              | Annotations to add to deployment                                                      |  see `values.yaml`  |
| podAnnotations                     | Annotations to add to each pod                                                        |  see `values.yaml`  |
| podLabels                          | Labels to add to each pod                                                             | `{}`                |
| resources                          | Pod resource requests & limits                                                        | `{}`                |
| tolerations                        | List of node taints to tolerate                                                       | `[]`                |
| dnsPolicy                          | Pod dnsPolicy                                                                         |                     |
| dnsConfig                          | Pod dnsConfig                                                                         |                     |
| podDisruptionBudget.enabled        | Enable PodDisruptionBudget for Kong                                                   | `false`             |
| podDisruptionBudget.maxUnavailable | Represents the minimum number of Pods that can be unavailable (integer or percentage) | `50%`               |
| podDisruptionBudget.minAvailable   | Represents the number of Pods that must be available (integer or percentage)          |                     |
| podSecurityPolicy.enabled          | Enable podSecurityPolicy for Kong                                                     | `false`             |
| podSecurityPolicy.labels           | Labels to add to podSecurityPolicy for Kong                                           | `{}`             |
| podSecurityPolicy.annotations      | Annotations to add to podSecurityPolicy for Kong                                      | `{}`             |
| podSecurityPolicy.spec             | Collection of [PodSecurityPolicy settings](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#what-is-a-pod-security-policy) | |
| priorityClassName                  | Set pod scheduling priority class for Kong pods                                       | `""`                |
| secretVolumes                      | Mount given secrets as a volume in Kong container to override default certs and keys. | `[]`                |
| securityContext                    | Set the securityContext for Kong Pods                                                 | `{}`                |
| containerSecurityContext           | Set the securityContext for Containers                                                | See values.yaml     |
| serviceMonitor.enabled             | Create ServiceMonitor for Prometheus Operator                                         | `false`             |
| serviceMonitor.interval            | Scraping interval                                                                     | `30s`               |
| serviceMonitor.namespace           | Where to create ServiceMonitor                                                        |                     |
| serviceMonitor.labels              | ServiceMonitor labels                                                                 | `{}`                |
| serviceMonitor.targetLabels        | ServiceMonitor targetLabels                                                           | `{}`                |
| serviceMonitor.honorLabels         | ServiceMonitor honorLabels                                                            | `{}`                |
| serviceMonitor.metricRelabelings   | ServiceMonitor metricRelabelings                                                      | `{}`                |
| extraConfigMaps                    | ConfigMaps to add to mounted volumes                                                  | `[]`                |
| extraSecrets                       | Secrets to add to mounted volumes                                                     | `[]`                |
| nameOverride                       | Replaces "kong" in resource names, like "RELEASENAME-nameOverride" instead of "RELEASENAME-kong" | `""`                |
| fullnameOverride                   | Overrides the entire resource name string                                             | `""`                |
| extraObjects                       | Create additional k8s resources                                                       | `[]`                |
**Note:** If you are using `deployment.hostNetwork` to bind to lower ports ( < 1024), which may be the desired option (ports 80 and 433), you also
need to tweak the `containerSecurityContext` configuration as in the example:

```yaml
containerSecurityContext: # run as root to bind to lower ports
  capabilities:
    add: [NET_BIND_SERVICE]
  runAsGroup: 0
  runAsNonRoot: false
  runAsUser: 0
```

**Note:** The default `podAnnotations` values disable inbound proxying for Kuma 
and Istio. This is appropriate when using Kong as a gateway for external 
traffic inbound into the cluster.

If you want to use Kong as an internal proxy within the cluster network, you 
should enable inbound the inbound mesh proxies:

```yaml
# Enable inbound mesh proxying for Kuma and Istio
podAnnotations:
  kuma.io/gateway: disabled
  traffic.sidecar.istio.io/includeInboundPorts: "*"
```

#### The `env` section

The `env` section can be used to configured all properties of Kong.
Any key value put under this section translates to environment variables
used to control Kong's configuration. Every key is prefixed with `KONG_`
and upper-cased before setting the environment variable.

Furthermore, all `kong.env` parameters can also accept a mapping instead of a
value to ensure the parameters can be set through configmaps and secrets.

An example:

```yaml
kong:
  env:                       # load PG password from a secret dynamically
     pg_user: kong
     pg_password:
       valueFrom:
         secretKeyRef:
            key: kong
            name: postgres
     nginx_worker_processes: "2"
```

For complete list of Kong configurations please check the
[Kong configuration docs](https://docs.konghq.com/latest/configuration).

> **Tip**: You can use the default [values.yaml](values.yaml)

#### The `customEnv` section

The `customEnv` section can be used to configure all custom properties of other than Kong.
Any key value put under this section translates to environment variables
that can be used in Kong's plugin configurations. Every key is upper-cased before setting the environment variable.

An example:

```yaml
kong:
  customEnv:
    api_token:
      valueFrom:
        secretKeyRef:
          key: token
          name: api_key
    client_name: testClient
```

#### The `extraLabels` section

The `extraLabels` section can be used to configure some extra labels that will be added to each Kubernetes object generated.

For example, you can add the `acme.com/some-key: some-value` label to each Kubernetes object by putting the following in your Helm values:

```yaml
extraLabels:
  acme.com/some-key: some-value
```

## Kong Enterprise Parameters

### Overview

Kong Enterprise requires some additional configuration not needed when using
Kong Open-Source. To use Kong Enterprise, at the minimum,
you need to do the following:

- Set `enterprise.enabled` to `true` in `values.yaml` file.
- Update values.yaml to use a Kong Enterprise image.
- Satisfy the two prerequisites below for Enterprise License and
  Enterprise Docker Registry.
- (Optional) [set a `password` environment variable](#rbac) to create the
  initial super-admin. Though not required, this is recommended for users that
  wish to use RBAC, as it cannot be done after initial setup.

Once you have these set, it is possible to install Kong Enterprise,
but please make sure to review the below sections for other settings that
you should consider configuring before installing Kong.

Some of the more important configuration is grouped in sections
under the `.enterprise` key in values.yaml, though most enterprise-specific
configuration can be placed under the `.env` key.

### Prerequisites

#### Kong Enterprise License

Kong Enterprise 2.3+ can run with or without a license. If you wish to run 2.3+
without a license, you can skip this step and leave `enterprise.license_secret`
unset. In this case only a limited subset of features will be available.
Earlier versions require a license.

If you have paid for a license, but you do not have a copy of yours, please
contact Kong Support. Once you have it, you will need to store it in a Secret:

```bash
kubectl create secret generic kong-enterprise-license --from-file=license=./license.json
```

Set the secret name in `values.yaml`, in the `.enterprise.license_secret` key.
Please ensure the above secret is created in the same namespace in which
Kong is going to be deployed.

#### Kong Enterprise Docker registry access

Kong Enterprise versions 2.2 and earlier use a private Docker registry and
require a pull secret. **If you use 2.3 or newer, you can skip this step.**

You should have received credentials to log into docker hub after
purchasing Kong Enterprise. After logging in, you can retrieve your API key
from \<your username\> \> Edit Profile \> API Key. Use this to create registry
secrets:

```bash
kubectl create secret docker-registry kong-enterprise-edition-docker \
    --docker-server=hub.docker.io \
    --docker-username=<username-provided-to-you> \
    --docker-password=<password-provided-to-you>
secret/kong-enterprise-edition-docker created
```

Set the secret names in `values.yaml` in the `image.pullSecrets` section.
Again, please ensure the above secret is created in the same namespace in which
Kong is going to be deployed.

### Service location hints

Kong Enterprise add two GUIs, Kong Manager and the Kong Developer Portal, that
must know where other Kong services (namely the admin and files APIs) can be
accessed in order to function properly. Kong's default behavior for attempting
to locate these absent configuration is unlikely to work in common Kubernetes
environments. Because of this, you should set each of `admin_gui_url`,
`admin_gui_api_url`, `proxy_url`, `portal_api_url`, `portal_gui_host`, and
`portal_gui_protocol` under the `.env` key in values.yaml to locations where
each of their respective services can be accessed to ensure that Kong services
can locate one another and properly set CORS headers. See the
[Property Reference documentation](https://docs.konghq.com/enterprise/latest/property-reference/)
for more details on these settings.

### RBAC

You can create a default RBAC superuser when initially running `helm install`
by setting a `password` environment variable under `env` in values.yaml. It
should be a reference to a secret key containing your desired password. This
will create a `kong_admin` admin whose token and basic-auth password match the
value in the secret. For example:

```yaml
env:
 password:
   valueFrom:
     secretKeyRef:
        name: kong-enterprise-superuser-password
        key: password
```

If using the ingress controller, it needs access to the token as well, by
specifying `kong_admin_token` in its environment variables:

```yaml
ingressController:
  env:
   kong_admin_token:
     valueFrom:
       secretKeyRef:
          name: kong-enterprise-superuser-password
          key: password
```

Although the above examples both use the initial super-admin, we recommend
[creating a less-privileged RBAC user](https://docs.konghq.com/enterprise/latest/kong-manager/administration/rbac/add-user/)
for the controller after installing. It needs at least workspace admin
privileges in its workspace (`default` by default, settable by adding a
`workspace` variable under `ingressController.env`). Once you create the
controller user, add its token to a secret and update your `kong_admin_token`
variable to use it. Remove the `password` variable from Kong's environment
variables and the secret containing the super-admin token after.

### Sessions

Login sessions for Kong Manager and the Developer Portal make use of
[the Kong Sessions plugin](https://docs.konghq.com/enterprise/latest/kong-manager/authentication/sessions).
When configured via values.yaml, their configuration must be stored in Secrets,
as it contains an HMAC key.

Kong Manager's session configuration must be configured via values.yaml,
whereas this is optional for the Developer Portal on versions 0.36+. Providing
Portal session configuration in values.yaml provides the default session
configuration, which can be overridden on a per-workspace basis.

```bash
cat admin_gui_session_conf
```

```json
{"cookie_name":"admin_session","cookie_samesite":"off","secret":"admin-secret-CHANGEME","cookie_secure":true,"storage":"kong"}
```

```bash
cat portal_session_conf
```

```json
{"cookie_name":"portal_session","cookie_samesite":"off","secret":"portal-secret-CHANGEME","cookie_secure":true,"storage":"kong"}
```

```bash
kubectl create secret generic kong-session-config --from-file=admin_gui_session_conf --from-file=portal_session_conf
```

```bash
secret/kong-session-config created
```

The exact plugin settings may vary in your environment. The `secret` should
always be changed for both configurations.

After creating your secret, set its name in values.yaml in
`.enterprise.rbac.session_conf_secret`. If you create a Portal configuration,
add it at `env.portal_session_conf` using a secretKeyRef.

### Email/SMTP

Email is used to send invitations for
[Kong Admins](https://docs.konghq.com/enterprise/latest/kong-manager/networking/email)
and [Developers](https://docs.konghq.com/enterprise/latest/developer-portal/configuration/smtp).

Email invitations rely on setting a number of SMTP settings at once. For
convenience, these are grouped under the `.enterprise.smtp` key in values.yaml.
Setting `.enterprise.smtp.disabled: true` will set `KONG_SMTP_MOCK=on` and
allow Admin/Developer invites to proceed without sending email. Note, however,
that these have limited functionality without sending email.

If your SMTP server requires authentication, you must provide the `username`
and `smtp_password_secret` keys under `.enterprise.smtp.auth`.
`smtp_password_secret` must be a Secret containing an `smtp_password` key whose
value is your SMTP password.

By default, SMTP uses `AUTH` `PLAIN` when you provide credentials. If your provider requires `AUTH LOGIN`, set `smtp_auth_type: login`.

## Prometheus Operator integration

The chart can configure a ServiceMonitor resource to instruct the [Prometheus
Operator](https://github.com/prometheus-operator/prometheus-operator) to
collect metrics from Kong Pods. To enable this, set
`serviceMonitor.enabled=true` in `values.yaml`.

Kong exposes memory usage and connection counts by default. You can enable
traffic metrics for routes and services by configuring the [Prometheus
plugin](https://docs.konghq.com/hub/kong-inc/prometheus/).

The ServiceMonitor requires an `enable-metrics: "true"` label on one of the
chart's Services to collect data. By default, this label is set on the proxy
Service. It should only be set on a single chart Service to avoid duplicate
data. If you disable the proxy Service (e.g. on a hybrid control plane instance
or Portal-only instance) and still wish to collect memory usage metrics, add
this label to another Service, e.g. on the admin API Service:

```
admin:
  labels:
    enable-metrics: "true"
```

## Argo CD Considerations

The built-in database subchart (`postgresql.enabled` in values) is not
supported when installing the chart via Argo CD.

Argo CD does not support the full Helm lifecycle. There is no distinction
between the initial install and upgrades. Both operations are a "sync" in Argo
terms. This affects when migration Jobs execute in database-backed Kong
installs.

The chart sets the `Sync` and `BeforeHookCreation` deletion
[hook policies](https://argo-cd.readthedocs.io/en/stable/user-guide/resource_hooks/)
on the `init-migrations` and `pre-upgrade-migrations` Jobs.

The `pre-upgrade-migrations` Job normally uses Helm's `pre-upgrade` policy. Argo
translates this to its `PreSync` policy, which would create the Job before all
sync phase resources. Doing this before various sync phase resources (such as
the ServiceAccount) are in place would prevent the Job from running
successfully. Overriding this with Argo's `Sync` policy starts the Job at the
same time as the upgraded Deployment Pods. The new Pods may fail to start
temporarily, but will eventually start normally once migrations complete.

## Seeking help

If you run into an issue, bug or have a question, please reach out to the Kong
community via [Kong Nation](https://discuss.konghq.com).
Please do not open issues in [this](https://github.com/helm/charts) repository
as the maintainers will not be notified and won't respond.
