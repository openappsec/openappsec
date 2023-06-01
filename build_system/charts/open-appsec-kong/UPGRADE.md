# Upgrade considerations

New versions of the Kong chart may add significant new functionality or
deprecate/entirely remove old functionality. This document covers how and why
users should update their chart configuration to take advantage of new features
or migrate away from deprecated features.

In general, breaking changes deprecate their old features before removing them
entirely. While support for the old functionality remains, the chart will show
a warning about the outdated configuration when running `helm
install/status/upgrade`.

Note that not all versions contain breaking changes. If a version is not
present in the table of contents, it requires no version-specific changes when
upgrading from a previous version.

## Table of contents

- [Upgrade considerations for all versions](#upgrade-considerations-for-all-versions)
- [2.17.0](#2170)
- [2.13.0](#2130)
- [2.8.0](#280)
- [2.7.0](#270)
- [2.4.0](#240)
- [2.3.0](#230)
- [2.2.0](#220)
- [2.1.0](#210)
- [2.0.0](#200)
- [1.14.0](#1140)
- [1.11.0](#1110)
- [1.10.0](#1100)
- [1.9.0](#190)
- [1.6.0](#160)
- [1.5.0](#150)
- [1.4.0](#140)
- [1.3.0](#130)

## Upgrade considerations for all versions

The chart automates the
[upgrade migration process](https://github.com/Kong/kong/blob/master/UPGRADE.md).
When running `helm upgrade`, the chart spawns an initial job to run `kong
migrations up` and then spawns new Kong pods with the updated version. Once
these pods become ready, they begin processing traffic and old pods are
terminated. Once this is complete, the chart spawns another job to run `kong
migrations finish`.

If you split your Kong deployment across multiple Helm releases (to create
proxy-only and admin-only nodes, for example), you must
[set which migration jobs run based on your upgrade order](https://github.com/Kong/charts/blob/main/charts/kong/README.md#separate-admin-and-proxy-nodes).
However, this does not apply to hybrid mode, which can run both migrations but
requires [upgrading the control plane version
first](https://docs.konghq.com/gateway/latest/plan-and-deploy/hybrid-mode/#version-compatibility).

While the migrations themselves are automated, the chart does not automatically
ensure that you follow the recommended upgrade path. If you are upgrading from
more than one minor Kong version back, check the [upgrade path
recommendations for Kong open source](https://github.com/Kong/kong/blob/master/UPGRADE.md#3-suggested-upgrade-path)
or [Kong Enterprise](https://docs.konghq.com/enterprise/latest/deployment/migrations/).

Although not required, users should upgrade their chart version and Kong
version indepedently. In the even of any issues, this will help clarify whether
the issue stems from changes in Kubernetes resources or changes in Kong.

Users may encounter an error when upgrading which displays a large block of
text ending with `field is immutable`. This is typically due to a bug with the
`init-migrations` job, which was not removed automatically prior to 1.5.0.
If you encounter this error, deleting any existing `init-migrations` jobs will
clear it.

### Updates to CRDs

Helm installs CRDs at initial install but [does not update them
after](https://github.com/helm/community/blob/main/hips/hip-0011.md). Some
chart releases include updates to CRDs that must be applied to successfully
upgrade. Because Helm does not handle these updates, you must manually apply
them before upgrading your release.

``` kubectl apply -f
https://raw.githubusercontent.com/Kong/charts/kong-<version>/charts/kong/crds/custom-resource-definitions.yaml
```

For example, if your release is 2.6.4, you would apply
`https://raw.githubusercontent.com/Kong/charts/kong-2.6.4/charts/kong/crds/custom-resource-definitions.yaml`.

## 2.19.0

2.19 sets a default [security context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
that declares a read-only root filesystem for Kong containers. The base Kong and KIC
images are compatible with this setting. The chart mounts temporary writeable
emptyDir filesystems for locations that require writeable files (`/tmp` and
`/kong_prefix/`).

This setting limit attack surface and should be compatible with most
installations. However, if you use custom plugins that write to disk, you must
either mount a writeable emptyDir for them or override the new defaults by
setting:

```
containerSecurityContext:
  readOnlyRootFilesystem: false
```

in your values.yaml.

## 2.13.0

2.13.0 includes updated CRDs. You must [apply these manually](#updates-to-crds)
before upgrading an existing release.

2.13 changes the default Kong tag to 3.0 and the default KIC tag to 2.6. We
recommend that you set these versions (`image.tag` and
`ingressController.image.tag`) in your values.yaml to allow updating the chart
without also updating the container versions. If you do update to these
container image versions, you should first review the Kong 3.0 breaking changes
(see the [open
source](https://github.com/Kong/kong/blob/master/CHANGELOG.md#300) and
[Enterprise](https://docs.konghq.com/gateway/changelog/#3000) Kong changelogs)
and the [ingress controller upgrade guide for Kong
3.x](https://docs.konghq.com/kubernetes-ingress-controller/2.6.x/guides/upgrade-kong-3x).

Kong 3.0 requires KIC version 2.6 at minimum. It will not work with any
previous versions. Changes to regular expression paths in Kong 3.x furthermore
require changes to Ingresses that use regular expression paths in rules.

## 2.8.0

### IngressClass controller name change requires manual delete

2.8 updates the chart-managed IngressClass's controller name to match the
controller name used elsewhere in Kong's documenation. Controller names are
immutable, so Helm cannot actually update existing IngressClass resources.

Prior to your upgrade, you must delete the existing IngressClass. Helm will
create a new IngressClass with the new controller name during the upgrade:

```
kubectl delete ingressclass <class name, "kong" by default>
helm upgrade RELEASE_NAME kong/kong ...
```

Removing the IngressClass will not affect configuration: the controller
IngressClass implementation is still in progress, and it will still ingest
resources whose `ingress.class` annotation or `ingressClassName` value matches
the the `CONTROLLER_INGRESS_CLASS` value in the controller environment even if
no matching IngressClass exists.

### Postgres subchart version update

2.8 updates the Postgres subchart version from 8.6.8 to 11.1.15. This changes
a number of values.yaml keys and the default Postgres version. The previous
default Postgres version was [11.7.0-debian-10-r37](https://github.com/bitnami/charts/blob/590c6b0f4e07161614453b12efe71f22e0c00a46/bitnami/postgresql/values.yaml#L18).

To use the new version on an existing install, you should [follow Bitnami's
instructions for updating values.yaml keys and upgrading their chart]() as well
as [the Postgres upgrade instructions](https://www.postgresql.org/docs/current/upgrading.html).

You can alternately use the new chart without upgrading Postgres by setting
`postgresql.image.tag=11.7.0-debian-10-r37` or use the old version of the
chart. Helm documentation is unclear on whether ignoring a subchart version
change for a release is possible, so we recommend [dumping the
database](https://www.postgresql.org/docs/current/backup-dump.html) and
creating a separate release if you wish to continue using 8.6.8:

```
$ helm install my-release -f values.yaml --version 8.6.8 bitnami/postgresql
```

Afterwords, you will upgrade your Kong chart release with
`postgresql.enabled=false` and `env.pg_host` and `env.pg_password` set to the
appropriate hostname and Secret reference for your new release (these are set
automatically when the subchart is enabled, but will not be set automatically
with a separate release).

## 2.7.0

2.7 updates CRDs to the version released in KIC 2.1.0. Helm does not upgrade
CRDs automatically; you must `kubectl apply -f https://raw.githubusercontent.com/Kong/charts/kong-2.7.0/charts/kong/crds/custom-resource-definitions.yaml`
manually before upgrading.

You should not apply the updated CRDs until you are prepared to upgrade to KIC
2.1 or higher, and [must have first upgraded to 2.0](https://github.com/Kong/kubernetes-ingress-controller/blob/v2.1.1/CHANGELOG.md#breaking-changes)
and applied the [previous version of the CRDs](https://raw.githubusercontent.com/Kong/charts/kong-2.6.4/charts/kong/crds/custom-resource-definitions.yaml).

## 2.4.0

### Disable ingress controller prior to 2.x upgrade when using PostgreSQL

Chart version 2.4 is the first Kong chart version that defaults to the 2.x
series of ingress controller releases. 2.x uses a different leader election
system than 1.x. If both versions are running simultaneously, both controller
versions will attempt to interact with the admin API, potentially setting
inconsistent configuration in the database when PostgreSQL is the backend.

If you are configured with the following:

- ingressController.enabled=true
- postgresql.enabled=true

and do not override the ingress controller version, you must perform the
upgrade in multiple steps:

First, pin the controller version and upgrade to chart 2.4.0:

```console
$ helm upgrade --wait \
  --set ingressController.image.tag=<CURRENT_CONTROLLER_VERSION> \
  --version 2.4.0 \
  --namespace <YOUR_RELEASE_NAMESPACE> \
  <YOUR_RELEASE_NAME> kong/kong
```
Second, temporarily disable the ingress controller:

```console
$ helm upgrade --wait \
  --set ingressController.enabled=false \
  --set deployment.serviceaccount.create=true \
  --version 2.4.0 \
  --namespace <YOUR_RELEASE_NAMESPACE> \
  <YOUR_RELEASE_NAME> kong/kong
```
Finally, re-enable the ingress controller at the new version:

```console
$ helm upgrade --wait \
  --set ingressController.enabled=true \
  --set ingressController.image.tag=<NEW_CONTROLLER_VERSION> \
  --version 2.4.0 \
  --namespace <YOUR_RELEASE_NAMESPACE> \
  <YOUR_RELEASE_NAME> kong/kong
```

While the controller is disabled, changes to Kubernetes configuration (Ingress
resources, KongPlugin resources, Service Endpoints, etc.) will not update Kong
proxy configuration. We recommend you establish an active maintenance window
under which to perform this upgrade and inform users and stakeholders so as to
avoid unexpected disruption.

### Changed ServiceAccount configuration location

2.4.0 moved ServiceAccount configuration from
`ingressController.serviceAccount` to `deployment.serviceAccount` to accomodate
configurations that required a ServiceAccount but did not use the controller.

The chart now creates a ServiceAccount by default. When enabled, upgrade
migration hooks require the ServiceAccount, but Helm will not create it before
the hooks run, and the migration jobs will fail. To avoid this, first perform
an initial chart upgrade that does not update the Kong image version and sets
`migrations.preUpgrade=false` and `migrations.postUpgrade=false`. This will
create the account for future upgrades, and you can re-enable migrations and
upgrade your Kong version after.

If you disable ServiceAccount or override its name, you must move your
configuration under `deployment.serviceAccount`. The chart will warn you if it
detects non-default configuration in the original location when you upgrade.
You can use `helm upgrade --dry-run` to see if you are affected before actually
upgrading.

## 2.3.0

### Updated CRDs and CRD API version

2.3.0 adds new and updated CRDs for KIC 2.x. These CRDs are compatible with
KIC 1.x also. The CRD API version is now v1, replacing the deprecated v1beta1,
to support Kubernetes 1.22 and onward. API version v1 requires Kubernetes 1.16
and newer.

Helm 2-style CRD management will upgrade CRDs automatically. You can check to
see if you are using Helm 2-style management by running:

```
kubectl get crd kongconsumers.configuration.konghq.com -o yaml | grep "meta.helm.sh/release-name"
```

If you see output, you are using Helm 2-style CRD management.

Helm 3-style CRD management (the default) does not upgrade CRDs automatically.
You must apply the changes manually by running:

```
kubectl apply -f https://raw.githubusercontent.com/Kong/charts/kong-2.2.0/charts/kong/crds/custom-resource-definitions.yaml
```

Although not recommended, you can remain on an older Kubernetes version and not
upgrade your CRDs if you are using Helm 3-style CRD management. However, you
will not be able to run KIC 2.x, and these configurations are considered
unsupported.

### Ingress controller feature detection

2.3.0 includes some features that are enabled by default, but require KIC 2.x.
KIC 2.x is not yet the default ingress controller version because there are
currently only preview releases for it. To maintain compatibility with KIC 1.x,
the chart automatically detects the KIC image version and disables incompatible
features. This feature detection requires a semver image tag, and the chart
cannot render successfully if the image tag is not semver-compliant.

Standard KIC images do use semver-compliant tags, and you do not need to make
any configuration changes if you use one. If you use a non-semver tag, such as
`next`, you must set the new `ingressController.image.effectiveSemver` field to
your approximate semver version. For example, if your `next` tag is for an
unreleased `2.1.0` KIC version, you should set `effectiveSemver: 2.1.0`.

## 2.2.0

### Changes to pod disruption budget defaults

Prior to 2.2.0, the default values.yaml included
`podDisruptionBudget.maxUnavailable: 50%`. This prevented setting
`podDisruptionBudget.minUnavailable` at all. To allow use of
`podDisruptionBudget.minUnavailable`, we have removed the
`podDisruptionBudget.maxUnavailable` default. If you previously relied on this
default (you set `podDisruptionBudget.enabled: true` but did not set
`podDisruptionBudget.maxUnavailable`), you now must explicitly set
`podDisruptionBudget.maxUnavailable: 50%` in your values.yaml.

## 2.1.0

### Migration off Bintray

Bintray, the Docker registry previously used for several images used by this
chart, is [sunsetting May 1,
2021](https://jfrog.com/blog/into-the-sunset-bintray-jcenter-gocenter-and-chartcenter/).

The chart default `values.yaml` now uses the new Docker Hub repositories for all
affected images. You should check your release `values.yaml` files to confirm that
they do not still reference Bintray repositories. If they do, update them to
use the Docker Hub repositories now in the default `values.yaml`.

## 2.0.0

### Support for Helm 2 dropped

2.0.0 takes advantage of template functionality that is only available in Helm
3 and reworks values defaults to target Helm 3 CRD handling, and requires Helm
3 as such. If you are not already using Helm 3, you must migrate to it before
updating to 2.0.0 or later:

https://helm.sh/docs/topics/v2_v3_migration/

If desired, you can migrate your Kong chart releases without migrating charts'
releases.

### Support for deprecated 1.x features removed

Several previous 1.x chart releases reworked sections of values.yaml while
maintaining support for the older version of those settings. 2.x drops support
for the older versions of these settings entirely:

* [Portal auth settings](#removal-of-dedicated-portal-authentication-configuration-parameters)
* [The `runMigrations` setting](#changes-to-migration-job-configuration)
* [Single-stack admin API Service configuration](#changes-to-kong-service-configuration)
* [Multi-host proxy configuration](#removal-of-multi-host-proxy-ingress)

Each deprecated setting is accompanied by a warning that appears at the end of
`helm upgrade` output on a 1.x release:

```
WARNING: You are currently using legacy ...
```

If you do not see any such warnings when upgrading a release using chart
1.15.0, you are not using deprecated configuration and are ready to upgrade to
2.0.0. If you do see these warnings, follow the linked instructions to migrate
to the current settings format.

## 1.14.0

### Removal of multi-host proxy Ingress

Most of the chart's Ingress templates support a single hostname and TLS Secret.
The proxy Ingress template originally differed, and allowed multiple hostnames
and TLS configurations. As of chart 1.14.0, we have deprecated the unique proxy
Ingress configuration; it is now identical to all other Kong services. If you
do not need to configure multiple Ingress rules for your proxy, you will
change:

```yaml
ingress:
  hosts: ["proxy.kong.example"]
  tls:
  - hosts:
    - proxy.kong.example
    secretName: example-tls-secret
  path: /
```
to:

```yaml
ingress:
  tls: example-tls-secret
  hostname: proxy.kong.example
  path: /
```
We plan to remove support for the multi-host configuration entirely in version
2.0 of the chart. If you currently use multiple hosts, we recommend that you
either:
- Define Ingresses for each application, e.g. if you proxy applicationA at
  `foo.kong.example` and applicationB at `bar.kong.example`, you deploy those
  applications with their own Ingress resources that target the proxy.
- Define a multi-host Ingress manually. Before upgrading, save your current
  proxy Ingress, delete labels from the saved copy, and set
  `proxy.ingress.enabled=false`. After upgrading, create your Ingress from the
  saved copy and edit it directly to add new rules.

We expect that most users do not need a built-in multi-host proxy Ingress or
even a proxy Ingress at all: the old configuration predates the Kong Ingress
Controller and is most useful if you place Kong behind some other controller.
If you are interested in preserving this functionality, please [discuss your
use case with us](https://github.com/Kong/charts/issues/73). If there is
sufficient interest, we will explore options for continuing to support the
original proxy Ingress configuration format.

### Default custom server block replaced with status listen

Earlier versions of the chart included [a custom server block](https://github.com/Kong/charts/blob/kong-1.13.0/charts/kong/templates/config-custom-server-blocks.yaml)
to provide `/status` and `/metrics` endpoints. This server block simplified
RBAC-enabled Enterprise deployments by providing access to these endpoints
outside the (protected) admin API.

Current versions (Kong 1.4.0+ and Kong Enterprise 1.5.0+) have a built-in
status listen that provides the same functionality, and chart 1.14.0 uses it
for readiness/liveness probes and the Prometheus service monitor.

If you are using a version that supports the new status endpoint, you do not
need to make any changes to your values unless you include `readinessProbe` and
`livenessProbe` in them. If you do, you must change the port from `metrics` to
`status`.

If you are using an older version that does not support the status listen, you
will need to:
- Create the server block ConfigMap independent of the chart. You will need to
  set the ConfigMap name and namespace manually and remove the labels block.
- Add an `extraConfigMaps` values entry for your ConfigMap.
- Set `env.nginx_http_include` to `/path/to/your/mount/servers.conf`.
- Add the [old readiness/liveness probe blocks](https://github.com/Kong/charts/blob/kong-1.13.0/charts/kong/values.yaml#L437-L458)
  to your values.yaml.
- If you use the Prometheus service monitor, edit it after installing the chart
  and set `targetPort` to `9542`. This cannot be set from values.yaml, but Helm
  3 will preserve the change on subsequent upgrades.

## 1.11.0

### `KongCredential` custom resources no longer supported

1.11.0 updates the default Kong Ingress Controller version to 1.0. Controller
1.0 removes support for the deprecated KongCredential resource. Before
upgrading to chart 1.11.0, you must convert existing KongCredential resources
to [credential Secrets](https://github.com/Kong/kubernetes-ingress-controller/blob/next/docs/guides/using-consumer-credential-resource.md#provision-a-consumer).

Custom resource management varies depending on your exact chart configuration.
By default, Helm 3 only creates CRDs in the `crds` directory if they are not
already present, and does not modify or remove them after. If you use this
management method, you should create a manifest file that contains [only the
KongCredential CRD](https://github.com/Kong/charts/blob/kong-1.10.0/charts/kong/crds/custom-resource-definitions.yaml#L35-L68)
and then [delete it](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/#delete-a-customresourcedefinition).

Helm 2 and Helm 3 both allow managing CRDs via the chart. In Helm 2, this is
required; in Helm 3, it is optional. When using this method, only a single
release will actually manage the CRD. Check to see which release has
`ingressController.installCRDs: true` to determine which does so if you have
multiple releases. When using this management method, upgrading a release to
chart 1.11.0 will delete the KongCredential CRD during the upgrade, which will
_delete any existing KongCredential resources_. To avoid losing configuration,
check to see if your CRD is managed:

```
kubectl get crd kongcredentials.configuration.konghq.com -o yaml | grep "app.kubernetes.io/managed-by: Helm"
```

If that command returns output, your CRD is managed and you must convert to
credential Secrets before upgrading (you should do so regardless, but are not
at risk of losing data, and can downgrade to an older chart version if you have
issues).

### Changes to CRDs

Controller 1.0 [introduces a status field](https://github.com/Kong/kubernetes-ingress-controller/blob/main/CHANGELOG.md#added)
for its custom resources. By default, Helm 3 does not apply updates to custom
resource definitions if those definitions are already present on the Kubernetes
API server (and they will be if you are upgrading a release from a previous
chart version). To update your custom resources:

```
kubectl apply -f https://raw.githubusercontent.com/Kong/charts/main/charts/kong/crds/custom-resource-definitions.yaml
```

### Deprecated controller flags/environment variables and annotations removed

Kong Ingress Controller 0.x versions had a number of deprecated
flags/environment variables and annotations. Version 1.0 removes support for
these, and you must update your configuration to use their modern equivalents
before upgrading to chart 1.11.0.

The [controller changelog](https://github.com/Kong/kubernetes-ingress-controller/blob/master/CHANGELOG.md#breaking-changes)
provides links to lists of deprecated configuration and their replacements.

## 1.10.0

### `KongClusterPlugin` replaces global `KongPlugin`s

Kong Ingress Controller 0.10.0 no longer supports `KongPlugin`s with a `global: true` label. See the [KIC changelog for 0.10.0](https://github.com/Kong/kubernetes-ingress-controller/blob/main/CHANGELOG.md#0100---20200915) for migration hints.

### Dropping support for resources not specifying an ingress class

Kong Ingress Controller 0.10.0 drops support for certain kinds of resources without a `kubernetes.io/ingress.class` annotation. See the [KIC changelog for 0.10.0](https://github.com/Kong/kubernetes-ingress-controller/blob/main/CHANGELOG.md#0100---20200915) for the exact list of those kinds, and for possible migration paths.

## 1.9.0

### New image for Enterprise controller-managed DB-less deployments

As of Kong Enterprise 2.1.3.0, there is no longer a separate image
(`kong-enterprise-k8s`) for controller-managed DB-less deployments. All Kong
Enterprise deployments now use the `kong-enterprise-edition` image.

Existing users of the `kong-enterprise-k8s` image can use the latest
`kong-enterprise-edition` image as a drop-in replacement for the
`kong-enterprise-k8s` image. You will also need to [create a Docker registry
secret](https://github.com/Kong/charts/blob/main/charts/kong/README.md#kong-enterprise-docker-registry-access)
for the `kong-enterprise-edition` registry and add it to `image.pullSecrets` in
values.yaml if you do not have one already.

### Changes to wait-for-postgres image

Prior to 1.9.0, the chart launched a busybox initContainer for migration Pods
to check Postgres' reachability [using
netcat](https://github.com/Kong/charts/blob/kong-1.8.0/charts/kong/templates/_helpers.tpl#L626).

As of 1.9.0, the chart uses a [bash
script](https://github.com/Kong/charts/blob/kong-1.9.0/charts/kong/templates/wait-for-postgres-script.yaml)
to perform the same connectivity check. The default `waitImage.repository`
value is now `bash` rather than `busybox`. Double-check your values.yaml to
confirm that you do not set `waitImage.repository` and `waitImage.tag` to the
old defaults: if you do, remove that configuration before upgrading.

The Helm upgrade cycle requires this script be available for upgrade jobs. On
existing installations, you must first perform an initial `helm upgrade --set
migrations.preUpgrade=false --migrations.postUpgrade=false` to chart 1.9.0.
Perform this initial upgrade without making changes to your Kong image version:
if you are upgrading Kong along with the chart, perform a separate upgrade
after with the migration jobs re-enabled.

If you do not override `waitImage.repository` in your releases, you do not need
to make any other configuration changes when upgrading to 1.9.0.

If you do override `waitImage.repository` to use a custom image, you must
switch to a custom image that provides a `bash` executable. Note that busybox
images, or images derived from it, do _not_ include a `bash` executable. We
recommend switching to an image derived from the public bash Docker image or a
base operating system image that provides a `bash` executable.

## 1.6.0

### Changes to Custom Resource Definitions

The KongPlugin and KongClusterPlugin resources have changed. Helm 3's CRD
management system does not modify CRDs during `helm upgrade`, and these must be
updated manually:

```
kubectl apply -f https://raw.githubusercontent.com/Kong/charts/kong-1.6.0/charts/kong/crds/custom-resource-definitions.yaml
```

Existing plugin resources do not require changes; the CRD update only adds new
fields.

### Removal of default security context UID setting

Versions of Kong prior to 2.0 and Kong Enterprise prior to 1.3 use Docker
images that required setting a UID via Kubernetes in some environments
(primarily OpenShift). This is no longer necessary with modern Docker images
and can cause issues depending on other environment settings, so it was
removed.

Most users should not need to take any action, but if you encounter permissions
errors when upgrading (`kubectl describe pod PODNAME` should contain any), you
can restore it by adding the following to your values.yaml:

```
securityContext:
  runAsUser: 1000
```

## 1.5.0

### PodSecurityPolicy defaults to read-only root filesystem

1.5.0 defaults to using a read-only root container filesystem if
`podSecurityPolicy.enabled: true` is set in values.yaml. This improves
security, but is incompatible with Kong Enterprise versions prior to 1.5. If
you use an older version and enable PodSecurityPolicy, you must set
`podSecurityPolicy.spec.readOnlyRootFilesystem: false`.

Kong open-source and Kong for Kubernetes Enterprise are compatible with a
read-only root filesystem on all versions.

### Changes to migration job configuration

Previously, all migration jobs were enabled/disabled through a single
`runMigrations` setting. 1.5.0 splits these into toggles for each of the
individual upgrade migrations:

```
migrations:
  preUpgrade: true
  postUpgrade: true
```

Initial migration jobs are now only run during `helm install` and are deleted
automatically when users first run `helm upgrade`.

Users should replace `runMigrations` with the above block from the latest
values.yaml.

The new format addresses several needs:
* The initial migrations job are only created during the initial install,
  preventing [conflicts on upgrades](https://github.com/Kong/charts/blob/main/charts/kong/FAQs.md#running-helm-upgrade-fails-because-of-old-init-migrations-job).
* The upgrade migrations jobs can be disabled as need for managing
  [multi-release clusters](https://github.com/Kong/charts/blob/main/charts/kong/README.md#separate-admin-and-proxy-nodes).
  This enables management of clusters that have nodes with different roles,
  e.g. nodes that only run the proxy and nodes that only run the admin API.
* Migration jobs now allow specifying annotations, and provide a default set
  of annotations that disable some service mesh sidecars. Because sidecar
  containers do not terminate, they [prevent the jobs from completing](https://github.com/kubernetes/kubernetes/issues/25908).

## 1.4.0

### Changes to default Postgres permissions

The [Postgres sub-chart](https://github.com/bitnami/charts/tree/master/bitnami/postgresql)
used by this chart has modified the way their chart handles file permissions.
This is not an issue for new installations, but prevents Postgres from starting
if its PVC was created with an older version. If affected, your Postgres pod
logs will show:

```
postgresql 19:16:04.03 INFO  ==> ** Starting PostgreSQL **
2020-03-27 19:16:04.053 GMT [1] FATAL:  data directory "/bitnami/postgresql/data" has group or world access
2020-03-27 19:16:04.053 GMT [1] DETAIL:  Permissions should be u=rwx (0700).
```

You can restore the old permission handling behavior by adding two settings to
the `postgresql` block in values.yaml:

```yaml
postgresql:
  enabled: true
  postgresqlDataDir: /bitnami/postgresql/data
  volumePermissions:
    enabled: true
```

For background, see https://github.com/helm/charts/issues/13651

### `strip_path` now defaults to `false` for controller-managed routes

1.4.0 defaults to version 0.8 of the ingress controller, which changes the
default value of the `strip_path` route setting from `true` to `false`. To
understand how this works in practice, compare the upstream path for these
requests when `strip_path` is toggled:

| Ingress path | `strip_path` | Request path | Upstream path |
|--------------|--------------|--------------|---------------|
| /foo/bar     | true         | /foo/bar/baz | /baz          |
| /foo/bar     | false        | /foo/bar/baz | /foo/bar/baz  |

This change brings the controller in line with the Kubernetes Ingress
specification, which expects that controllers will not modify the request
before passing it upstream unless explicitly configured to do so.

To preserve your existing route handling, you should add this annotation to
your ingress resources:

```
konghq.com/strip-path: "true"
```

This is a new annotation that is equivalent to the `route.strip_path` setting
in KongIngress resources. Note that if you have already set this to `false`,
you should leave it as-is and not add an annotation to the ingress.

### Changes to Kong service configuration

1.4.0 reworks the templates and configuration used to generate Kong
configuration and Kuberenetes resources for Kong's services (the admin API,
proxy, Developer Portal, etc.). For the admin API, this requires breaking
changes to the configuration format in values.yaml. Prior to 1.4.0, the admin
API allowed a single listen only, which could be toggled between HTTPS and
HTTP:

```yaml
admin:
  enabled: false # create Service
  useTLS: true
  servicePort: 8444
  containerPort: 8444
```
In 1.4.0+, the admin API allows enabling or disabling the HTTP and TLS listens
independently. The equivalent of the above configuration is:

```yaml
admin:
  enabled: false # create Service
  http:
    enabled: false # create HTTP listen
    servicePort: 8001
    containerPort: 8001
    parameters: []

  tls:
    enabled: true # create HTTPS listen
    servicePort: 8444
    containerPort: 8444
    parameters:
    - http2
```
All Kong services now support `SERVICE.enabled` parameters: these allow
disabling the creation of a Kubernetes Service resource for that Kong service,
which is useful in configurations where nodes have different roles, e.g. where
some nodes only handle proxy traffic and some only handle admin API traffic. To
disable a Kong service completely, you should also set `SERVICE.http.enabled:
false` and `SERVICE.tls.enabled: false`. Disabling creation of the Service
resource only leaves the Kong service enabled, but only accessible within its
pod. The admin API is configured with only Service creation disabled to allow
the ingress controller to access it without allowing access from other pods.

Services now also include a new `parameters` section that allows setting
additional listen options, e.g. the `reuseport` and `backlog=16384` parameters
from the [default 2.0.0 proxy
listen](https://github.com/Kong/kong/blob/2.0.0/kong.conf.default#L186). For
compatibility with older Kong versions, the chart defaults do not enable most
of the newer parameters, only HTTP/2 support. Users of versions 1.3.0 and newer
can safely add the new parameters.

## 1.3.0

### Removal of dedicated Portal authentication configuration parameters

1.3.0 deprecates the `enterprise.portal.portal_auth` and
`enterprise.portal.session_conf_secret` settings in values.yaml in favor of
placing equivalent configuration under `env`. These settings are less important
in Kong Enterprise 0.36+, as they can both be set per workspace in Kong
Manager.

These settings provide the default settings for Portal instances: when the
"Authentication plugin" and "Session Config" dropdowns at
https://manager.kong.example/WORKSPACE/portal/settings/ are set to "Default",
the settings from `KONG_PORTAL_AUTH` and `KONG_PORTAL_SESSION_CONF` are used.
If these environment variables are not set, the defaults are to use
`basic-auth` and `{}` (which applies the [session plugin default
configuration](https://docs.konghq.com/hub/kong-inc/session/)).

If you set nonstandard defaults and wish to keep using these settings, or use
Kong Enterprise 0.35 (which did not provide a means to set per-workspace
session configuration) you should convert them to environment variables. For
example, if you currently have:

```yaml
portal:
  enabled: true
  portal_auth: basic-auth
  session_conf_secret: portal-session
```
You should remove the `portal_auth` and `session_conf_secret` entries and
replace them with their equivalents under the `env` block:

```yaml
env:
  portal_auth: basic-auth
  portal_session_conf:
    valueFrom:
      secretKeyRef:
        name: portal-session
        key: portal_session_conf
```
