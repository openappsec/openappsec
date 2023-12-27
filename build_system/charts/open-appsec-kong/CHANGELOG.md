# Changelog

## 2.33.2

* Fix a template bug related to the `affinity` field for migrations Pods.
  [#972](https://github.com/Kong/charts/pull/972)

## 2.33.1

### Fixed

* Use changed `incubator.ingress-controller.konghq.com` API group name in `KongServiceFacade`
  RBAC rules. Refer to [KIC#5302](https://github.com/Kong/kubernetes-ingress-controller/pull/5302)
  for rename reasoning.
  [#968](https://github.com/Kong/charts/pull/968)

## 2.33.0

### Improvements

* Only allow `None` ClusterIPs on ClusterIP-type Services.
  [#961](https://github.com/Kong/charts/pull/961)
  [#962](https://github.com/Kong/charts/pull/962)
* Bumped Kong version to 3.5.
  [#957](https://github.com/Kong/charts/pull/957)
* Support for `affinity` configuration has been added to migration job templates.
* Display a warning message when Kong Manager is enabled and the Admin API is disabled.
* Validate Gateway API's `Gateway` and `HTTPRoute` resources in the controller's
  admission webhook only when KIC version is 3.0 or higher.
  [#954](https://github.com/Kong/charts/pull/954)
* Added controller's RBAC rules for `KongServiceFacade` CRD (installed only when
  KongServiceFacade feature gate turned on and KIC version >= 3.1.0).
  [#963](https://github.com/Kong/charts/pull/963)

## 2.32.0

### Improvements

* Add new `deployment.hostname` value to make identifying instances in
  controlplane/dataplane configurations easier.
  [#943](https://github.com/Kong/charts/pull/943)

## 2.31.0

### Improvements

* Added controller's RBAC rules for `KongUpstreamPolicy` CRD.
  [#917](https://github.com/Kong/charts/pull/917)
* Added services resource to admission webhook config for KIC >= 3.0.0.
  [#919](https://github.com/Kong/charts/pull/919)
* Update default ingress controller version to v3.0
  [#929](https://github.com/Kong/charts/pull/929)
  [#930](https://github.com/Kong/charts/pull/930)

### Fixed

* The target port for cmetrics should only be applied if the ingress controller is enabled.
  [#926](https://github.com/Kong/charts/pull/926)
* Fix RBAC for Gateway API v1.
  [#928](https://github.com/Kong/charts/pull/928)
* Enable Admission webhook for Gateway API v1 resources.
  [#928](https://github.com/Kong/charts/pull/928)

## 2.30.0

### Improvements

* Prevent installing PodDisruptionBudget for `replicaCount: 1` or `autoscaling.minReplicas: 1`.
  [#896](https://github.com/Kong/charts/pull/896)
* The admission webhook now will be triggered on Secrets creation for KIC 2.12.1+.
  [#907](https://github.com/Kong/charts/pull/907)
* Container security context defaults now comply with the restricted pod
  security standard. This includes an enforced run as user ID set to 1000. UID
  1000 is used for official Kong images other than Alpine images (which use UID
  100) and for KIC images 3.0.0+ (older images use UID 65532). Images that do
  not use UID 1000 can still run with this user, as static image files are
  world-accessible and runtime-created files are created in temporary
  directories created for the run as user.
  [#911](https://github.com/Kong/charts/pull/911)
* Allow using templates (via `tpl`) when specifying `proxy.nameOverride`.
  [#914](https://github.com/Kong/charts/pull/914)

## 2.29.0

### Improvements
* Make it possible to set the admission webhook's `timeoutSeconds`.
  [#894](https://github.com/Kong/charts/pull/894)

## 2.28.1

### Fixed

* The admission webhook now includes Gateway API resources and Ingress
  resources for controller versions 2.12+. This version introduces new
  validations for Kong's regex path implementation.
  [#892](https://github.com/Kong/charts/pull/892)

## 2.28.0

### Improvements

* Bump default `kong` image tag to 3.4.
  [#883](https://github.com/Kong/charts/pull/883)
* Bump default ingress controller image tag to 2.12.
* Added validation rule for `latency` upstream load balancing algorithm to
  CRDs. [Upgrade your CRDs](https://github.com/Kong/charts/blob/main/charts/kong/UPGRADE.md#updates-to-crds)
  when installing this release.

## 2.27.0

### Improvements

* Listens now all support `.address` configuration. This was an existing
  setting that was not applied properly for some listens.
  [#881](https://github.com/Kong/charts/pull/881)

## 2.26.5

### Fixed 

* Kuma ServiceAccount Token hints and volumes are also available in migrations
  Pods.
  [#877](https://github.com/Kong/charts/pull/877)

## 2.26.4

### Fixed 

* updated `admin_api_uri` to `admin_gui_api_url` as per [kong documentation](https://docs.konghq.com/gateway/3.4.x/reference/configuration/#admin_api_uri). 

## 2.26.3

### Fixed 

* Enabled Service and Ingress in Kong Manager for non enterprise users.

## 2.26.2

### Fixed 

* Add missing CRD KongConsumerGroup and extend status subresource for CRDs

## 2.26.1

### Fixed

* Fix parsing enterprise tags (like e.g. `3.4.0.0`)
  [#857](https://github.com/Kong/charts/pull/857)

## 2.26.0

### Breaking changes

2.26 changes the default proxy readiness endpoint for newer Kong versions. This
causes an issue in a narrow edge case. If all of the following are true:

* You use Kong 3.3 or newer.
* You use controller 2.10 or older.
* You run the controller and proxy in separate Deployments.

you are affected and should review [the 2.26 upgrade instructions](https://github.com/Kong/charts/blob/main/charts/kong/UPGRADE.md#2260).

### Improvements

* Use the Kong 3.3 `/status/ready` endpoint for readiness probes by default if
  available. If not available, use the old `/status` default.
  [#844](https://github.com/Kong/charts/pull/844)
* Add ArgoCD `Sync` and `BeforeHookCreation` [hook policies](https://argo-cd.readthedocs.io/en/stable/user-guide/resource_hooks/)
  to the the init and pre-upgrade migrations Jobs.
* Add controller's RBAC rules for `KongConsumerGroups` CRD.
  [#850](https://github.com/Kong/charts/pull/850)
* Updated controller version to 2.11.

## 2.25.0

- Generate the `adminApiService.name` value from `.Release.Name` rather than
  hardcoding to `kong`
  [#839](https://github.com/Kong/charts/pull/839)

## 2.24.0

### Improvements

* Running `tpl` against user-supplied labels and annotations used in Deployment
  [#814](https://github.com/Kong/charts/pull/814)

  Example:
  ```yaml
  podLabels:
    version: "{{ .Values.image.tag }}"  # Will render dynamically when overridden downstream
  ```

* Fail to render templates when PodSecurityPolicy was requested but cluster doesn't
  serve its API.
  [#823](https://github.com/Kong/charts/pull/823)
* Add support for multiple hosts and tls configurations for Kong proxy `Ingress`.
  [#813](https://github.com/Kong/charts/pull/813)
* Bump postgres default tag to `13.11.0-debian-11-r20` which includes arm64 images.
  [#834](https://github.com/Kong/charts/pull/834)

### Fixed

* Fix Ingress and HPA API versions during capabilities checking
  [#827](https://github.com/Kong/charts/pull/827)

## 2.23.0

### Improvements

* Add custom label configuration option for Kong proxy `Ingress`.
  [#812](https://github.com/Kong/charts/pull/812)
* Bump default `kong/kubernetes-ingress-controller` image tag to 2.10.
  Bump default `kong` image tag to 3.3.
  [#815](https://github.com/Kong/charts/pull/815)

## 2.22.0

### Improvements

* Removed redundant RBAC permissions for non-existing subresources `secrets/status`
  and `endpoints/status`.
  [#798](https://github.com/Kong/charts/pull/798)
* For Kong Ingress Controller in version >= 2.10, RBAC permissions for `Endpoints`
  are not configured anymore (because it uses `EndpointSlices`).
  [#798](https://github.com/Kong/charts/pull/798)
* Added support for setting `certificates.cluster.commonName`. This allows a custom
  certificate `CommonName` to be provided when deploying Kong Gateway in hybrid
  mode using Cert Manager [#804](https://github.com/Kong/charts/pull/804)

## 2.21.0

### Improvements

* Added support for `startupProbe` on Kong pods. This can be configured via
  `.Values.startupProbe`. To maintain backward compatibility, it is disabled by default.
  [#792](https://github.com/Kong/charts/pull/792)
* Customize Admission Webhook namespaceSelectors and compose them from values.
  [#794](https://github.com/Kong/charts/pull/794)
* Added `CustomResourceDefinition` `list` and `watch` permissions to controller's ClusterRole.
  [#796](https://github.com/Kong/charts/pull/796)

## 2.20.2

### Fixed

* Automatic license provisioning for Gateways managed by Ingress Controllers in Konnect mode
  is disabled by default.
  To enable it, set `.Values.ingressController.konnect.license.enabled=true`.
  [#793](https://github.com/Kong/charts/pull/793)

## 2.20.1

### Fixed

* Fix correct timestamp format and remove `isCA` in certificates
  [#791](https://github.com/Kong/charts/pull/791)

## 2.20.0

### Improvements

* Added support for automatic license provisioning for Gateways managed by
  Ingress Controllers in Konnect mode (`.Values.ingressController.konnect.enabled=true`).
  [#787](https://github.com/Kong/charts/pull/787)

## 2.19.1

### Fixed

* Fix `webhook-cert` being mounted regardless if `.Values.ingressController.enabled`
  is set.
  [#779](https://github.com/Kong/charts/pull/779)

## 2.19.0

### Improvements

* Security context enforces read-only root filesystem by default. This is not
  expected to affect most configurations, but [will affect custom plugins that
  write to the container filesystem](https://github.com/Kong/charts/blob/main/charts/kong/UPGRADE.md#2170).
  [#770](https://github.com/Kong/charts/pull/770)

## 2.18.0

### Improvements

* Added support for the Admin API service TLS client verification.
  [#780](https://github.com/Kong/charts/pull/780

## 2.17.1

### Fixed

* The `-redhat` suffix on official KIC images is no longer considered part of
  the semver string for version checks.
  [#779](https://github.com/Kong/charts/pull/779)

## 2.17.0

### Improvements

* Added support for controller's gateway discovery.
  With `ingressController.gatewayDiscovery.enabled` set to `true` Kong Ingress Controller
  will enable gateway discovery using an Admin API service.
  For more information on this please see [the corresponding README.md section][kic_gateway_discovery_readme].
  This feature is only available when deploying chart with Kong Ingress Controller in version 2.9 or higher.
  [#747](https://github.com/Kong/charts/pull/747)
* Added experimental support for the ingress controller's Konnect sync feature via `ingressController.konnect.*` values.
  This feature is only available when deploying chart with Kong Ingress Controller in version 2.9 or higher and
  requires `ingressController.gatewayDiscovery.enabled` set to `true`.
  [#746](https://github.com/Kong/charts/pull/746)
* Added support for annotations on the admission webhook ValidatingWebhookConfiguration.
  [#760](https://github.com/Kong/charts/pull/760)
* Added support for `subject` and `privateKey` properties on certificates.
  [#762](https://github.com/Kong/charts/pull/762)
* Added support for loadBalancerClass in LoadBalancer type services.
  [#767](https://github.com/Kong/charts/pull/767)
* Added support for `GRPCRoute`s.
  [#772](https://github.com/Kong/charts/pull/772)
* Default Kong version is bumped to 3.2.
  [#773](https://github.com/Kong/charts/pull/773)
* Added support for admissionhook to include labels.
  [#768](https://github.com/Kong/charts/pull/768)

### Under the hood

* Add kube-linter to the CI pipeline to ensure produced manifests comply
  with community best practices.
  [#751](https://github.com/Kong/charts/pull/751)

[kic_gateway_discovery_readme]: ./README.md#the-gatewaydiscovery-section

## 2.16.5

### Fixed

* Fix autoscaling version detection.
  [#752](https://github.com/Kong/charts/pull/752)
* Don't include a clear-stale-pid initContainer when kong gateway is not
  enabled in the deployment.
  [#749](https://github.com/Kong/charts/pull/749)

## 2.16.4

### Fixed

* HorizontalPodAutoscaler's API version is detected properly.
  [#744](https://github.com/Kong/charts/pull/744)

## 2.16.3

### Fixed

* Fix template issue preventing custom dblessconfig volume from being mounted.
  [#741](https://github.com/Kong/charts/pull/741)

## 2.16.2

### Fixed

* The admission webhook is disabled when the ingress controller is disabled, as
  the admission webhook requires a service provided by the ingress controller.

## 2.16.1

### Fixed

* serviceAccount projected volume is properly provisioned for GKE clusters >= 1.20.
  [#735](https://github.com/Kong/charts/pull/735)

## 2.16.0

### Improvements

* Let users specify their own labels and annotations for generated PodSecurityPolicy.
  [#721](https://github.com/Kong/charts/pull/721)
* Enable the admission webhook by default. This can reject configuration, but
  is not expected to be a meaningfully breaking change. Existing configuration
  is not affected, and any new changes that the webhook would reject would also
  be rejected by Kong.
  [#727](https://github.com/Kong/charts/pull/727)
* Replaced static secret with projected volume in deployment.
  [#722](https://github.com/Kong/charts/pull/722)
* Reject invalid log config values.
  [#733](https://github.com/Kong/charts/pull/733)
* Update custom resource definitions to latest v2.8.1 from
  kong/kubernetes-ingress-controller
  [#730](https://github.com/Kong/charts/pull/730)
* Respect setting `.Values.deployment.serviceAccount.automountServiceAccountToken` in
  migrations Jobs. This was already the case for the Deployment.
  [#729](https://github.com/Kong/charts/pull/729)

## 2.15.3

### Fixed

* Changed `ingressController.readinessProbe` to use `/readyz` to prevent pods from becoming ready and serving 404s prior to the `ingress-controller` first syncing config to the `proxy` [#716](https://github.com/Kong/charts/pull/716).
* Fixed incorrect `if` block order in volume mount templates.

## 2.15.2

### Fixed

* Do not attempt to mount DB-less config if none provided by chart.

## 2.15.1

### Fixed

* Remove unnecessary failure condition from [#695](https://github.com/Kong/charts/pull/695).

## 2.15.0

### Improvements

* Add the `dblessConfig.secret` key to the values file, allowing the user to
  supply a Secret for their dbless config file.
  [#695](https://github.com/Kong/charts/pull/695)
* Add support for version `v1beta1` of the Gateway API when generating RBAC rules.
* Add support for version `v1beta1` of the Gateway API when generating RBAC rules.
  ([#706](https://github.com/Kong/charts/pull/706))
* Prevent supplying duplicate plugin inclusion to `KONG_PLUGINS` env variable.
  ([#711](https://github.com/Kong/charts/pull/711))

### Fixed

* Removed appProtocol to fix AKS load balancer
  ([#705](https://github.com/Kong/charts/pull/705))
* Fix lookup for CA certificate secret for admission webhook.
  ([#704](https://github.com/Kong/charts/pull/704))

## 2.14.0

Note: KIC 2.8 does include several updates to CRDs, but only for documentation and validation.
You can [upgrade CRDs](https://github.com/Kong/charts/blob/main/charts/kong/UPGRADE.md#updates-to-crds),
but doing so is not required.

### Improvements

* Default Kong and KIC versions bumped to 3.1 and 2.8.
* UDP proxy (udpProxy) assumes the UDP protocol by default for stream entries (udpProxy.stream).
  This can be still overridden to TCP by specifying the protocol explicitly, but it is not recommended to do so.
  [#682](https://github.com/Kong/charts/pull/682)
* Supported `autoscaling/v2` API
  ([#679](https://github.com/Kong/charts/pull/679))
* Add support for specifying the minium number of seconds for which newly created pods should be ready without
  any of its container crashing, for it to be considered available. (`deployment.minReadySeconds`)
  ([#688](https://github.com/Kong/charts/pull/688))
* Increased the default memory requests and limits for the Kong pod to 2G
  ([#690](https://github.com/Kong/charts/pull/690))
* Add a rule for `KongIngress` to the ValidatingWebhookConfiguration.
  ([#702](https://github.com/Kong/charts/pull/702))

### Fixed

* Removed `PodSecurityPolicy` if the API is not supported in k8s cluster
  to be compatible to k8s 1.25+.
  [#680](https://github.com/Kong/charts/pull/680)


## 2.13.1

### Improvements

* Updated default controller version to [KIC 2.7](https://github.com/Kong/kubernetes-ingress-controller/blob/main/CHANGELOG.md#270).

## 2.13.0

### Improvements

* Added cert-manager issuer support for proxy default and cluster mtls certificates
  ([#592](https://github.com/Kong/charts/pull/592))
* Updated CRDs with the new ordering field for KongPlugins, the new
  IngressClassParameters resource, and assorted field description updates.
  These [require a manual update](https://github.com/Kong/charts/blob/main/charts/kong/UPGRADE.md#updates-to-crds).
* Updated default tags to Kong 3.0 and KIC 2.6.

## 2.12.0

### Improvements

* Added ClusterRole for cluster-scoped resources when using watchNamespaces.
  [#611](https://github.com/Kong/charts/issues/611)
* Added `extraObjects` to create additional k8s resources as part of the helm release.
  [#652](https://github.com/Kong/charts/issues/652)

## 2.11.0

### Fixed

* Fixed Deployment missing if in case of empty tolerations
  [#630](https://github.com/Kong/charts/issues/630)
* Use stdout and stderr by default for all logs. Several were writing to prefix
  directory files.
  [#634](https://github.com/Kong/charts/issues/634)
* Remove `terminationGracePeriodSeconds` from KIC's container spec since this
  field is only applicable for pods, not containers.
  [#640](https://github.com/Kong/charts/issues/640)

### Improvements

* Bump controller version to 2.5.
  [#642](https://github.com/Kong/charts/issues/642)
* Added `fullnameOverride` to override the normal resource name string.
  [#635](https://github.com/Kong/charts/issues/635)
* Added size limits for emptyDir mounts.
  [#632](https://github.com/Kong/charts/issues/632)

## 2.10.2

### Fixed

* Kuma now also mounts ServiceAccount tokens on releases without a controller
  container.

## 2.10.1

### Fixed

* Updated manual ServiceAccount Secret mount format for compatibility with
  Kuma.

## 2.10.0

### Added

* Added option to disable test job pods.
  [#598](https://github.com/Kong/charts/issues/598)
* Changed default admission failure policy from `Fail` to `Ignore`.
  [#612](https://github.com/Kong/charts/issues/612)
* ServiceAccount tokens are now only mounted in the controller container to
  limit attack surface.
  [#619](https://github.com/Kong/charts/issues/619)

## 2.9.1

### Fixed

* Fixed another unwanted newline chomp that broke GatewayClass
  permissions.

## 2.9.0

* Added terminationDelaySeconds for Ingress Controller.
  ([597](https://github.com/Kong/charts/pull/597))
* Made KNative permissions conditional on CRD availability.

### Fixed

* Removed KNative permission from the Gateway permissions set.

## 2.8.2

### Fixed

* Fixed an unwanted newline chomp in fix PR #595.
  ([594](https://github.com/Kong/charts/pull/594))

## 2.8.1

### Fixed

* Fixed the stream default type, which should have been an empty array, not an
  empty map. This had no effect on chart behavior, but resulted in warning
  messages when user values.yamls contained non-empty stream configuration.
  ([594](https://github.com/Kong/charts/pull/594))
* Gateway API permissions are no longer created if Gateway API CRDs are not
  installed on the cluster. This would block installs by non-super admin users.
  ([595](https://github.com/Kong/charts/pull/595))

## 2.8.0

### Breaking changes

2.8 requires manual removal of existing IngressClass resources and updates the
Postgres sub-chart version. Further details are available [in the upgrade guide](https://github.com/Kong/charts/blob/main/charts/kong/UPGRADE.md#280).

The chart honors `ingressController.installCRDs: false` again. Remove it from
your values.yaml if it is currently present. Unless your install user [lacks
permissions to read
CRDs](https://github.com/Kong/charts/blob/main/charts/kong/README.md#removing-c
luster-scoped-permissions), which would have prevented you from installing
earlier chart versions, you should omit this setting and let the templates
detect whether you use the legacy CRD installation method automatically.

### Improvements

* Added Ingress for cluster sync.
  ([583](https://github.com/Kong/charts/pull/583))
* Added controller support for custom environment variables.
  ([568](https://github.com/Kong/charts/pull/568))
* Ingress `pathType` field is now configurable.
  ([564](https://github.com/Kong/charts/pull/564))
* Added IngressClass resources to RBAC roles.
  ([563](https://github.com/Kong/charts/pull/563))
* Ingresses now support wildcard hostnames.
  ([559](https://github.com/Kong/charts/pull/559))
* Enables the option to add sidecar containers to the migration containers.
  ([540](https://github.com/Kong/charts/pull/540))
* Update the IngressClass controller string to match the value used upstream.
  ([557](https://github.com/Kong/charts/pull/557))
* Added support for user-defined controller volume mounts.
  ([560](https://github.com/Kong/charts/pull/560))
* Added support for autoscaling `behavior`.
  ([561](https://github.com/Kong/charts/pull/561))
* Improved support and documentation for installations that [lack
  cluster-scoped permissions](https://github.com/Kong/charts/blob/main/charts/kong/README.md#removing-cluster-scoped-permissions).
  ([565](https://github.com/Kong/charts/pull/565))
* Updated podDisruptionBudget from `policy/v1beta1` to `policy/v1`.
  ([574](https://github.com/Kong/charts/pull/574))
* Updated controller version to 2.3.

### Fixed

* Removed CREATE from ValidatingWebhookConfiguration objectSelector for Secrets to align with changes in Kong/kubernetes-ingress-controller.
  ([#542](https://github.com/Kong/charts/pull/542))
* Fixed traffic routing from Istio's envoy proxy to Kong proxy when using Istio's AuthorizationPolicy.
  ([#550](https://github.com/Kong/charts/pull/550))
* Fixed creation of non-default IngressClasses
  ([#552](https://github.com/Kong/charts/pull/552))
* Fixed: wait_for_db no longer tries to instantiate the keyring in Kong Enterprise
  ([#556](https://github.com/Kong/charts/pull/556))

## 2.7.0

2.7.0 includes CRD updates, which [must be applied manually](https://github.com/Kong/charts/blob/main/charts/kong/UPGRADE.md#270).

### Breaking Changes

* There are upstream changes to the Postgres sub-chart that change many
  values.yaml keys. The default `postgresqlUsername` and `postgresqlDatabase`
  keys used in this chart's values.yaml are now `auth.username` and
  `auth.database`. If you set other Postgres sub-chart values, consult the
  [upstream README](https://github.com/bitnami/charts/tree/master/bitnami/postgresql)
  and [upgrade guide](https://docs.bitnami.com/kubernetes/infrastructure/postgresql/administration/upgrade/#to-1100)
  to see what you need to change.

### Improvements

* Added Gateway API resources to RBAC rules.
  ([#536](https://github.com/Kong/charts/pull/536))
* Replaced `sleep 15` in `preStop` command with `--wait=15` argument to `kong quit`.
  ([#531](https://github.com/Kong/charts/pull/531))
* Added support for non `KONG_` prefixed custom environment variables
  ([#530](https://github.com/Kong/charts/pull/530))
* Updated to latest CRDs from upstream.

## 2.6.5

### Fixed

* Generated IngressClass resources persist across updates properly.
  ([#518](https://github.com/Kong/charts/pull/518))

## 2.6.4

### Improvements

* Updated default tags to Kong 2.7, Kong Enterprise 2.7.0.0, and Kong Ingress
  Controller 2.1.

### Fixed

* Corrected a misnamed field in podDisruptionBudget.
  ([#519](https://github.com/Kong/charts/pull/519))

## 2.6.3

### Improvements

* Increased example resources for the Kong container.
  ([#511](https://github.com/Kong/charts/pull/511))

### Fixed

* Corrected an invalid label match condition for the admission webhook.
  ([#513](https://github.com/Kong/charts/pull/513))

## 2.6.2

### Improvements

* Added `app` and `version` labels to pods.
  ([#504](https://github.com/Kong/charts/pull/504))
* Reworked leftover socket file cleanup to avoid similar problems of the same
  class.
  ([#508](https://github.com/Kong/charts/pull/508))

### Fixed

* SecurityContext and resources applied to PID cleanup initContainer also.
  ([#503](https://github.com/Kong/charts/pull/503))
* Disabled the admission webhook on Helm Secrets, fixing an issue where it
  prevented Helm from updating release metadata.
  ([#500](https://github.com/Kong/charts/pull/500))
* initContainers that use the Kong image use the same imagePullPolicy as the
  main Kong container.
  ([#501](https://github.com/Kong/charts/pull/501))
* Applied mesh sidecar annotations to the Pod, not the Deployment.
  ([#507](https://github.com/Kong/charts/pull/507))

## 2.6.1

### Fixed

* Disabled IngressClass creation on Kubernetes versions that do not support it.
* Added missing resources (Secrets, KongClusterPlugins) to the admission
  controller configuration.
  ([#492](https://github.com/Kong/charts/pull/492))

## 2.6.0

**Note:** chart versions 2.3.0 through 2.5.0 contained an incorrect
KongIngress CRD. The `proxy.path` field was missing. Helm will not fix this
automatically on upgrade. You can fix it by running:

```
kubectl apply -f https://raw.githubusercontent.com/Kong/charts/main/charts/kong/crds/custom-resource-definitions.yaml
```

### Improvements

* Added an initContainer to clear leftover PID file in the event of a Kong
  container crash, allowing the container to restart.
  ([#480](https://github.com/Kong/charts/pull/480))
* Added deployment.hostNetwork to enable host network access.
  ([#486](https://github.com/Kong/charts/pull/486))

### Fixed

* NOTES.txt documentation link now uses up-to-date location.
* Ingress availability check tightened to require the Ingress API specifically
  in `networking.k8s.io/v1`.
  ([#484](https://github.com/Kong/charts/pull/484))
* Flipped backwards logic for creating an IngressClass when no IngressClass was
  present.
  ([#485](https://github.com/Kong/charts/pull/485))
* Removed unnecessary hardcoded controller container argument.
  ([#481](https://github.com/Kong/charts/pull/481))
* Restored missing `proxy.path` field to KongIngress CRD.

## 2.5.0

### Improvements

* Default Kong proxy version updated to 2.6.

### Fixed

* Properly disable KongClusterPlugin when watchNamespaces is set.
  ([#475](https://github.com/Kong/charts/pull/475))

## 2.4.0

### Breaking Changes

* KIC now defaults to version 2.0. If you use a database, you must first
  perform a temporary intermediate upgrade to disable KIC before upgrading it
  to 2.0 and re-enabling it. See the [upgrade guide](https://github.com/Kong/charts/blob/main/charts/kong/UPGRADE.md#disable-ingress-controller-prior-to-2x-upgrade-when-using-postgresql)
  for detailed instructions.
* ServiceAccount are now always created by default unless explicitly disabled.
  ServiceAccount customization has [moved under the `deployment` section of
  configuration](https://github.com/Kong/charts/blob/main/charts/kong/UPGRADE.md#changed-serviceaccount-configuration-location)
  to reflect this. This accomodates configurations that need a ServiceAccount
  but that do not use the ingress controller.
  ([#455](https://github.com/Kong/charts/pull/455))

### Improvements

* Migration jobs support a configurable backoffLimit.
  ([#442](https://github.com/Kong/charts/pull/442))
* Generated Ingresses now use `networking.k8s.io/v1` when available.
  ([#446](https://github.com/Kong/charts/pull/446))

### Fixed

* 5-digit UDP ports now work properly.
  ([#443](https://github.com/Kong/charts/pull/443))
* Fixed port name used for NLB annotation example.
  ([#458](https://github.com/Kong/charts/pull/458))
* Fixed a compatibility issue with Helm's `--set-file` feature and
  user-provided DB-less configuration ConfigMaps.
  ([#465](https://github.com/Kong/charts/pull/465))

## 2.3.0

### Breaking Changes

* Upgraded CRDs to V1 from the previous deprecated v1beta1.
  [#391](https://github.com/kong/charts/issues/391)
  ACTION REQUIRED: This is a breaking change as it makes
  this chart incompatible with Kubernetes clusters older
  than v1.16.x. Upgrade your cluster to a version greater
  than or equal to v1.16 before installing.
  Note that technically it will remain possible to deploy
  on older clusters by managing the CRDs manually ahead of
  time (e.g. intentionally deploying the legacy CRDs) but
  these configurations will be considered unsupported.
  [upgrade](https://kubernetes.io/docs/tasks/administer-cluster/cluster-upgrade/)
  ACTION REQUIRED: For existing deployments Helm avoids managing
  CRDs so when upgrading from a previous release you will need
  to apply the new V1 versions of the CRDs (in `crds/`) manually.
  [hip-0011](https://github.com/helm/community/blob/main/hips/hip-0011.md)
  ([#415](https://github.com/Kong/charts/pull/415))
* Added support for controller metrics to the Prometheus resources. This
  requires KIC 2.x. The chart automatically detects if your controller image is
  compatible, but only if your tag is semver-compliant. If you are using an
  image without a semver-compliant tag (such as `next`) you _must_ set the
  `ingressController.image.effectiveSemver` value to a semver string
  appropriate for your image (for example, if your image is 2.0.0-based, you
  would set it to `2.0.0`.
  ([#430](https://github.com/Kong/charts/pull/430))

### Improvements

* Updated default Kong versions to 2.5 (OSS) and 2.5.0.0 (Enterprise).
* Added user-configured initContainer support to Jobs.
  ([#408](https://github.com/Kong/charts/pull/408))
* Upgraded RBAC resources to v1 from v1beta1 for compatibility with Kubernetes
  1.22 and newer. This breaks compatibility with Kubernetes 1.7 and older, but
  these Kubernetes versions were never supported, so this change is not
  breaking. Added additional permissions to support KIC 2.x.
  ([#420](https://github.com/Kong/charts/pull/420))
  ([#419](https://github.com/Kong/charts/pull/419))
* Added `ingressController.watchNamespaces[]` to values.yaml. When set, the
  controller will only watch the listed namespaces (instead of all namespaces,
  the default), and will create Roles for each namespace (instead of a
  ClusterRole). This feature requires KIC 2.x.
  ([#420](https://github.com/Kong/charts/pull/420))
* Added support for [dnsPolicy and
  dnsConfig](https://kubernetes.io/docs/tasks/administer-cluster/nodelocaldns/).
  ([#425](https://github.com/Kong/charts/pull/425))
* Use migration commands directly in upgrade/install Jobs instead of invoking
  them via a shell. This adds support for some additional features in Kong
  images that only apply when the container command starts with `kong`.
  ([#429](https://github.com/Kong/charts/pull/429))

### Fixed
* Fixed an incorrect template for DaemonSet releases.
  ([#426](https://github.com/Kong/charts/pull/426))

## 2.2.0

### Breaking changes

* Removed default `maxUnavailable` setting for pod disruption budget
  configuration. This is necessary to allow usage of the `minUnavailable`
  setting, but means that there is no longer any default availability
  constraint. If you set `podDisruptionBudget.enabled=true` in your values and
  did not previously set any `podDisruptionBudget.maxUnavailable` value, you
  must add `podDisruptionBudget.maxUnavailable="50%"` to your values.

### Improvements

* Added host alias injection to override DNS and/or add DNS entries not
  available from the DNS resolver.
  ([#366](https://github.com/Kong/charts/pull/366))
* Added support for custom labels.
  ([#370](https://github.com/Kong/charts/pull/370))
* Only add paths to Ingresses if configured, for OpenShift 4.x compatibility.
  ([#375](https://github.com/Kong/charts/pull/375))
* Kong containers no longer the image ENTRYPOINT. This allows the stock image
  bootstrap scripts to run normally.
  ([#377](https://github.com/Kong/charts/pull/377))
* Added security context settings for containers.
  ([#387](https://github.com/Kong/charts/pull/387))
* Bumped Kong and controller image defaults to the latest versions.
  ([#378](https://github.com/Kong/charts/pull/378))
* Added support for user-provided admission webhook certificates.
  ([#385](https://github.com/Kong/charts/pull/385))
* Disable service account tokens when it is unnecessary.
  ([#389](https://github.com/Kong/charts/pull/389))

### Fixed

* Admission webhook port is now listed under the controller container, where
  the admission webhook runs.
  ([#384](https://github.com/Kong/charts/pull/384))

### Documentation

* Removed a duplicate key from example values.
  ([#360](https://github.com/Kong/charts/pull/360))
* Clarified Enterprise free mode usage.
  ([#362](https://github.com/Kong/charts/pull/362))
* Expand EKS Service annotation examples for proxy.
  ([#376](https://github.com/Kong/charts/pull/375))

## 2.1.0

### Improvements

* Added support for user-defined volumes, volume mounts, and init containers.
  ([#317](https://github.com/Kong/charts/pull/317))
* Tolerations are now applied to migration Job Pods also.
  ([#341](https://github.com/Kong/charts/pull/341))
* Added support for using a DaemonSet instead of Deployment.
  ([#347](https://github.com/Kong/charts/pull/347))
* Updated default image versions and completed migration off Bintray
  repositories.
  ([#349](https://github.com/Kong/charts/pull/349))
* PDB ignores migration Job Pods.
  ([#352](https://github.com/Kong/charts/pull/352))

### Documentation

* Clarified service monitor usage information.
  ([#345](https://github.com/Kong/charts/pull/345))

## 2.0.0

### Breaking changes

* Helm 2 is no longer supported. You **must** [migrate your Kong chart releases
  to Helm 3](https://helm.sh/docs/topics/v2_v3_migration/) before updating to
  this release.
* Deprecated [Portal auth settings](https://github.com/Kong/charts/blob/kong-1.15.0/charts/kong/UPGRADE.md#removal-of-dedicated-portal-authentication-configuration-parameters)
  are no longer supported.
* The deprecated [`runMigrations` setting](https://github.com/Kong/charts/blob/kong-1.15.0/charts/kong/UPGRADE.md#changes-to-migration-job-configuration)
  is no longer supported.
* Deprecated [admin API Service configuration](https://github.com/Kong/charts/blob/kong-1.15.0/charts/kong/UPGRADE.md#changes-to-kong-service-configuration)
  is no longer supported.
* Deprecated [multi-host proxy configuration](https://github.com/Kong/charts/blob/kong-1.15.0/charts/kong/UPGRADE.md#removal-of-multi-host-proxy-ingress)
  is no longer supported.

`helm upgrade` with the previous version (1.15.0) will print a warning message
if you still use any of the removed values.yaml configuration. If you do not
see any warnings after the upgrade completes, you are already using the modern
equivalents of these settings and can proceed with upgrading to 2.0.0-rc1.

### Improvements

* Admission webhook certificates persist after their initial creation. This
  prevents an unnecessary restart of Kong Pods on upgrades that do not actually
  modify the deployment.
  ([#256](https://github.com/Kong/charts/pull/256))
* `ingressController.installCRDs` now defaults to `false`, simplifying
  installation on Helm 3. Installs now default to using Helm 3's CRD management
  system, and do not require changes to values or install flags to install
  successfully.
  ([#305](https://github.com/Kong/charts/pull/305))
* Added support for Pod `topologySpreadConstraints`.
  ([#308](https://github.com/Kong/charts/pull/308))
* Kong Ingress Controller image now pulled from Docker Hub (due to Bintray being
  discontinued). Changed the default Docker image repository for the ingress
  controller.

### Fixed

* Generated admission webhook certificates now include SANs for compatibility
  with Go 1.15 controller builds.
  ([#312](https://github.com/Kong/charts/pull/312)).

### Documentation

* Clarified use of `terminationGracePeriodSeconds`.
  ([#302](https://github.com/Kong/charts/pull/302))

## 1.15.0

1.15.0 is an interim release before the planned release of 2.0.0. There were
several feature changes we wanted to release prior to the removal of deprecated
functionality for 2.0. The original planned deprecations covered in the [1.14.0
changelog](#1140) are still planned for 2.0.0.

### Improvements

* The default Kong version is now 2.3 and the default Kong Enterprise version
  is now 2.3.2.0.
* Added configurable `terminationGracePeriodSeconds` for the pre-stop lifecycle
  hook.
  ([#271](https://github.com/Kong/charts/pull/271)).
* Initial migration database wait init containers no longer have a default
  image configuration in values.yaml. When no image is specified, the chart
  will use the Kong image. The standard Kong images include bash, and can run
  the database wait script without downloading a separate image. Configuring a
  wait image is now only necessary if you use a custom Kong image that lacks
  bash.
  ([#285](https://github.com/Kong/charts/pull/285)).
* Init containers for database availability and migration completeness can now
  be disabled. They cause compatibility issues with many service meshes.
  ([#285](https://github.com/Kong/charts/pull/285)).
* Removed the default migration Job annotation that disabled Kuma's mesh proxy.
  The latest version of Kuma no longer prevents Jobs from completing.
  ([#285](https://github.com/Kong/charts/pull/285)).
* Services now support user-configurable labels, and the Prometheus
  ServiceMonitor label is included on the proxy Service by default. Users that
  disable the proxy Service and add this label to another Service to collect
  metrics.
  ([#290](https://github.com/Kong/charts/pull/290)).
* Migration Jobs now allow resource quota configuration. Init containers
  inherit their resource quotas from their associated Kong container.
  ([#294](https://github.com/Kong/charts/pull/294)).

### Fixed

* The database readiness wait script ConfigMap and associated mounts are no
  longer created if that feature is not in use.
  ([#285](https://github.com/Kong/charts/pull/285)).
* Removed a duplicated field from CRDs.
  ([#281](https://github.com/Kong/charts/pull/281)).

## 1.14.5

### Fixed

* Removed `http2` from default status listen TLS parameters. It only supports a
  limited subset of the extra listen parameters, and does not allow `http2`.

## 1.14.4

### Fixed

* Status listens now include parameters in the default values.yaml. The absence
  of these defaults caused a template rendering error when the TLS listen was
  enabled.

### Documentation

* Updated status listen comments to reflect TLS listen availability on Kong
  2.1+.

## 1.14.3

### Fixed

* Fix issues with legacy proxy Ingress object template.

## 1.14.2

### Fixed

* Corrected invalid default value for `enterprise.smtp.smtp_auth`.

## 1.14.1

### Fixed

* Moved several Kong container settings into the appropriate template block.
  Previously these were rendered whether or not the Kong container was enabled,
  which unintentionally applied them to the controller container.

## 1.14.0

### Breaking changes

1.14 is the last planned 1.x version of the Kong chart. 2.x will remove support
for Helm 2.x and all deprecated configuration. The chart prints a warning when
upgrading or installing if it detects any configuration still using an old
format.

* All Ingress and Service resources now use the same template. This ensures
  that all chart Ingresses and Services support the same configuration. The
  proxy previously used a unique Ingress configuration, which is now
  deprecated. If you use the proxy Ingress, [see the instructions in
  UPGRADE.md](https://github.com/Kong/charts/blob/kong-1.14.0/charts/kong/UPGRADE.md#removal-of-multi-host-proxy-ingress)
  to update your configuration. No changes are required for other Service and
  Ingress configurations.
  ([#251](https://github.com/Kong/charts/pull/251)).
* The chart now uses the standard Kong status endpoint instead of custom
  configuration, allowing users to specify their own custom configuration. The
  status endpoint is no available in versions older than Kong 1.4.0 or Kong
  Enterprise 1.5.0; if you use an older version, you will need to [add and load
  the old custom configuration](https://github.com/Kong/charts/blob/main/charts/kong/UPGRADE.md#default-custom-server-block-replaced-with-status-listen).

  If you use a newer version and include Kong container readinessProbe and/or
  livenessProbe configuration in your values.yaml, you must change the port
  from `metrics` to `status`.
  ([#255](https://github.com/Kong/charts/pull/255)).

### Fixed

* Correct an issue with migrations Job toggles.
  ([#231](https://github.com/Kong/charts/pull/231))

## 1.13.0

### Improvements

* Updated default Kong Enterprise version to 2.2.1.0-alpine.
* Updated default Kong Ingress Controller version to 1.1.
* Add `namespace` to values.yaml to override release namespace if desired.
  ([#231](https://github.com/Kong/charts/pull/231))

### Fixed

* Migration Jobs now use the same nodeSelector configuration as the main Kong
  Deployment.
  ([#238](https://github.com/Kong/charts/pull/238))
* Disabled custom Kong template mount if Kong is not enabled.
  ([#240](https://github.com/Kong/charts/pull/240))
* Changed YAML string to a YAML boolean.
  ([#240](https://github.com/Kong/charts/pull/240))

### Documentation

* Clarify requirements for using horizontal pod autoscalers.
  ([#236](https://github.com/Kong/charts/pull/236))

## 1.12.0

### Improvements

* Increased default worker count to 2 to avoid issues with latency during
  blocking tasks, such as DB-less config updates. This change increases memory
  usage, but the increase should not be a concern for any but the smallest
  deployments (deployments with memory limits below 512MB).
* Updated default Kong version to 2.2.
  ([#221](https://github.com/Kong/charts/pull/221))
* Updated default Kong Enterprise version to 2.1.4.1.
* Added a means to mount extra ConfigMap and Secret resources.
  ([#208](https://github.com/Kong/charts/pull/208))
* Added configurable annotations for migration Jobs.
  ([#219](https://github.com/Kong/charts/pull/219))
* Added template for deprecation warnings to automate formatting and avoid
  excess newlines.

### Fixed

* Upgrades no longer force auto-scaling Deployments back to the replica count.
  ([#222](https://github.com/Kong/charts/pull/222))

## 1.11.0

### Breaking changes

* Kong Ingress Controller 1.0 removes support for several deprecated flags and
  the KongCredential custom resource. Please see the [controller changelog](https://github.com/Kong/kubernetes-ingress-controller/blob/main/CHANGELOG.md#breaking-changes)
  for details. Note that Helm 3 will not remove the KongCredential CRD by
  default: you should delete it manually after converting KongCredentials to
  [credential Secrets](https://github.com/Kong/kubernetes-ingress-controller/blob/next/docs/guides/using-consumer-credential-resource.md#provision-a-consumer).
  If you manage CRDs using Helm (check to see if your KongCredential CRD has a
  `app.kubernetes.io/managed-by: Helm` label), perform the credential Secret
  conversion **before** upgrading to chart 1.11.0 to avoid losing credential
  configuration.
* The chart no longer uses the `extensions` API for PodSecurityPolicy, and now
  uses the modern `policy` API. This breaks compatibility with Kubernetes
  versions 1.11 and older.
  ([#195](https://github.com/Kong/charts/pull/195))

### Improvements

* Updated default controller version to 1.0.
* The chart now adds namespace information to manifests explicitly. This
  simplifies workflows that use `helm template`.
  ([#193](https://github.com/Kong/charts/pull/193))

### Fixed
* Changes to annotation block generation prevent incorrect YAML indentation
  when specifying annotations via command line arguments to Helm commands.
  ([#200](https://github.com/Kong/charts/pull/200))

## 1.10.0

### Breaking changes

* Kong Ingress Controller 0.10.0 comes with breaking changes to global
  `KongPlugin`s and to resources without an ingress class defined. Refer to the
  [`UPGRADE.md notes for chart 1.10.0`](https://github.com/Kong/charts/blob/main/charts/kong/UPGRADE.md#1100)
  for details.

### Improvements

* Updated default controller version to 0.10.0.

### Fixed

* Removed the `status` field from the `TCPIngress` CRD.
  ([#188](https://github.com/Kong/charts/pull/188))

## 1.9.1

### Documentation

* Clarified documentation for [breaking changes in 1.9.0](#190) to indicate
  that any values.yaml that sets `waitImage.repository` requires changes,
  including those that set the old default.
* Updated Enterprise examples to use latest Enterprise image version.

## 1.9.0

### Breaking changes

1.9.0 now uses a bash-based pre-migration database availability check. If you
set `waitImage.repository` in values.yaml, either to the previous default
(`busybox`) or to a custom image, you must change it to an image that includes
a `bash` executable.

Once you have `waitImage.repository` set to an image with bash, [perform an
initial chart version upgrade with migrations disabled](https://github.com/Kong/charts/blob/main/charts/kong/UPGRADE.md#changes-to-wait-for-postgres-image)
before re-enabling migrations, updating your Kong image version, and performing
a second release upgrade.

### Improvements

* Added support for sidecar injection.
  ([#174](https://github.com/Kong/charts/pull/174))
* Changed to a bash-based pre-migration database availability check.
  ([#179](https://github.com/Kong/charts/pull/179))
* Changed to a bash-based pre-migration database availability check.
  ([#179](https://github.com/Kong/charts/pull/179))
* Updated default Kong Enterprise version to 2.1.3.0.

### Fixed

* Added missing cluster telemetry service and fixed missing cluster service
  port.
  ([#185](https://github.com/Kong/charts/pull/185))

### Documentation

* Added an example Enterprise controller-managed DB-less values.yaml.
  ([#175](https://github.com/Kong/charts/pull/175))

## 1.8.0

**Kong Enterprise users:** please review documentation for the [Kong Enterprise
2.1.x beta
release](https://docs.konghq.com/enterprise/2.1.x/release-notes/#coming-soon)
and [hybrid mode on Kong
Enterprise](https://docs.konghq.com/enterprise/2.1.x/deployment/hybrid-mode/#kubernetes-support)
as well. Version 1.8 of the Kong Helm chart adds support for hybrid mode, which
is currently only available in the 2.1.x beta. Production systems should
continue to use the Kong Enterprise 1.5.x stable releases, which do not support
hybrid mode.

### Improvements

* Update default Kong version to 2.1.
* Update Kong Enterprise images to 1.5.0.4 (kong-enterprise-edition) and
  2.0.4.2 (kong-enterprise-k8s).
* Updated default controller version to 0.9.1.
  ([#150](https://github.com/Kong/charts/pull/150))
* Added support for ServiceMonitor targetLabels (for use with the Prometheus
  Operator).
  ([#162](https://github.com/Kong/charts/pull/162))
* Automatically handle the [new port_maps
  setting](https://github.com/Kong/kong/pull/5861) for the proxy service.
  ([#169](https://github.com/Kong/charts/pull/169))
* Add support for [hybrid mode
  deployments](https://docs.konghq.com/latest/hybrid-mode/).
  ([#160](https://github.com/Kong/charts/pull/160))


### Fixed

* Fixed an issue with improperly-rendered listen strings.
  ([#155](https://github.com/Kong/charts/pull/155))

### Documentation

* Improved inline documentation of `env` in values.yaml.
  ([#163](https://github.com/Kong/charts/pull/163))

## 1.7.0

### Improvements

* Added support for
  [CRD-only](https://github.com/Kong/charts/blob/1.7.0/charts/kong/README.md#crds-only)
  and [controller-only releases](https://github.com/Kong/charts/blob/next/charts/kong/README.md#standalone-controller-nodes).
  ([#136](https://github.com/Kong/charts/pull/136))

### Documentation

* Added a set of [example
  values.yamls](https://github.com/Kong/charts/tree/main/charts/kong/example-values)
  for various configurations of Kong and Kong Enterprise.
  ([#134](https://github.com/Kong/charts/pull/134))

## 1.6.1

This release contains no changes other than the version. This is to address an
issue with our release automation.

## 1.6.0

### Improvements

* Updated default controller version to 0.9.0.
  ([#132](https://github.com/Kong/charts/pull/132))
* Updated default Enterprise versions to 2.0.4.1 and 1.5.0.2.
  ([#130](https://github.com/Kong/charts/pull/130))
* Added ability to override chart lifecycle.
  ([#116](https://github.com/Kong/charts/pull/116))
* Added ability to apply user-defined labels to pods.
  ([#121](https://github.com/Kong/charts/pull/121))
* Filtered serviceMonitor to disable metrics collection from non-proxy
  services.
  ([#112](https://github.com/Kong/charts/pull/112))
* Set admin API to listen on localhost only if possible.
  ([#125](https://github.com/Kong/charts/pull/125))
* Add `auth_type` and `ssl` settings to `smtp` block.
  ([#127](https://github.com/Kong/charts/pull/127))
* Remove UID from default securityContext.
  ([#138](https://github.com/Kong/charts/pull/138))

### Documentation

* Corrected invalid default serviceMonitor.interval value.
  ([#110](https://github.com/Kong/charts/pull/110))
* Removed duplicate `installCRDs` documentation.
  ([#115](https://github.com/Kong/charts/pull/115))
* Simplified example license Secret creation command.
  ([#131](https://github.com/Kong/charts/pull/131))

## 1.5.0

### Improvements

* Added support for annotating the ServiceAccount.
  ([#97](https://github.com/Kong/charts/pull/97))
* Updated controller templates to use environment variables for default
  configuration.
  ([#99](https://github.com/Kong/charts/pull/99))
* Added support for stream listens.
  ([#103](https://github.com/Kong/charts/pull/103))
* Moved migration configuration under a `migrations` block with support for
  enabling upgrade jobs independently and adding annotations.
  ([#102](https://github.com/Kong/charts/pull/102))
* Added support for the [status listen](https://github.com/Kong/kong/pull/4977).
  ([#107](https://github.com/Kong/charts/pull/107))
* :warning: Exposed PodSecurityPolicy spec in values.yaml and added default
  configuration to enforce a read-only root filesystem. **Kong Enterprise
  versions prior to 1.5.0 require the root filesystem be read-write. If you use
  an older version and enforce PodSecurityPolicy, you must set
  `.Values.podSecurityPolicy.spec.readOnlyRootFilesystem: false`.**
  ([#104](https://github.com/Kong/charts/pull/104))

### Fixed

* Fixed old init-migrations jobs blocking upgrades.
  ([#102](https://github.com/Kong/charts/pull/102))

### Documentation

* Fixed discrepancy between image version in values.yaml and README.md.
  ([#96](https://github.com/Kong/charts/pull/96))
* Added example Enterprise image tags to values.yaml.
  ([#100](https://github.com/Kong/charts/pull/100))
* Added deprecation warnings in CHANGELOG.md.
  ([#91](https://github.com/Kong/charts/pull/91))
* Improved RBAC documentation to clarify process and use new controller
  functionality.
  ([#95](https://github.com/Kong/charts/pull/95))
* Added documentation for managing multi-release clusters with varied node
  roles (e.g. admin-only, Portal-only, etc.).
  ([#102](https://github.com/Kong/charts/pull/102))

## 1.4.1

### Documentation

* Fixed an issue with the 1.4.1 upgrade steps.

## 1.4.0

### Improvements

* :warning: Service and listen configuration now use a unified configuration
  format. **The previous configuration format for the admin API service is
  deprecated and will be removed in a future release.** Listen configuration
  now supports specifying parameters. Kubernetes service creation can now be
  enabled or disabled for all Kong services. Users should review the
  [1.4.0 upgrade guide](https://github.com/Kong/charts/blob/next/charts/kong/UPGRADE.md#changes-to-kong-service-configuration)
  for details on how to update their values.yaml.
  ([#72](https://github.com/Kong/charts/pull/72))
* Updated the default controller version to 0.8. This adds new
  KongClusterPlugin and TCPIngress CRDs and RBAC permissions for them. Users
  should also note that `strip_path` now defaults to disabled, which will
  likely break existing configuration. See [the controller
  changelog](https://github.com/Kong/kubernetes-ingress-controller/blob/main/CHANGELOG.md#080---20200325)
  and [upgrade-guide](https://github.com/Kong/charts/blob/next/charts/kong/UPGRADE.md#strip_path-now-defaults-to-false-for-controller-managed-routes)
  for full details.
  ([#77](https://github.com/Kong/charts/pull/77))
* Added support for user-supplied ingress controller CLI arguments.
  ([#79](https://github.com/Kong/charts/pull/79))
* Added support for annotating the chart's deployment.
  ([#81](https://github.com/Kong/charts/pull/81))
* Switched to the Bitnami Postgres chart, as the chart in Helm's repository has
  [moved
  there](https://github.com/helm/charts/tree/master/stable/postgresql#this-helm-chart-is-deprecated).
  ([#82](https://github.com/Kong/charts/pull/82))

### Fixed

* Corrected the app version in Chart.yaml.
  ([#86](https://github.com/Kong/charts/pull/86))

### Documentation

* Fixed incorrect default value for `installCRDs`.
  ([#78](https://github.com/Kong/charts/pull/78))
* Added detailed upgrade guide covering breaking changes and deprecations.
  ([#74](https://github.com/Kong/charts/pull/74))
* Improved installation steps for Helm 2 and Helm 3.
  ([#83](https://github.com/Kong/charts/pull/83))
  ([#84](https://github.com/Kong/charts/pull/84))
* Remove outdated `ingressController.replicaCount` setting.
  ([#87](https://github.com/Kong/charts/pull/87))

## 1.3.1

### Fixed

* Added missing newline to NOTES.txt template.
  ([#66](https://github.com/Kong/charts/pull/66))

### Documentation

* Instruct users to create secrets for both the kong-enterprise-k8s and
  kong-enterprise-edition Docker registries.
  ([#65](https://github.com/Kong/charts/pull/65))
* Updated maintainer information.

## 1.3.0

### Improvements

* Custom plugin mounts now support subdirectories. These are necessary for
  plugins that include their own migrations. Note that Kong versions prior to
  2.0.1 [have a bug](https://github.com/Kong/kong/pull/5509) that prevents them
  from running these migrations. ([#24](https://github.com/Kong/charts/pull/24))
* LoadBalancer services will now respect their NodePort.
  ([#48](https://github.com/Kong/charts/pull/41))
* The proxy TLS listen now enables HTTP/2 (and, by extension, gRPC).
  ([#47](https://github.com/Kong/charts/pull/47))
* Added support for `priorityClassName` to the Kong deployment.
  ([#56](https://github.com/Kong/charts/pull/56))
* Bumped default Kong version to 2.0 and controller version to 0.7.1.
  ([#60](https://github.com/Kong/charts/pull/60))
* :warning: Removed dedicated Portal auth settings, which are unnecessary in
  modern versions. **The `enterprise.portal.portal_auth` and
  `enterprise.portal.session_conf_secret` settings in values.yaml are
  deprecated and will be removed in a future release.** See the [upgrade
  guide](https://github.com/Kong/charts/blob/main/charts/kong/UPGRADE.md#removal-of-dedicated-portal-authentication-configuration-parameters)
  for instructions on migrating them to environment variables.
  ([#55](https://github.com/Kong/charts/pull/55))

### Fixed

* Fixed typo in HorizontalPodAutoscaler template.
  ([#45](https://github.com/Kong/charts/pull/45))

### Documentation

* Added contributing guidelines. ([#41](https://github.com/Kong/charts/pull/41))
* Added README section for Helm 2 versus Helm 3 considerations.
  ([#34](https://github.com/Kong/charts/pull/41))
* Added documentation for `proxy.annotations` to README.md.
  ([#57](https://github.com/Kong/charts/pull/57))
* Added FAQ entry for init-migrations job conflicts on upgrades.
  ([#59](https://github.com/Kong/charts/pull/59)
* Move changelog out of README.md into CHANGELOG.md.
  ([#60](https://github.com/Kong/charts/pull/60)
* Improved formatting for 1.2.0 changelog.

## 1.2.0

### Improvements
* Added support for HorizontalPodAutoscaler.
  ([#12](https://github.com/Kong/charts/pull/12))
* Environment variables are now consistently sorted alphabetically.
  ([#29](https://github.com/Kong/charts/pull/29))

### Fixed
* Removed temporary ServiceAccount template, which caused upgrades to break the
  existing ServiceAccount's credentials. Moved template and instructions for
  use to FAQs, as the temporary user is only needed in rare scenarios.
  ([#31](https://github.com/Kong/charts/pull/31))
* Fix an issue where the wait-for-postgres job did not know which port to use
  in some scenarios. ([#28](https://github.com/Kong/charts/pull/28))

### Documentation
* Added warning regarding volume mounts.
  ([#25](https://github.com/Kong/charts/pull/25))

## 1.1.1

### Fixed

* Add missing `smtp_admin_emails` and `smtp_mock = off` to SMTP enabled block in
  `kong.env`.

### CI changes

* Remove version bump requirement in preparation for new release model.

## 1.1.0

> https://github.com/Kong/charts/pull/4

### Improvements

* Significantly refactor the `env`/EnvVar templating system to determine the
  complete set of environment variables (both user-defined variables and
  variables generated from other sections of values.yaml) and resolve conflicts
  before rendering. User-provided values are now guaranteed to take precedence
  over generated values. Previously, precedence relied on a Kubernetes
  implementation quirk that was not consistent across all Kubernetes providers.
* Combine templates for license, session configuration, etc. that generate
  `secretKeyRef` values into a single generic template.

## 1.0.3

- Fix invalid namespace for pre-migrations and Role.
- Fix whitespaces formatting in README.

## 1.0.2

- Helm 3 support: CRDs are declared in crds directory. Backward compatible support for helm 2.

## 1.0.1

Fixed invalid namespace variable name causing ServiceAccount and Role to be generated in other namespace than desired.

## 1.0.0

There are not code changes between `1.0.0` and `0.36.5`.
From this version onwards, charts are hosted at https://charts.konghq.com.

The `0.x` versions of the chart are available in Helm's
[Charts](https://github.com/helm/charts) repository are are now considered
deprecated.

## 0.36.5

> PR https://github.com/helm/charts/pull/20099

### Improvements

- Allow `grpc` protocol for KongPlugins

## 0.36.4

> PR https://github.com/helm/charts/pull/20051

### Fixed

- Issue: [`Ingress Controller errors when chart is redeployed with Admission
  Webhook enabled`](https://github.com/helm/charts/issues/20050)

## 0.36.3

> PR https://github.com/helm/charts/pull/19992

### Fixed

- Fix spacing in ServiceMonitor when label is specified in config

## 0.36.2

> PR https://github.com/helm/charts/pull/19955

### Fixed

- Set `sideEffects` and `admissionReviewVersions` for Admission Webhook
- timeouts for liveness and readiness probes has been changed from `1s` to `5s`

## 0.36.1

> PR https://github.com/helm/charts/pull/19946

### Fixed

- Added missing watch permission to custom resources

## 0.36.0

> PR https://github.com/helm/charts/pull/19916

### Upgrade Instructions

- When upgrading from <0.35.0, in-place chart upgrades will fail.
  It is necessary to delete the helm release with `helm del --purge $RELEASE` and redeploy from scratch.
  Note that this will cause downtime for the kong proxy.

### Improvements

- Fixed Deployment's label selector that prevented in-place chart upgrades.

## 0.35.1

> PR https://github.com/helm/charts/pull/19914

### Improvements

- Update CRDs to Ingress Controller 0.7
- Optimize readiness and liveness probes for more responsive health checks
- Fixed incorrect space in NOTES.txt

## 0.35.0

> PR [#19856](https://github.com/helm/charts/pull/19856)

### Improvements

- Labels on all resources have been updated to adhere to the Helm Chart
  guideline here:
  https://v2.helm.sh/docs/developing_charts/#syncing-your-chart-repository

## 0.34.2

> PR [#19854](https://github.com/helm/charts/pull/19854)

This release contains no user-visible changes

### Under the hood

 - Various tests have been consolidated to speed up CI.

## 0.34.1

> PR [#19887](https://github.com/helm/charts/pull/19887)

### Fixed

- Correct indentation for Job securityContexts.

## 0.34.0

> PR [#19885](https://github.com/helm/charts/pull/19885)

### New features

- Update default version of Ingress Controller to 0.7.0

## 0.33.1

> PR [#19852](https://github.com/helm/charts/pull/19852)

### Fixed

- Correct an issue with white space handling within `final_env` helper.

## 0.33.0

> PR [#19840](https://github.com/helm/charts/pull/19840)

### Dependencies

- Postgres sub-chart has been bumped up to 8.1.2

### Fixed

- Removed podDisruption budge for Ingress Controller. Ingress Controller and
  Kong run in the same pod so this was no longer applicable
- Migration job now receives the same environment variable and configuration
  as that of the Kong pod.
- If Kong is configured to run with Postgres, the Kong pods now always wait
  for Postgres to start. Previously this was done only when the sub-chart
  Postgres was deployed.
- A hard-coded container name is used for kong: `proxy`. Previously this
  was auto-generated by Helm. This deterministic naming allows for simpler
  scripts and documentation.

### Under the hood

Following changes have no end user visible effects:

- All Custom Resource Definitions have been consolidated into a single
  template file
- All RBAC resources have been consolidated into a single template file
- `wait-for-postgres` container has been refactored and de-duplicated

## 0.32.1

### Improvements

- This is a doc only release. No code changes have been done.
- Post installation steps have been simplified and now point to a getting
  started page
- Misc updates to README:
  - Document missing variables
  - Remove outdated variables
  - Revamp and rewrite major portions of the README
  - Added a table of content to make the content navigable

## 0.32.0

### Improvements

- Create and mount emptyDir volumes for `/tmp` and `/kong_prefix` to allow
  for read-only root filesystem securityContexts and PodSecurityPolicys.
- Use read-only mounts for custom plugin volumes.
- Update stock PodSecurityPolicy to allow emptyDir access.
- Override the standard `/usr/local/kong` prefix to the mounted emptyDir
  at `/kong_prefix` in `.Values.env`.
- Add securityContext injection points to template. By default,
  it sets Kong pods to run with UID 1000.

### Fixes

- Correct behavior for the Vitals toggle.
  Vitals defaults to on in all current Kong Enterprise releases, and
  the existing template only created the Vitals environment variable
  if `.Values.enterprise.enabled == true`. Inverted template to create
  it (and set it to "off") if that setting is instead disabled.
- Correct an issue where custom plugin configurations would block Kong
  from starting.

## 0.31.0

### Breaking changes

- Admin Service is disabled by default (`admin.enabled`)
- Default for `proxy.type` has been changed to `LoadBalancer`

### New features

- Update default version of Kong to 1.4
- Update default version of Ingress Controller to 0.6.2
- Add support to disable kong-admin service via `admin.enabled` flag.

## 0.31.2

### Fixes

- Do not remove white space between documents when rendering
  `migrations-pre-upgrade.yaml`

## 0.30.1

### New Features

- Add support for specifying Proxy service ClusterIP

## 0.30.0

### Breaking changes

- `admin_gui_auth_conf_secret` is now required for Kong Manager
  authentication methods other than `basic-auth`.
  Users defining values for `admin_gui_auth_conf` should migrate them to
  an externally-defined secret with a key of `admin_gui_auth_conf` and
  reference the secret name in `admin_gui_auth_conf_secret`.

## 0.29.0

### New Features

- Add support for specifying Ingress Controller environment variables.

## 0.28.0

### New Features

- Added support for the Validating Admission Webhook with the Ingress Controller.

## 0.27.2

### Fixes

- Do not create a ServiceAccount if it is not necessary.
- If a configuration change requires creating a ServiceAccount,
  create a temporary ServiceAccount to allow pre-upgrade tasks to
  complete before the regular ServiceAccount is created.

## 0.27.1

### Documentation updates
- Retroactive changelog update for 0.24 breaking changes.

## 0.27.0

### Breaking changes

- DB-less mode is enabled by default.
- Kong is installed as an Ingress Controller for the cluster by default.

## 0.25.0

### New features

- Add support for PodSecurityPolicy
- Require creation of a ServiceAccount

## 0.24.0

### Breaking changes

- The configuration format for ingresses in values.yaml has changed.
Previously, all ingresses accepted an array of hostnames, and would create
ingress rules for each. Ingress configuration for services other than the proxy
now accepts a single hostname, which allows simpler TLS configuration and
automatic population of `admin_api_uri` and similar settings. Configuration for
the proxy ingress is unchanged, but its documentation now accurately reflects
the TLS configuration needed.
