# Frequently Asked Questions (FAQs)

Despite the title, this is more a list of common problems.

#### Kong cannot connect to a fresh Postgres install and fails to start

If Kong is reporting that it cannot connect to Postgres because of an invalid
password on a fresh install, you likely have a leftover PersistentVolume from a
previous install using the same name. You should delete your install, delete
the associated PersistentVolumeClaim, and install again.

Postgres PVCs [are not deleted when the chart install is
deleted](https://docs.bitnami.com/kubernetes/faq/troubleshooting/troubleshooting-helm-chart-issues/#persistence-volumes-pvs-retained-from-previous-releases),
and will be reused by subsequent installs if still present. Since the `kong`
user password is written to disk during database initialization only, that old
user's password is expected, not the new user's.

PVC names use the pattern `data-<release name>-postgresql-<replica index>`. If
you named your install `foo` and did not increase the Postgres replica count,
you will have a single `data-foo-postgresql-0` PVC that needs to be deleted:

```
kubectl delete pvc data-foo-postgresql-0
```

If you use a workflow that frequently deletes and re-creates installs, you
should make sure to delete PVCs when you delete the release:

```
helm delete foo; kubectl delete pvc data-foo-postgresql-0 
```

#### Upgrading a release fails due to missing ServiceAccount

When upgrading a release, some configuration changes result in this error:

```
Error creating: pods "releasename-kong-pre-upgrade-migrations-" is forbidden: error looking up service account releasename-kong: serviceaccount "releasename-kong" not found
```

Enabling the ingress controller or PodSecurityPolicy requires that the Kong
chart also create a ServiceAccount. When upgrading from a configuration that
previously had neither of these features enabled, the pre-upgrade-migrations
Job attempts to use this ServiceAccount before it is created. It is [not
possible to easily handle this case automatically](https://github.com/Kong/charts/pull/31).

Users encountering this issue should temporarily modify their
[pre-upgrade-migrations template](https://github.com/Kong/charts/blob/main/charts/kong/templates/migrations-pre-upgrade.yaml),
adding the following at the bottom:

```
{{ if or .Values.podSecurityPolicy.enabled (and .Values.ingressController.enabled .Values.ingressController.serviceAccount.create) -}}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ template "kong.serviceAccountName" . }}
  namespace: {{ template "kong.namespace" . }}
  annotations:
    "helm.sh/hook": pre-upgrade
    "helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded
  labels:
    {{- include "kong.metaLabels" . | nindent 4 }}
{{- end -}}
```

Upgrading with this in place will create a temporary service account before
creating the actual service account. After this initial upgrade, users must
revert to the original pre-upgrade migrations template, as leaving the
temporary ServiceAccount template in place will [cause permissions issues on
subsequent upgrades](https://github.com/Kong/charts/issues/30).

#### Running "helm upgrade" fails because of old init-migrations Job

When running `helm upgrade`, the upgrade fails and Helm reports an error
similar to the following:

```
Error: UPGRADE FAILED: cannot patch "RELEASE-NAME-kong-init-migrations" with
kind Job: Job.batch "RELEASE-NAME-kong-init-migrations" is invalid ... field
is immutable
```

This occurs if a `RELEASE-NAME-kong-init-migrations` Job is left over from a
previous `helm install` or `helm upgrade`. Deleting it with
`kubectl delete job RELEASE-NAME-kong-init-migrations` will allow the upgrade
to proceed. Chart versions greater than 1.5.0 delete the job automatically.

#### DB-backed instances do not start when deployed within a service mesh

Service meshes, such as Istio and Kuma, if deployed in a mode that injects
a sidecar to Kong, don't make the mesh available to `InitContainer`s,
because the sidecar starts _after_ all `InitContainer`s finish.

By default, this chart uses init containers to ensure that the database is
online and has migrations applied before starting Kong. This provides for a
smoother startup, but isn't compatible with service mesh sidecar requirements
if Kong is to access the database through the mesh.

Setting `waitImage.enabled=false` in values.yaml disables these init containers
and resolves this issue. However, during the initial install, your Kong
Deployment will enter the CrashLoopBackOff state while waiting for migrations
to complete. It will eventually exit this state and enter Running as long as
there are no issues finishing migrations, usually within 2 minutes.

If your Deployment is stuck in CrashLoopBackoff for longer, check the init
migrations Job logs to see if it is unable to connect to the database or unable
to complete migrations for some other reason. Resolve any issues you find,
delete the release, and attempt to install again.

#### Kong fails to start after `helm upgrade` when Postgres is used

As of Kong chart 2.8, this issue is no longer present. 2.8 updates the Postgres
sub-chart to a version that checks for existing password Secrets and leaves
them as-is rather than overwriting them.

You may be running into this issue: https://github.com/helm/charts/issues/12575.
This issue is caused due to: https://github.com/helm/helm/issues/3053.

The problem that happens is that Postgres database has the old password but
the new secret has a different password, which is used by Kong, and password
based authentication fails.

The solution to the problem is to specify a password to the `postgresql` chart.
This is to ensure that the password is not generated randomly but is set to
the same one that is user-provided on each upgrade.

The Postgres chart provides [two options](https://github.com/bitnami/charts/tree/master/bitnami/postgresql#postgresql-common-parameters)
for setting a password:

- `auth.password` sets a password directly in values.yaml, in cleartext. This
  is fine if you are using the instance for testing and have no security
  concerns.
- `auth.existingSecret` specifies a Secret that contains [specific keys](https://github.com/bitnami/charts/blob/a6146a1ed392c8683c30b21e3fef905d86b0d2d6/bitnami/postgresql/values.yaml#L134-L143).
  This should be used if you need to properly secure the Postgres instance.

If you have already upgraded, the old password is lost. You will need to
delete the Helm release and the Postgres PersistentVolumeClaim before
re-installing with a non-random password.
