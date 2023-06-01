This README explains how to install Kong in DB-backed mode with Postgres and Cert Manager

# Install Postgres

Use the bitnami chart to install Postgres. Read the output to understand how to connect to the database.

```bash
helm install postgres oci://registry-1.docker.io/bitnamicharts/postgresql -n db --create-namespace
```

Once connected, create a postgres user and database:

```sql
CREATE USER kong WITH PASSWORD 'super_secret'; CREATE DATABASE kong OWNER kong;
```

# Cert Manager

Install Cert Manager in to your cluster:

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.11.0/cert-manager.crds.yaml
helm install \
  cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.11.0
```

Create a self signed CA + Issuer for future use:

```yaml
echo "
apiVersion: v1
kind: Namespace
metadata:
  name: kong
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: selfsigned-issuer
spec:
  selfSigned: {}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-selfsigned-ca
  namespace: kong
spec:
  isCA: true
  commonName: my-selfsigned-ca
  secretName: root-secret
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: selfsigned-issuer
    kind: ClusterIssuer
    group: cert-manager.io
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: my-ca-issuer
  namespace: kong
spec:
  ca:
    secretName: root-secret
" | kubectl apply -f -
```

# Kong

Deploy Kong using the `cp-values.yaml` and `dp-values.yaml` in this folder:

```bash
helm install kong-cp kong/kong -n kong --values cp-values.yaml
helm install kong-dp kong/kong -n kong --values dp-values.yaml
```

You should now have Kong running in hybrid mode
