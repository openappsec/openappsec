<div align=center>
<img src="https://i2-s3-ui-static-content-prod-10.s3.eu-west-1.amazonaws.com/elpis/tree-no-bg-256.png" width="100" height="100"> 
<h1>openappsec/openappsec</h1>
</div>

[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/6629/badge)](https://bestpractices.coreinfrastructure.org/projects/6629)

# About
[open-appsec](https://www.openappsec.io) (openappsec.io) builds on machine learning to provide preemptive web app & API threat protection against OWASP-Top-10 and zero-day attacks. It can be deployed as an add-on to Kubernetes Ingress, NGINX, Envoy (soon), and API Gateways.

The open-appsec engine learns how users normally interact with your web application. It then uses this information to automatically detect requests that fall outside of normal operations, and conducts further analysis to decide whether the request is malicious or not.

Upon every HTTP request, all parts are decoded, JSON and XML sections are extracted, and any IP-level access control is applied.

Every request to the application goes through two phases:

1. Multiple variables are fed to the machine-learning engine. These variables, which are either directly extracted from the HTTP request or decoded from different parts of the payload, include attack indicators, IP addresses, user agents, fingerprints, and many other considerations. The supervised model of the machine learning engine uses these variables to compare the request with many common attack patterns found across the globe.

2. If the request is identified as a valid and legitimate request the request is allowed, and forwarded to your application. If, however, the request is considered suspicious or high risk, it then gets evaluated by the unsupervised model, which was trained in your specific environment. This model uses information such as the URL and the users involved to create a final confidence score that determines whether the request should be allowed or blocked.

##  Machine Learning models

open-appsec uses two models:

1. A supervised model that was trained offline based on millions of requests, both malicious and benign.
    
    * A basic model is provided as part of this repository. It is recommended for use in Monitor-Only and Test environments.
    * An advanced model which is more accurate and recommended for Production use can be downloaded from the [open-appsec portal](https://my.openappsec.io)->User Menu->Download advanced ML model. This model updates from time to time and you will get an email when these updates happen.

2. An unsupervised model that is being built in real time in the protected environment. This model uses traffic patterns specific to the environment.

# Resources
* [Project Website](https://openappsec.io)
* [Offical Documentation](https://docs.openappsec.io/)
* [Video Tutorials](https://www.openappsec.io/tutorials)
* [Live Playgrounds](https://www.openappsec.io/playground)


# open-appsec Installation

For Kubernetes (NGINX Ingress) using the installer:

```bash
$ wget https://downloads.openappsec.io/open-appsec-k8s-install && chmod +x open-appsec-k8s-install
$ ./open-appsec-k8s-install
```

For Kubernetes (NGINX or Kong) using Helm: follow [documentation](https://docs.openappsec.io/getting-started/start-with-kubernetes/install-using-helm-ingress-nginx-and-kong) – use this method if you’ve built your own containers. 

For Linux (NGINX or Kong) using the installer (list of supported/pre-compiled NGINX attachments is available [here](https://downloads.openappsec.io/supported-nginx.txt)):

```bash
$ wget https://downloads.openappsec.io/open-appsec-install && chmod +x open-appsec-install
$ ./open-appsec-install –auto
```

For Linux, if you’ve built your own package use the following commands:

```bash
$ install-cp-nano-agent.sh --install --hybrid_mode
$ install-cp-nano-service-http-transaction-handler.sh –install
$ install-cp-nano-attachment-registration-manager.sh --install
```
You can add the ```--token <token>``` and ```--email <email address>``` options to the first command, to get a token follow [documentation](https://docs.openappsec.io/getting-started/using-the-web-ui-saas/connect-deployed-agents-to-saas-management-k8s-and-linux). 

