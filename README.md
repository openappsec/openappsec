<div align=center>
<img src="https://i2-s3-ui-static-content-prod-10.s3.eu-west-1.amazonaws.com/elpis/tree-no-bg-256.png" width="100" height="100"> 
<h1>openappsec/openappsec</h1>
</div>

[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/6629/badge)](https://bestpractices.coreinfrastructure.org/projects/6629)

# About
[open-appsec](https://www.openappsec.io) (openappsec.io) builds on machine learning to provide preemptive web app & API threat protection against OWASP-Top-10 and zero-day attacks. It can be deployed as an add-on to Linux, Docker or K8s deployments, on NGINX, Kong, APISIX, or Envoy.

The open-appsec engine learns how users normally interact with your web application. It then uses this information to automatically detect requests that fall outside of normal operations, and conducts further analysis to decide whether the request is malicious or not.

Upon every HTTP request, all parts are decoded, JSON and XML sections are extracted, and any IP-level access control is applied.

Every request to the application goes through two phases:

1. Multiple variables are fed to the machine-learning engine. These variables, which are either directly extracted from the HTTP request or decoded from different parts of the payload, include attack indicators, IP addresses, user agents, fingerprints, and many other considerations. The supervised model of the machine learning engine uses these variables to compare the request with many common attack patterns found across the globe.

2. If the request is identified as a valid and legitimate request the request is allowed, and forwarded to your application. If, however, the request is considered suspicious or high risk, it then gets evaluated by the unsupervised model, which was trained in your specific environment. This model uses information such as the URL and the users involved to create a final confidence score that determines whether the request should be allowed or blocked.

![image](https://github.com/openappsec/openappsec/assets/114033741/f32f1c99-9c45-4d21-aa85-61408a16a18e)


open-appsec uses two machine learning models:

1. A supervised model that was trained offline based on millions of requests, both malicious and benign.
    
    * A **basic model** is provided as part of this repository. It is recommended for use in Monitor-Only and Test environments.
    * An **advanced model** which is more accurate and **recommended for Production** use can be downloaded from the [open-appsec portal](https://my.openappsec.io)->User Menu->Download advanced ML model. This model updates from time to time and you will get an email when these updates happen.

2. An unsupervised model that is being built in real time in the protected environment. This model uses traffic patterns specific to the environment.


# Management

open-appsec can be managed using multiple methods:
* [Declarative configuration files](https://docs.openappsec.io/getting-started/getting-started)
* [Kubernetes Helm Charts and annotations](https://docs.openappsec.io/getting-started/getting-started)
* [Using SaaS Web Management](https://docs.openappsec.io/getting-started/using-the-web-ui-saas)

open-appsec Web UI:
<img width="1854" height="775" alt="image" src="https://github.com/user-attachments/assets/4c6f7b0a-14f3-4f02-9ab0-ddadc9979b8d" />



## Deployment Playgrounds (Virtual labs)
You can experiment with open-appsec using [Playgrounds](https://www.openappsec.io/playground)
<img width="781" height="878" alt="image" src="https://github.com/user-attachments/assets/0ddee216-5cdf-4288-8c41-cc28cfbf3297" />

# Resources
* [Project Website](https://openappsec.io)
* [Offical Documentation](https://docs.openappsec.io/)
* [Video Tutorials](https://www.openappsec.io/tutorials)

# Installation

For Kubernetes (NGINX /Kong / APISIX / Istio) using Helm: follow [documentation](https://docs.openappsec.io/getting-started/start-with-kubernetes)

For Linux (NGINX / Kong / APISIX) using the installer (list of supported/pre-compiled NGINX attachments is available [here](https://downloads.openappsec.io/packages/supported-nginx.txt)):

```bash
$ wget https://downloads.openappsec.io/open-appsec-install && chmod +x open-appsec-install
$ ./open-appsec-install --auto
```
For kong Lua Based plug in follow [documentation](https://docs.openappsec.io/getting-started/start-with-linux)

For Linux, if you’ve built your own package use the following commands:

```bash
$ install-cp-nano-agent.sh --install --hybrid_mode
$ install-cp-nano-service-http-transaction-handler.sh --install
$ install-cp-nano-attachment-registration-manager.sh --install
```
You can add the ```--token <token>``` and ```--email <email address>``` and ```registered_server```  options to the first command, to get a token follow [documentation](https://docs.openappsec.io/getting-started/using-the-web-ui-saas/connect-deployed-agents-to-saas-management-k8s-and-linux). 

For Docker: follow [documentation](https://docs.openappsec.io/getting-started/start-with-docker) 

For more information read the [documentation](https://docs.openappsec.io/) or follow the [video tutorials](https://www.openappsec.io/tutorials).

# Repositories

open-appsec GitHub includes four main repositories:

* [openappsec/openappsec](https://github.com/openappsec/openappsec) the main code and logic of open-appsec. Developed in C++.
* [openappsec/attachment](https://github.com/openappsec/attachment) connects between processes that provide HTTP data (e.g NGINX) and the open-appsec Agent security logic. Developed in C.
* [openappsec/smartsync](https://github.com/openappsec/smartsync) in charge of correlating learning data from multiple agent instances and delivering a unified learning model for each asset. Developed in Golang.
* [openappsec/smartsync-shared-files](https://github.com/openappsec/smartsync-shared-files) interface to physical storage used by smartsync service for storing learning data. Developed in Golang.

# Compilation instructions

## Installing external dependencies

Before compiling the services, you'll need to ensure the latest development versions of the following libraries and tools:
* Boost
* OpenSSL
* PCRE2
* libxml2
* GTest
* GMock
* cURL
* Redis
* Hiredis
* MaxmindDB
* yq

An example of installing the packages on Alpine:

```bash
 $ apk update
 $ apk add boost-dev openssl-dev pcre2-dev libxml2-dev gtest-dev curl-dev hiredis-dev redis libmaxminddb-dev yq
```

## Compiling and packaging the agent code

1. Clone this repository
2. Run CMake command
3. Run make install command

```bash
 $ git clone https://github.com/openappsec/openappsec.git
 $ cd openappsec/
 $ cmake -DCMAKE_INSTALL_PREFIX=build_out .
 $ make install
 $ make package
```

## Placing the agent code inside an Alpine docker image

Once the agent code has been compiled and packaged, an Alpine image running it can be created. This requires permissions to execute the `docker` command.

```bash
 $ make docker
```

This will create a local image for your docker called `agent-docker`.

## Deployment of the agent docker image as a container

To run a Nano-Agent as a container the following steps are required:

1. If you are using a container management system / plan on deploying the container using your CI, add the agent docker image to an accessible registry.
2. If you are planning to manage the agent using the open-appsec UI, then make sure to obtain an agent token from the Management Portal and Enforce.
3. Run the agent with the following command (where -e https_proxy parameter is optional):

`docker run -d --name=agent-container --ipc=host -v=<path to persistent location for agent config>:/etc/cp/conf -v=<path to persistent location for agent data files>:/etc/cp/data -v=<path to persistent location for agent debugs and logs>:/var/log/nano_agent -e https_proxy=<user:password@Proxy address:port> -e registered_server=<server-type> -it <agent-image> /cp-nano-agent [--token <token> | --standalone]`

Example:
```bash
 $ docker run -d --name=agent-container --ipc=host -v=/home/admin/agent/conf:/etc/cp/conf -v=/home/admin/agent/data:/etc/cp/data -v=/home/admin/agent/logs:/var/log/nano_agent –e https_proxy=user:password@1.2.3.4:8080 -e registered_server='nginx' -it agent-docker /cp-nano-agent --standalone
 $ docker ps
CONTAINER ID        IMAGE               COMMAND                          CREATED             STATUS              PORTS               NAMES
1e67f2abbfd4        agent-docker        "/cp-nano-agent --hybrid-mode"   1 minute ago        Up 1 minute                             agent-container
```

 Note that you are not required to use a token from the Management Portal if you are managing your security policy locally. However, you are required to use the --standalone flag in such cases. In addition, the volumes in the command are mandatory only if you wish to have persistency upon restart/upgrade/crash of the agent and its re-execution.
 Lastly, --ipc=host argument is mandatory in order for the agent to have access to shared memory with a protected attachment (NGINX server).

 Supported registered_server are: 
 - NGINX
 - Kong
 - KongLua
 - APISIX
 - Envoy

4. Create or replace the NGINX container using the [Attachment Repository](https://github.com/openappsec/attachment).

This will run a docker container using the agent docker image.

# Contributing
We welcome everyone that wishes to share their knowledge and expertise to enhance and expand the project.

Please see the [Contributing Guidelines](https://github.com/openappsec/openappsec/blob/main/CONTRIBUTING.md).

# Security

### Security Audit
open-appsec code was audited by an independent third party in September-October 2022.
See the [full report](https://github.com/openappsec/openappsec/blob/main/LEXFO-CHP20221014-Report-Code_audit-OPEN-APPSEC-v1.2.pdf).

### Reporting security vulnerabilities
If you've found a vulnerability or a potential vulnerability in open-appsec please let us know at security-alert@openappsec.io. We'll send a confirmation email to acknowledge your report within 24 hours, and we'll send an additional email when we've identified the issue positively or negatively.


# License
open-appsec is open source and available under Apache 2.0 license.

The basic ML model is open source and available under Apache 2.0 license.

The advanced ML model is open source and available under Machine Learning Model license, available upon download in the tar file.
