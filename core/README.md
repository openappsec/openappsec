# `core`

## Overview
The `core` directory contains code that is used to generate the libraries common to several elements in the system - most notibly the `ngen_core` library.
The code in this directory should not be changed without informing as changes here have a far reaching consequences.

## Important code sections
For the typical developer, the important parts of agent-core are all under the `include` directory, which in turn is divided into several sections:
- `general` - This section covers headers files that impact both attachments and services, for example the communication between services and attachements, or the files related to unit-testing.
- `services_sdk/interfaces` - This section contains the interfaces that are made available for components in services.
  - `services_sdk/interfaces/mock` - This section holds mock objects for the interfaces, to be used in unit-tests.
- `services_sdk/resources` - This section contains capabilities available to components in services in forms other than interfaces (such as creating a log).
- `services_sdk/utilities` - This section contains helper code that can be used to develop components faster - customized containers, etc..
- `include/internal` - This section is meant for internal implementation of the libraries and is less relevant for the typical developer.
-  attachments  - This section holds capabilities used by attachments, such as communicating with their services - so services also have access to them.


## Important Notice
The above mentioned `include` directories have there own sub-directies, which are not described in the `README` file. *Typically you should not include any of these files directly yourself!*
These files serve one of two purposes:
1. Supporting the higher-files - in which case these files will handle the required inclution themselves.
2. Provide a "unsafe" interface - for example, interfaces that are very performance intensive.
Either way, please consult the Infinity Next Agents group before including these files yourself.
