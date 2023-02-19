# About
This directory contains an example using the libgraphqlparser C library from [Go](https://golang.org/project/).

For an overview of binding to C libraries in Go, please see the [cgo documentation](https://github.com/golang/go/wiki/cgo).
Specifically, please read the overview of [Function pointer callbacks](https://github.com/golang/go/wiki/cgo#function-pointer-callbacks) in Go and C.

## Building and Running

To build with Go, please ensure that you have `pkg-config` installed for your
system.

Assuming pkg-config has been installed, it should be possible to then build
using Go in the normal fashion:
```sh
$ cd libgraphqlparser/go
$ go build
$ ./go
field : myfield
Example error: 1.18-19: syntax error, unexpected on, expecting ( or @ or {
```
