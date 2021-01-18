# Man-in-the-Middle Proxy 

For lack of simpler, cleaner forward proxies that MITM in Go...

## Certificate Authority

The CA is generated at startup, and can be saved to disk to be loaded for the 
next instances. Alternatively, valid cert and keys can be passed in as flags


## Run

`go run cmd/main.go`