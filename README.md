# mem-resolver

memresolver is an in-memory golang resolver that allows to override current golang Lookup func literals


## How to use it

Create your custom Lookup function, is it common to overwrite LookupIP, that is the one used by the Dialer so we can redirect custom domains, per example.

```go
func myLookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	// fqdn appends a dot
	if "mycustom.mydomain" == strings.TrimSuffix(host, ".") {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	return net.DefaultResolver.LookupIP(ctx, network, host)
}
```

Once we have our cusotm Lookup function we create a custom `net.Resolver` 

```go
	f := &MemResolver{
		LookupIP: myLookupIP,
	}
	// override lookupIP
	resolver := NewMemoryResolver(f)
```

This custom resolver implements a `Dial` function that can be used to override the `net.Dialer` resolver.

```go
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			Resolver:  resolver,
		}).DialContext,
	}
	client := &http.Client{
		Transport: tr,
	}
```

There is a full example in [example_test.go]