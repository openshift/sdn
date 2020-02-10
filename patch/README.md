# About this folder

This folder is used to patch vendor locally.
We used to do this in glide.lock

**WARNING**: This file must be updated manually

## Changes

### github.com/vishvananda/netlink:

Commit: 0e3b74dbe28f37fd911f9bca3565fdca33c03f29

Diff:
```
vendor/github.com/vishvananda/netlink/link_linux.go
1774c1774
< 			gre.FlowBased = true
---
> 			gre.FlowBased = int8(datum.Value[0]) != 0
```

Files removed: *_test.go nl/*_test.go LICENSE README.md .travis.yml
