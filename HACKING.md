## How to do a Kubernetes rebase

First off, wait for someone else to start the origin rebase. It will
make things easier...

### Creating a new branch in our local kubernetes repo

1. Grab https://github.com/openshift/kubernetes and check out a new
   branch named
   `sdn-${OPENSHIFT_RELEASE_NUMBER}-kubernetes-${KUBERNETES_RELEASE_NUMBER}`,
   based on the latest upstream release/pre-release tag. eg, the first
   rebase attempt for OCP 4.4 was the branch
   `sdn-4.4-kubernetes-1.17.2`, based off the upstream tag
   `v1.17.2`. The `${OPENSHIFT_RELEASE_NUMBER}` should just be
   `MAJOR.MINOR`, but the `${KUBERNETES_RELEASE_NUMBER}` should be
   exactly the name of the upstream tag you used, minus the initial
   "`v`". Sometimes https://github.com/openshift/kubernetes won't have all the
   tags, make sure to get the latest tag from
   https://github.com/kubernetes/kubernetes 

3. Peruse the previous release's branch using your favorite git tool.
   If you're not sure what branch that is, look in [sdn's
   `go.mod`](./go.mod):

       ...
         [...]
         replace (
            [...]
            k8s.io/kubernetes => github.com/openshift/kubernetes v1.17.0-alpha.0.0.20190924141618-7eb200efda20
            [...]
         )
       ...

   Unfortunately, `go mod` will autogenerate the version in a non
   human-friendly way, in this case, `7eb200efda20` is the commit number.
   One way to see the branch is going to the github.com/openshift/kubernetes
   repository, and check the log for it:
   `git log --oneline --decorate 7eb200efda20`

   So, eg, [that branch in
   openshift/kubernetes](https://github.com/openshift/kubernetes/commits/sdn-4.4-kubernetes-1.17.2) looks like:

       $  git log --oneline --decorate=no 7eb200efda2 | head -5
       7eb200efda2 UPSTREAM: <carry>: kube-proxy: make wiring in kubeproxy easy until we sort out config
       f92ec1095b1 UPSTREAM: <carry>: Allow low-level tweaking of proxy sync flow
       2bd9643cee5 Add/Update CHANGELOG-1.16.md for v1.16.0-rc.2.
       4cb51f0d2d8 Merge pull request #82688 from dims/automated-cherry-pick-of-#82669-upstream-release-1.16
       101ecd704d9 Merge pull request #82658 from liggitt/automated-cherry-pick-of-#82653-upstream-release-1.16

4. Look through all of the upstream commits on the previous branch:
   you should be able to drop all of the commits marked `<drop>`
   (which there may not be any of), but still need to carry forward
   all of the commits marked `<carry>`. For the commits tagged with
   (upstream kubernetes) bug numbers, you need to see if they have
   been merged in the new branch already or not. (If this is a rebase
   to a new major release, then they should all have been merged
   upstream already.)

5. Cherry-pick the commits you need to [the new
   branch](https://github.com/openshift/kubernetes/tree/sdn-4.4-kubernetes-1.17.2):

       7a71bf4afe8 (sdn-4.4-kubernetes-1.17.2) UPSTREAM: <carry>: kube-proxy: make wiring in kubeproxy easy until we sort out config
       4a62e82fa9c UPSTREAM: <carry>: Allow low-level tweaking of proxy sync flow
       59603c6e503 (tag: v1.17.2) Merge pull request #87334 from justaugustus/cl-117-bump-tag


6. Run "make" to ensure it still compiles with the carried patches.

7. Push the new branch to `openshift/kubernetes`. If you don't have
   permission to do this, then push it to your own fork, then get
   someone else with more permissions to pull your branch and then
   push it to `openshift/kubernetes`. (You can't just file a PR
   because that would be trying to merge your branch on to some other
   existing branch, rather than tryign to create a new one.)

### Updating the sdn repo dependencies

1. Update the kubernetes dependencies in `go.mod`. Because `k8s.io/kubernetes`
   [wasn't designed to be used as a go module](https://github.com/golang/go/issues/26366)
   we need to do  some hacks.

   First we need to update kubernetes itself, in go.mod, the dependencies on
   the require section **must** point to a version that exists on that module
   upstream. This means picking whatever is the closest to whatever you need,
   for the k8s.io/* dependencies, for the 1.17.2 I used v1.17.2, but don't
   worry too much about this because we'll actually define the dependency on
   the replace section and `go mod tidy` will change whatever you write anyway.

   The replace section is where we define what is the dependency which will
   really be vendored. All the modules that are part of kubernetes must be
   replaced to point to their path in kubernetes. These depdendencies can be
   easily found out with grep:

       $ cat go.mod | grep -e  replace -e staging | grep -v sigs.k8s.io/yaml
       replace (

      	k8s.io/api => github.com/openshift/kubernetes/staging/src/k8s.io/api v0.0.0-20190924141618-7eb200efda20
	
         k8s.io/apiextensions-apiserver => github.com/openshift/kubernetes/staging/src/k8s.io/apiextensions-apiserver v0.0.0-20190924141618-7eb200efda20
	      k8s.io/apimachinery => github.com/openshift/kubernetes/staging/src/k8s.io/apimachinery v0.0.0-20190924141618-7eb200efda20
	      k8s.io/apiserver => github.com/openshift/kubernetes/staging/src/k8s.io/apiserver v0.0.0-20190924141618-7eb200efda20
         ...
   
   We need to replace the version, in this case
   `v0.0.0-20190924141618-7eb200efda20`, with the correct branch. I used sed:
   
       sed -i 's/v0.0.0-20190924141618-7eb200efda20/sdn-4.4-kubernetes-1.17.2/g' go.mod

   You shouldn't need to update the rest of the dependencies unless there are
   conflicts.

2. Update `go.mod` and `go.lock` and the vendor directory using:
   
       make update-deps-overrides
   
   Which at a lower level executes:

       go mod tidy && go mod vendor && go mod verify

   This should work but it may not, if you get any errors, run the steps
   individually and good luck. Try modifying go.mod and repeat until it works.

3. Update non kubernetes dependencies in `go.mod`. If some of the dependencies
   kubernetes are used by kubernetes as well, there is a chance that
   `make update-deps-overrides` has modified them as well. If this breaks
   something you can overwrite the version in the `replace` section of
   `go.mod`.

4. Repeat steap 2: `make update-deps-overrides`

### Updating the code

At this point you have updated dependencies, but possibly old code.
Now try `make` and see what happens.

Most likely you will need various minor tweaks throughout the code to
deal with small API changes upstream.

In some cases, you may run into compile problems in vendored code
because you ended up with an incompatible set of modules. (Eg, in the
4.2 to 4.3 rebase, I had to update the requested version of
`github.com/vishvananda/netlink` to be compatible with the newer
version of `golang.org/x/sys` that was required by other
dependencies.)

Another thing that can happen (especially in the final rebase) is that
if go mod decides to pull in any new dependencies that aren't listed in
`go.mod` or `go.lock`, it may pull a version incompatible with other
some other module and so won't compile.
In that case, the fix is to explicitly pin the two incompatible modules
to compatible versions in the `replace` section of go.mod. This may not be
possible without code changes.

Once you figure out a working set of dependency versions, update
`go.mod`, re-run `make update-deps-overrides`, and amend the bump commit.
Then commit the corresponding code fixes as one or more separate
commits (for ease of review later).

### Figure out if any further updates are needed

Much of the above is generic to any module. For the specific case of
`openshift/sdn`, there are two more things to take care of:

1. [`pkg/cmd/openshift-sdn-node/kube_proxy.go`](./pkg/cmd/openshift-sdn-node/kube_proxy.go) is a
   fork of kubernetes's
   [`cmd/kube-proxy/app/server.go`](./vendor/k8s.io/kubernetes/cmd/kube-proxy/app/server.go)
   /
   [`cmd/kube-proxy/app/server_others.go`](./vendor/k8s.io/kubernetes/cmd/kube-proxy/app/server_others.go).
   You should look through the changes made upstream since the
   previous release and see if any of them need to be copied into our
   fork.
   A good way to see the deltas between two release for example between 1.25.0 and 1.26.0,
   run the following command from your upstream kuberenetes repo created at the begining of this
   process.

   ```bash
   git diff v1.25.0 v1.26.0 -- cmd/kube-proxy
   ```

   On kube_proxy.go you should also pay special attention to metrics, as we
   expect to have some problems in the near future with the
   [metrics handler](https://github.com/openshift/sdn/pull/114).

2. Since OpenShift's e2e tests are all run out of the origin repo, if
   there are any new upstream tests that depend on new kube-proxy
   functionality, they will have to be temporarily skipped as part of
   the origin rebase (since the origin rebase commit will be running
   tests against a non-rebased `openshift/sdn` image). After rebasing
   sdn, you should un-skip those tests in the origin repo (after
   making any other necessary fixes in the sdn repo).