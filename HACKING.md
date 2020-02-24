## How to do a Kubernetes rebase 

First off, wait for someone else to start the origin rebase. It will
make things easier...

### Creating a new branch in our local kubernetes repo

1. Grab https://github.com/openshift/kubernetes and check out a new
   branch named
   `sdn-${OPENSHIFT_RELEASE_NUMBER}-kubernetes-${KUBERNETES_RELEASE_NUMBER}`,
   based on the latest upstream release/pre-release tag. eg, the first
   rebase attempt for OCP 4.3 was the branch
   `sdn-4.3-kubernetes-1.16.0-beta.2`, based off the upstream tag
   `v1.16.0-beta.2`. The `${OPENSHIFT_RELEASE_NUMBER}` should just be
   `MAJOR.MINOR`, but the `${KUBERNETES_RELEASE_NUMBER}` should be
   exactly the name of the upstream tag you used, minus the initial
   "`v`".

3. Peruse the previous release's branch using your favorite git tool.
   If you're not sure what branch that is, look in [sdn's
   `glide.yaml`](./glide.yaml):

       ...
       - package: k8s.io/kubernetes
         repo:    https://github.com/openshift/kubernetes.git
         version: sdn-4.2-kubernetes-1.14.0
       ...

   So, eg, [that branch in
   `openshift/kubernetes`](https://github.com/openshift/kubernetes/commits/sdn-4.2-kubernetes-1.14.0)
   looks like:

       89abaaf762 (origin/sdn-4.2-kubernetes-1.14.0) Merge pull request #70 from squeed/openshift-4.2-fix-unidling
       1dfd96da53 UPSTREAM: <carry>: Allow low-level tweaking of proxy sync flow
       42eb726769 UPSTREAM: 71735: proxy/userspace: respect minSyncInterval
       f409845764 UPSTREAM: 74027: proxy: add some useful metrics
       64a1883466 UPSTREAM: 78428:Capture stderr output and write it to buffer on error
       dd6811c547 UPSTREAM: 78428:Discard stderr output when calling iptables-save
       d5a5dbeeb5 UPSTREAM: 78428:Better error message if panic occurs during iptables-save output parsing
       dbf92ac7e1 UPSTREAM: 77303: Update iptables.IsNotFoundError for iptables-nft error messages
       9bb96ce068 UPSTREAM: <carry>: kube-proxy: make wiring in kubeproxy easy until we sort out config
   
       641856db18 (tag: v1.14.0) Merge pull request #75530 from logicalhan/automated-cherry-pick-of-#75529-upstream-release-1.14
       ...

4. Look through all of the upstream commits on the previous branch:
   you should be able to drop all of the commits marked `<drop>`
   (which there may not be any of), but still need to carry forward
   all of the commits marked `<carry>`. For the commits tagged with
   (upstream kubernetes) bug numbers, you need to see if they have
   been merged in the new branch already or not. (If this is a rebase
   to a new major release, then they should all have been merged
   upstream already.)

5. Cherry-pick the commits you need to [the new
   branch](https://github.com/openshift/kubernetes/commits/sdn-4.3-kubernetes-1.16.0-beta.2):

       00686ab296 (sdn-4.3-kubernetes-1.16.0-beta.2) UPSTREAM: <carry>: Allow low-level tweaking of proxy sync flow
       d7cd27b93a UPSTREAM: <carry>: kube-proxy: make wiring in kubeproxy easy until we sort out config
    
       48ca054dab (tag: v1.16.0-beta.2) Merge remote-tracking branch 'origin/master' into release-1.16

6. Run "make" to ensure it still compiles with the carried patches.

7. Push the new branch to `openshift/kubernetes`. If you don't have
   permission to do this, then push it to your own fork, then get
   someone else with more permissions to pull your branch and then
   push it to `openshift/kubernetes`. (You can't just file a PR
   because that would be trying to merge your branch on to some other
   existing branch, rather than tryign to create a new one.)

### Updating the sdn repo dependencies

1. Update the kubernetes dependencies in `glide.yaml`. For
   `k8s.io/kubernetes` itself that means updating it to point to your
   new branch. For everything else, it means updating to a branch/tag
   that matches what you rebased `k8s.io/kubernetes` to. You should not
   need to create special sdn/openshift-specific branches of anything
   besides `k8s.io/kubernetes`.

   (For kubernetes dependencies that depend on a commit SHA rather
   than a branch or tag, see step 2.)

   Occasionally, if you're rebasing to a prerelease version, one of
   the repos will not have the correct branch/tag yet. In that case,
   look at the repo, and see if there's another recent tag (eg, from
   the previous beta) or else see if `master` can reasonably be used.
   If you do this leave a `# FIXME` comment in `glide.yaml`.

   If you get to the final rebase (ie, `.0`, no `beta` or `rc`) and
   there's some module where there's still no appropriate tag, then
   it's better to depend on the commit SHA of the current master
   rather than actually depending on `master`.

2. Update the remaining kubernetes and openshift dependencies in
   `glide.yaml`. For dependencies under `github.com/openshift/`, and
   for kubernetes dependencies where we currently depend on a specific
   commit SHA, see what version is now being used by the origin
   rebase, and use that. (This is why you waited until after someone
   started the origin rebase...)

3. Try it out... run

       make update-deps

   And hopefully this will work. But probably it won't. If it fails,
   look back through the messages glide printed while it was running
   and see what repos it complained about, and try to figure out how
   to resolve it.

   Sometimes you will get errors like:

       [ERROR]	Error scanning k8s.io/kubernetes/pkg/kubelet/apis/cri: cannot find package "." in:
       	/home/danw/.glide/cache/src/https-github.com-openshift-kubernetes.git/pkg/kubelet/apis/cri

   That means that some part of `openshift/sdn` is trying to pull in
   some package that no longer exists in one of its dependencies.
   You'll need to figure out what happened with that package, and fix
   our code accordingly. (eg, in this case,
   `k8s.io/kubernetes/pkg/kubelet/apis/cri` moved to
   `k8s.io/cri-api/pkg/apis`, so several files in `pkg/network/node`
   had to be updated to point to the new place.)

   Once glide completes successfully, do:

       git add glide.yaml glide.lock vendor
       git commit -m bump

   (Don't commit any code changes yet.)

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
if glide decides to pull in any new dependencies that aren't listed in
`glide.yaml`, it may pull the git master version of it and get some
code that depends on the master versions of everything else and so
won't compile. In that case, the fix is to explicitly pin that new
module to the right version in `glide.yaml`.

Once you figure out a working set of dependency versions, update
`glide.yaml`, re-run `make update-deps`, and amend the bump commit.
Then commit the corresponding code fixes as one or more separate
commits (for ease of review later).

### Figure out if any further updates are needed

Much of the above is generic to any module. For the specific case of
`openshift/sdn`, there are two more things to take care of:

1. [`pkg/openshift-sdn/proxy.go`](./pkg/openshift-sdn/proxy.go) is a
   fork of kubernetes's
   [`cmd/kube-proxy/app/server.go`](./vendor/k8s.io/kubernetes/cmd/kube-proxy/app/server.go)
   /
   [`cmd/kube-proxy/app/server_others.go`](./vendor/k8s.io/kubernetes/cmd/kube-proxy/app/server_others.go).
   You should look through the changes made upstream since the
   previous release and see if any of them need to be copied into our
   fork.

2. Since OpenShift's e2e tests are all run out of the origin repo, if
   there are any new upstream tests that depend on new kube-proxy
   functionality, they will have to be temporarily skipped as part of
   the origin rebase (since the origin rebase commit will be running
   tests against a non-rebased `openshift/sdn` image). After rebasing
   sdn, you should un-skip those tests in the origin repo (after
   making any other necessary fixes in the sdn repo).
