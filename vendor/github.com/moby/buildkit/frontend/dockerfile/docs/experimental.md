# Dockerfile frontend experimental syntaxes

## Note for Docker users

If you are using Docker v18.06 or later, BuildKit mode can be enabled by setting `export DOCKER_BUILDKIT=1` on the client side.
Docker v18.06 also requires the daemon to be [running in experimental mode](https://docs.docker.com/engine/reference/commandline/dockerd/#description).

You need to use `docker build` CLI instead of `buildctl` CLI mentioned in this document.
See [the `docker build` document](https://docs.docker.com/engine/reference/commandline/build/) for the usage.

## Use experimental Dockerfile frontend
The features mentioned in this document are experimentally available as [`docker/dockerfile-upstream:experimental`](https://hub.docker.com/r/docker/dockerfile-upstream/tags/) image.

To use the experimental features, the first line of your Dockerfile needs to be `# syntax=docker/dockerfile-upstream:experimental`.
As the experimental syntaxes may change in future revisions, you may want to pin the image to a specific revision.

See also [#528](https://github.com/moby/buildkit/issues/528) for further information about planned `docker/dockerfile` releases.

## Experimental syntaxes

### `RUN --mount=type=bind` (the default mount type)

This mount type allows binding directories (read-only) in the context or in an image to the build container.

|Option               |Description|
|---------------------|-----------|
|`target` (required)  | Mount path.|
|`source`             | Source path in the `from`. Defaults to the root of the `from`.|
|`from`               | Build stage or image name for the root of the source. Defaults to the build context.|


### `RUN --mount=type=cache`

This mount type allows the build container to cache directories for compilers and package managers.

|Option               |Description|
|---------------------|-----------|
|`id`                 | Optional ID to identify separate/different caches|
|`target` (required)  | Mount path.|
|`ro`,`readonly`      | Read-only if set.|
|`sharing`            | One of `shared`, `private`, or `locked`. Defaults to `shared`. A `shared` cache mount can be used concurrently by multiple writers. `private` creates a new mount if there are multiple writers. `locked` pauses the second writer until the first one releases the mount.|


#### Example: cache Go packages

```dockerfile
# syntax = docker/dockerfile-upstream:experimental
FROM golang
...
RUN --mount=type=cache,target=/root/.cache/go-build go build ...
```

#### Example: cache apt packages

```dockerfile
# syntax = docker/dockerfile-upstream:experimental
FROM ubuntu
RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache
RUN --mount=type=cache,target=/var/cache/apt --mount=type=cache,target=/var/lib/apt \
  apt update && apt install -y gcc
```

### `RUN --mount=type=tmpfs`

This mount type allows mounting tmpfs in the build container.

|Option               |Description|
|---------------------|-----------|
|`target` (required)  | Mount path.|


### `RUN --mount=type=secret`

This mount type allows the build container to access secure files such as private keys without baking them into the image.

|Option               |Description|
|---------------------|-----------|
|`id`                 | ID of the secret. Defaults to basename of the target path.|
|`target`             | Mount path. Defaults to `/run/secrets/` + `id`.|
|`required`           | If set to `true`, the instruction errors out when the secret is unavailable. Defaults to `false`.|


#### Example: access to S3

```dockerfile
# syntax = docker/dockerfile-upstream:experimental
FROM python:3
RUN pip install awscli
RUN --mount=type=secret,id=aws,target=/root/.aws/credentials aws s3 cp s3://... ...
```

```console
$ buildctl build --frontend=dockerfile.v0 --local context=. --local dockerfile=. \
  --secret id=aws,src=$HOME/.aws/credentials
```

### `RUN --mount=type=ssh`

This mount type allows the build container to access SSH keys via SSH agents, with support for passphrases.

|Option               |Description|
|---------------------|-----------|
|`id`                 | ID of SSH agent socket or key. Defaults to "default".|
|`target`             | SSH agent socket path. Defaults to `/run/buildkit/ssh_agent.${N}`.|
|`required`           | If set to `true`, the instruction errors out when the key is unavailable. Defaults to `false`.|


#### Example: access to Gitlab

```dockerfile
# syntax = docker/dockerfile-upstream:experimental
FROM alpine
RUN apk add --no-cache openssh-client
RUN mkdir -p -m 0700 ~/.ssh && ssh-keyscan gitlab.com >> ~/.ssh/known_hosts
RUN --mount=type=ssh ssh git@gitlab.com | tee /hello
# "Welcome to GitLab, @GITLAB_USERNAME_ASSOCIATED_WITH_SSHKEY" should be printed here
```

```console
$ eval $(ssh-agent)
$ ssh-add ~/.ssh/id_rsa
(Input your passphrase here)
$ buildctl build --frontend=dockerfile.v0 --local context=. --local dockerfile=. \
  --ssh default=$SSH_AUTH_SOCK
```

You can also specify a path to `*.pem` file on the host directly instead of `$SSH_AUTH_SOCK`.
However, pem files with passphrases are not supported.

