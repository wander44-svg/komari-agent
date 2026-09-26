# Workflow notes

Komari Agent is a Linux-only monitoring agent. Every build and release workflow
must produce exactly these two binaries:

- `komari-agent-linux-amd64`
- `komari-agent-linux-arm64`

The active development branch is `komari-optimal`. Snapshot builds run from that
branch and create a `Snapshot-yymmddhhMM` prerelease. Stable binaries are attached
to a published non-prerelease tag. The embedded version variable is:

```sh
-X github.com/komari-monitor/komari-agent/version.CurrentVersion=${VERSION}
```

The agent intentionally has no self-update mechanism. Deploying a newer binary
is handled by the installer or by replacing the container image.

Before changing a workflow, verify that:

- only Linux AMD64 and ARM64 targets are built;
- snapshot jobs validate `refs/heads/komari-optimal` before publishing;
- stable release jobs do not run for prereleases;
- asset names stay compatible with `install.sh`;
- no workflow references the removed `update` package.
