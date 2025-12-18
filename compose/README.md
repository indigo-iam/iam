# Docker compose

This folder contains compose files that are used in testing
and development.

## Submodules

The folder contains a submodule for the [voms-testsuite](https://github.com/italiangrid/voms-testsuite).

If you have already cloned the [indigo-iam](https://github.com/indigo-iam/iam) repo, download the submodule with

```bash
git submodule update --init --recursive
```

(otherwise clone the repo with the `--recurse-submodules` flag). This will populate the [voms-testsuite](./voms-replica/voms-testsuite/) directories.

To update and commit the submodule, type

```bash
git submodule update --remote
git add .
git commit -m "<commit-message>"
git push --recurse-submodules=on-demand
```