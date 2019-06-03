# Linux-loader

## Short-description

* Parsing and loading vmlinux (raw ELF image) and bzImage images
* Linux command line parsing and generation
* Definitions and helpers for the Linux boot protocol

## How to build

```
cd linux-loader
cargo build
```

## Tests

Our Continuous Integration (CI) pipeline is implemented on top of
[Buildkite](https://buildkite.com/).
For the complete list of tests, check our
[CI pipeline](https://buildkite.com/rust-vmm/vm-virtio-ci).

Each individual test runs in a container. To reproduce a test locally, you can
use the dev-container on both x86 and arm64.

```bash
docker run -it \
           --security-opt seccomp=unconfined \
           --volume $(pwd):/linux-loader \
           fandree/rust-vmm-dev
cd linux-loader/
cargo test
```

### Test Profiles

The integration tests support two test profiles:
- **devel**: this is the recommended profile for running the integration tests
  on a local development machine.
- **ci** (default option): this is the profile used when running the
  integration tests as part of the the Continuous Integration (CI).

The test profiles are applicable to tests that run using pytest. Currently only
the [coverage test](tests/test_coverage.py) follows this model as all the other
integration tests are run using the
[Buildkite pipeline](https://buildkite.com/rust-vmm/vm-virtio-ci).

The difference between is declaring tests as passed or failed:
- with the **devel** profile the coverage test passes if the current coverage
  is equal or higher than the upstream coverage value. In case the current
  coverage is higher, the coverage file is updated to the new coverage value.
- with the **ci** profile the coverage test passes only if the current coverage
  is equal to the upstream coverage value.

Further details about the coverage test can be found in the
[Adaptive Coverage](#adaptive-coverage) section.

### Adaptive Coverage

The line coverage is saved in [tests/coverage](tests/coverage). To update the
coverage before submitting a PR, run the coverage test:

```bash
docker run -it \
           --security-opt seccomp=unconfined \
           --volume $(pwd):/linux-loader \
           fandree/rust-vmm-dev
cd linux-loader/
pytest --profile=devel tests/test_coverage.py
```

If the PR coverage is higher than the upstream coverage, the coverage file
needs to be manually added to the commit before submitting the PR:

```bash
git add tests/coverage
```

Failing to do so will generate a fail on the CI pipeline when publishing the
PR.

**NOTE:** The coverage file is only updated in the `devel` test profile. In
the `ci` profile the coverage test will fail if the current coverage is higher
than the coverage reported in [tests/coverage](tests/coverage).

### bzImage test

As we don't want to distribute an entire kernel bzImage, the `load_bzImage` test is ignored by
default. In order to test the bzImage support, one needs to locally build a bzImage, copy it
to the `src/loader` directory and run the ignored test:

```shell
# Assuming your linux-loader and linux-stable are both under $LINUX_LOADER
$ git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git $LINUX_LOADER/linux-stable
$ cd linux-stable
$ make bzImage 
$ cp linux-stable/arch/x86/boot/bzImage $LINUX_LOADER/linux-loader/src/loader/
$ cd $LINUX_LOADER/linux-loader
$ docker run -it \
           --security-opt seccomp=unconfined \
           --volume $(pwd):/linux-loader \
           fandree/rust-vmm-dev
$ cd linux-loader/
$ cargo test -- --ignored
```
