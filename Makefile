ARCH ?= $(shell uname -m)
LIBC ?= gnu

ifndef BASE
$(error BASE is not set. Please specify BASE branch. e.g., make BASE=main build)
endif

.DEFAULT_GOAL := build

SUPPORTED_ARCH := x86_64 aarch64 riscv64
SUPPORTED_LIBC := gnu musl

ifeq (,$(filter $(ARCH),$(SUPPORTED_ARCH)))
$(error Unsupported ARCH=$(ARCH). Supported: $(SUPPORTED_ARCH))
endif

ifeq (,$(filter $(LIBC),$(SUPPORTED_LIBC)))
$(error Unsupported LIBC=$(LIBC). Supported: $(SUPPORTED_LIBC))
endif

ifeq ($(filter x86_64,$(ARCH)),x86_64)
TARGET := x86_64-unknown-linux-$(LIBC)
else ifeq ($(filter aarch64,$(ARCH)),aarch64)
TARGET := aarch64-unknown-linux-$(LIBC)
else ifeq ($(filter riscv64,$(ARCH)),riscv64)
TARGET := riscv64gc-unknown-linux-$(LIBC)
endif

FEATURES :=
ifeq ($(filter riscv64,$(ARCH)),riscv64)
FEATURES := --no-default-features --features kvm
else ifeq ($(filter aarch64,$(ARCH)),aarch64)
FEATURES := --no-default-features --features kvm
endif

COMMITS := $(shell git rev-list $(BASE)..HEAD)

.PHONY: build
build:
	@echo "================================================================"
	@echo " Building current commit"
	@echo " Arch  : $(ARCH)"
	@echo " Target: $(TARGET)"
	@echo "================================================================"
	cargo check $(FEATURE_ARGS) --tests --examples --all --target=$(TARGET)

.PHONY: check
check:
	@echo "================================================================"
	@echo " Static checks (fmt + clippy)"
	@echo " Arch  : $(ARCH)"
	@echo " Target: $(TARGET)"
	@echo "================================================================"
	cargo +nightly fmt --all -- --check
	cargo clippy $(FEATURE_ARGS) --locked --all --all-targets --tests --examples -- -D warnings

.PHONY: bisect-check
bisect-check:
	@echo "================================================================"
	@echo " Bisectability Check"
	@echo " Base branch: $(BASE)"
	@echo " Arch       : $(ARCH)"
	@echo " Target     : $(TARGET)"
	@echo " Commits    : $(COMMITS)"
	@echo "================================================================"
	@if test -n "$(shell git status --porcelain)"; then \
		echo "Working tree not clean. Please commit changes."; \
		exit 1; \
	fi
	@$(MAKE) _bisect-loop COMMITS="$(COMMITS)" TARGET="$(TARGET)"

.PHONY: _bisect-loop
_bisect-loop:
	@original_branch=$$(git symbolic-ref --quiet --short HEAD || git rev-parse --short HEAD); \
	for commit in $(COMMITS); do \
		echo ""; \
		echo "================================================================"; \
		echo " Checking commit $$commit"; \
		echo "================================================================"; \
		git checkout $$commit >/dev/null 2>&1; \
		if ! $(MAKE) _check-one-commit TARGET="$(TARGET)"; then \
			echo ""; \
			echo "Bisect failed at commit $$commit"; \
			echo "Restoring original HEAD..."; \
			git checkout $$current_sha >/dev/null; \
			exit 1; \
		fi; \
	done; \
	echo ""; \
	echo "All commits passed bisectability check"; \
	echo "Restoring to original branch..."; \
	git checkout $$original_branch >/dev/null

.PHONY: _check-one-commit
_check-one-commit:
	@echo "Running commit checks..."
	$(MAKE) build
	$(MAKE) check
