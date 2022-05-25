# If this flag is set to 1, rustup installation needs to exist on the system and
# <arch>-unknown-linux-gnu target is required.
# If this flag is set to 0, distro specific Rust packages will be pulled into the build environment.
%define using_rustup 1
# If this flag is set to 1, <arch>-unknown-linux-musl target is required.
%define using_musl_libc 1
# If this flag is set to 1, the vendored crates archive and cargo.toml need to be prepared and
# offline build is implied. Attached script update_src can be used for the vendorization.
# If this flag is set to 0, access to the internet is required during the build.
%define using_vendored_crates 0

Name:           cloud-hypervisor
Summary:        Cloud Hypervisor is an open source Virtual Machine Monitor (VMM) that runs on top of KVM.
Version:        24.0
Release:        0%{?dist}
License:        ASL 2.0 or BSD-3-clause
Group:          Applications/System
Source0:        https://github.com/cloud-hypervisor/cloud-hypervisor/archive/v%{version}.tar.gz
%if 0%{?using_vendored_crates}
Source1:        vendor.tar.gz
Source2:        config.toml
%endif
ExclusiveArch:  x86_64 aarch64

BuildRequires:  gcc
BuildRequires:  glibc-devel
BuildRequires:  binutils
BuildRequires:  git
BuildRequires:  openssl-devel

%if ! 0%{?using_rustup}
BuildRequires:  rust
BuildRequires:  cargo
%endif

Requires: bash
Requires: glibc
Requires: libgcc
Requires: libcap
 
%ifarch x86_64
%define rust_def_target x86_64-unknown-linux-gnu
%if 0%{?using_musl_libc}
%define rust_musl_target x86_64-unknown-linux-musl
%endif
%endif
%ifarch aarch64
%define rust_def_target aarch64-unknown-linux-gnu
%if 0%{?using_musl_libc}
%define rust_musl_target aarch64-unknown-linux-musl
%endif
%endif

%if 0%{?using_vendored_crates}
%define cargo_offline --offline
%endif

%description
Cloud Hypervisor is an open source Virtual Machine Monitor (VMM) that runs on top of KVM. The project focuses on exclusively running modern, cloud workloads, on top of a limited set of hardware architectures and platforms. Cloud workloads refers to those that are usually run by customers inside a cloud provider. For our purposes this means modern Linux* distributions with most I/O handled by paravirtualised devices (i.e. virtio), no requirement for legacy devices and recent CPUs and KVM.

%prep

%setup -q
%if 0%{?using_vendored_crates}
tar xf %{SOURCE1}
mkdir -p .cargo
cp %{SOURCE2} .cargo/
%endif

%install
rm -rf %{buildroot}
install -d %{buildroot}%{_bindir}
install -D -m755  ./target/%{rust_def_target}/release/cloud-hypervisor %{buildroot}%{_bindir}
install -D -m755  ./target/%{rust_def_target}/release/ch-remote %{buildroot}%{_bindir}
install -d %{buildroot}%{_libdir}
install -d %{buildroot}%{_libdir}/cloud-hypervisor
install -D -m755 target/%{rust_def_target}/release/vhost_user_block %{buildroot}%{_libdir}/cloud-hypervisor
install -D -m755 target/%{rust_def_target}/release/vhost_user_net %{buildroot}%{_libdir}/cloud-hypervisor

%if 0%{?using_musl_libc}
install -d %{buildroot}%{_libdir}/cloud-hypervisor/static
install -D -m755 target/%{rust_musl_target}/release/cloud-hypervisor %{buildroot}%{_libdir}/cloud-hypervisor/static
install -D -m755 target/%{rust_musl_target}/release/vhost_user_block %{buildroot}%{_libdir}/cloud-hypervisor/static
install -D -m755 target/%{rust_musl_target}/release/vhost_user_net %{buildroot}%{_libdir}/cloud-hypervisor/static
install -D -m755 target/%{rust_musl_target}/release/ch-remote %{buildroot}%{_libdir}/cloud-hypervisor/static
%endif


%build
cargo_version=$(cargo --version)
if [[ $? -ne 0 ]]; then
	echo "Cargo not found, please install cargo. exiting"
	exit 0
fi

%if 0%{?using_rustup}
which rustup
if [[ $? -ne 0 ]]; then
	echo "Rustup not found please install rustup #curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
fi
%endif

echo ${cargo_version}

%if 0%{?using_rustup}
rustup target list --installed | grep -e "%{rust_def_target}"
if [[ $? -ne 0 ]]; then
         echo "Target  %{rust_def_target} not found, please install(#rustup target add %{rust_def_target}). exiting"
fi
	%if 0%{?using_musl_libc}
rustup target list --installed | grep -e "%{rust_musl_target}"
if [[ $? -ne 0 ]]; then
         echo "Target  %{rust_musl_target} not found, please install(#rustup target add %{rust_musl_target}). exiting"
fi
	%endif
%endif

%if 0%{?using_vendored_crates}
# For vendored build, prepend this so openssl-sys doesn't trigger full OpenSSL build
export OPENSSL_NO_VENDOR=1
%endif
cargo build --release --target=%{rust_def_target} --all %{cargo_offline}
%if 0%{?using_musl_libc}
cargo build --release --target=%{rust_musl_target} --all %{cargo_offline}
%endif


%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/ch-remote
%caps(cap_net_admin=ep) %{_bindir}/cloud-hypervisor
%{_libdir}/cloud-hypervisor/vhost_user_block
%caps(cap_net_admin=ep) %{_libdir}/cloud-hypervisor/vhost_user_net
%if 0%{?using_musl_libc}
%{_libdir}/cloud-hypervisor/static/ch-remote
%caps(cap_net_admim=ep) %{_libdir}/cloud-hypervisor/static/cloud-hypervisor
%{_libdir}/cloud-hypervisor/static/vhost_user_block
%caps(cap_net_admin=ep) %{_libdir}/cloud-hypervisor/static/vhost_user_net
%endif
%license LICENSE-APACHE
%license LICENSE-BSD-3-Clause


%changelog
*   Wed May 25 2022 Sebastien Boeuf <sebastien.boeuf@intel.com> 24.0-0
-   Update to 24.0

*   Tue May 18 2022 Anatol Belski <anbelski@linux.microsoft.com> - 23.1-0
-   Update to 23.1
-   Add support for aarch64 build
-   Add offline build configuration using vendored crates
-   Fix dependency for openssl-sys

*   Thu Apr 13 2022 Rob Bradford <robert.bradford@intel.com> 23.0-0
-   Update to 23.0

*   Thu Mar 03 2022 Rob Bradford <robert.bradford@intel.com> 22.0-0
-   Update to 22.0

*   Thu Jan 20 2022 Rob Bradford <robert.bradford@intel.com> 21.0-0
-   Update to 21.0

*   Thu Dec 02 2021 Sebastien Boeuf <sebastien.boeuf@intel.com> 20.0-0
-   Update to 20.0

*   Mon Nov 08 2021 Fabiano Fidêncio <fabiano.fidencio@intel.com> 19.0-0
-   Update to 19.0

*   Fri May 28 2021 Muminul Islam <muislam@microsoft.com> 15.0-0
-   Update version to 15.0

*   Wed Jul 22 2020 Muminul Islam <muislam@microsoft.com> 0.8.0-0
-   Initial version
