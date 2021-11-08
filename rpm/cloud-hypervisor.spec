# This spec file assumes you're building on an environment where:
# * You have access to the internet during the build
# * You have rustup installed on your system
# * You have both x86_64-unknown-linux-gnu and  x86_64-unknown-linux-musl
#   targets installed.

%define using_rustup 1

Name:           cloud-hypervisor
Summary:        Cloud Hypervisor is an open source Virtual Machine Monitor (VMM) that runs on top of KVM.
Version:        19.0
Release:        0%{?dist}
License:        ASL 2.0 or BSD-3-clause
Group:          Applications/System
Source0:        https://github.com/cloud-hypervisor/cloud-hypervisor/archive/v%{version}.tar.gz
ExclusiveArch:  x86_64

BuildRequires:  gcc
BuildRequires:  glibc-devel
BuildRequires:  binutils
BuildRequires:  git

%if ! 0%{?using_rustup}
BuildRequires:  rust
BuildRequires:  cargo
%endif

Requires: bash
Requires: glibc
Requires: libgcc
Requires: libcap
 
%description
Cloud Hypervisor is an open source Virtual Machine Monitor (VMM) that runs on top of KVM. The project focuses on exclusively running modern, cloud workloads, on top of a limited set of hardware architectures and platforms. Cloud workloads refers to those that are usually run by customers inside a cloud provider. For our purposes this means modern Linux* distributions with most I/O handled by paravirtualised devices (i.e. virtio), no requirement for legacy devices and recent CPUs and KVM.

%prep

%setup -q

%install
rm -rf %{buildroot}
install -d %{buildroot}%{_bindir}
install -D -m755  ./target/x86_64-unknown-linux-gnu/release/cloud-hypervisor %{buildroot}%{_bindir}
install -D -m755  ./target/x86_64-unknown-linux-gnu/release/ch-remote %{buildroot}%{_bindir}
install -d %{buildroot}%{_libdir}
install -d %{buildroot}%{_libdir}/cloud-hypervisor
install -D -m755 target/x86_64-unknown-linux-gnu/release/vhost_user_block %{buildroot}%{_libdir}/cloud-hypervisor
install -D -m755 target/x86_64-unknown-linux-gnu/release/vhost_user_net %{buildroot}%{_libdir}/cloud-hypervisor

install -d %{buildroot}%{_libdir}/cloud-hypervisor/static
install -D -m755 target/x86_64-unknown-linux-musl/release/cloud-hypervisor %{buildroot}%{_libdir}/cloud-hypervisor/static
install -D -m755 target/x86_64-unknown-linux-musl/release/vhost_user_block %{buildroot}%{_libdir}/cloud-hypervisor/static
install -D -m755 target/x86_64-unknown-linux-musl/release/vhost_user_net %{buildroot}%{_libdir}/cloud-hypervisor/static
install -D -m755 target/x86_64-unknown-linux-musl/release/ch-remote %{buildroot}%{_libdir}/cloud-hypervisor/static


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
rustup target list --installed | grep x86_64-unknown-linux-gnu
if [[ $? -ne 0 ]]; then
         echo "Target  x86_64-unknown-linux-gnu not found, please install(#rustup target add x86_64-unknown-linux-gnu). exiting"
fi
rustup target list --installed | grep x86_64-unknown-linux-musl
if [[ $? -ne 0 ]]; then
         echo "Target  x86_64-unknown-linux-musl not found, please install(#rustup target add x86_64-unknown-linux-musl). exiting"
fi
%endif

cargo build --release --target=x86_64-unknown-linux-gnu --all
cargo build --release --target=x86_64-unknown-linux-musl --all


%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_bindir}/*
%{_libdir}/cloud-hypervisor
%license LICENSE-APACHE
%license LICENSE-BSD-3-Clause

%post
setcap cap_net_admin+ep %{_bindir}/cloud-hypervisor
setcap cap_net_admin+ep %{_libdir}/cloud-hypervisor/vhost_user_net
setcap cap_net_admin+ep %{_libdir}/cloud-hypervisor/static/cloud-hypervisor
setcap cap_net_admin+ep %{_libdir}/cloud-hypervisor/static/vhost_user_net


%changelog
*   Mon Nov 08 2021 Fabiano Fidêncio <fabiano.fidencio@intel.com> 19.0-0
-   Update to 19.0

*   Fri May 28 2021 Muminul Islam <muislam@microsoft.com> 15.0-0
-   Update version to 15.0

*   Wed Jul 22 2020 Muminul Islam <muislam@microsoft.com> 0.8.0-0
-   Initial version
