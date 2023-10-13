// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use api_client::simple_api_command;
use api_client::simple_api_command_with_fds;
use api_client::simple_api_full_command;
use api_client::Error as ApiClientError;
use clap::{Arg, ArgAction, ArgMatches, Command};
use option_parser::{ByteSized, ByteSizedParseError};
use std::fmt;
use std::io::Read;
use std::marker::PhantomData;
use std::os::unix::net::UnixStream;
use std::process;
#[cfg(feature = "dbus_api")]
use zbus::{dbus_proxy, zvariant::Optional};

type ApiResult = Result<(), Error>;

#[derive(Debug)]
enum Error {
    HttpApiClient(ApiClientError),
    #[cfg(feature = "dbus_api")]
    DBusApiClient(zbus::Error),
    InvalidCpuCount(std::num::ParseIntError),
    InvalidMemorySize(ByteSizedParseError),
    InvalidBalloonSize(ByteSizedParseError),
    AddDeviceConfig(vmm::config::Error),
    AddDiskConfig(vmm::config::Error),
    AddFsConfig(vmm::config::Error),
    AddPmemConfig(vmm::config::Error),
    AddNetConfig(vmm::config::Error),
    AddUserDeviceConfig(vmm::config::Error),
    AddVdpaConfig(vmm::config::Error),
    AddVsockConfig(vmm::config::Error),
    Restore(vmm::config::Error),
    ReadingStdin(std::io::Error),
    ReadingFile(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        match self {
            HttpApiClient(e) => e.fmt(f),
            #[cfg(feature = "dbus_api")]
            DBusApiClient(e) => write!(f, "Error D-Bus proxy: {e}"),
            InvalidCpuCount(e) => write!(f, "Error parsing CPU count: {e}"),
            InvalidMemorySize(e) => write!(f, "Error parsing memory size: {e:?}"),
            InvalidBalloonSize(e) => write!(f, "Error parsing balloon size: {e:?}"),
            AddDeviceConfig(e) => write!(f, "Error parsing device syntax: {e}"),
            AddDiskConfig(e) => write!(f, "Error parsing disk syntax: {e}"),
            AddFsConfig(e) => write!(f, "Error parsing filesystem syntax: {e}"),
            AddPmemConfig(e) => write!(f, "Error parsing persistent memory syntax: {e}"),
            AddNetConfig(e) => write!(f, "Error parsing network syntax: {e}"),
            AddUserDeviceConfig(e) => write!(f, "Error parsing user device syntax: {e}"),
            AddVdpaConfig(e) => write!(f, "Error parsing vDPA device syntax: {e}"),
            AddVsockConfig(e) => write!(f, "Error parsing vsock syntax: {e}"),
            Restore(e) => write!(f, "Error parsing restore syntax: {e}"),
            ReadingStdin(e) => write!(f, "Error reading from stdin: {e}"),
            ReadingFile(e) => write!(f, "Error reading from file: {e}"),
        }
    }
}

enum TargetApi<'a> {
    HttpApi(UnixStream, PhantomData<&'a ()>),
    #[cfg(feature = "dbus_api")]
    DBusApi(DBusApi1ProxyBlocking<'a>),
}

#[cfg(feature = "dbus_api")]
#[dbus_proxy(name = "org.cloudhypervisor.DBusApi1", assume_defaults = false)]
trait DBusApi1 {
    fn vmm_ping(&self) -> zbus::Result<String>;
    fn vmm_shutdown(&self) -> zbus::Result<()>;
    fn vm_add_device(&self, device_config: &str) -> zbus::Result<Optional<String>>;
    fn vm_add_disk(&self, disk_config: &str) -> zbus::Result<Optional<String>>;
    fn vm_add_fs(&self, fs_config: &str) -> zbus::Result<Optional<String>>;
    fn vm_add_net(&self, net_config: &str) -> zbus::Result<Optional<String>>;
    fn vm_add_pmem(&self, pmem_config: &str) -> zbus::Result<Optional<String>>;
    fn vm_add_user_device(&self, vm_add_user_device: &str) -> zbus::Result<Optional<String>>;
    fn vm_add_vdpa(&self, vdpa_config: &str) -> zbus::Result<Optional<String>>;
    fn vm_add_vsock(&self, vsock_config: &str) -> zbus::Result<Optional<String>>;
    fn vm_boot(&self) -> zbus::Result<()>;
    fn vm_coredump(&self, vm_coredump_data: &str) -> zbus::Result<()>;
    fn vm_counters(&self) -> zbus::Result<Optional<String>>;
    fn vm_create(&self, vm_config: &str) -> zbus::Result<()>;
    fn vm_delete(&self) -> zbus::Result<()>;
    fn vm_info(&self) -> zbus::Result<String>;
    fn vm_pause(&self) -> zbus::Result<()>;
    fn vm_power_button(&self) -> zbus::Result<()>;
    fn vm_reboot(&self) -> zbus::Result<()>;
    fn vm_remove_device(&self, vm_remove_device: &str) -> zbus::Result<()>;
    fn vm_resize(&self, vm_resize: &str) -> zbus::Result<()>;
    fn vm_resize_zone(&self, vm_resize_zone: &str) -> zbus::Result<()>;
    fn vm_restore(&self, restore_config: &str) -> zbus::Result<()>;
    fn vm_receive_migration(&self, receive_migration_data: &str) -> zbus::Result<()>;
    fn vm_send_migration(&self, receive_migration_data: &str) -> zbus::Result<()>;
    fn vm_resume(&self) -> zbus::Result<()>;
    fn vm_shutdown(&self) -> zbus::Result<()>;
    fn vm_snapshot(&self, vm_snapshot_config: &str) -> zbus::Result<()>;
}

#[cfg(feature = "dbus_api")]
impl<'a> DBusApi1ProxyBlocking<'a> {
    fn new_connection(name: &'a str, path: &'a str, system_bus: bool) -> Result<Self, zbus::Error> {
        let connection = if system_bus {
            zbus::blocking::Connection::system()?
        } else {
            zbus::blocking::Connection::session()?
        };

        Self::builder(&connection)
            .destination(name)?
            .path(path)?
            .build()
    }

    fn print_response(&self, result: zbus::Result<Optional<String>>) -> ApiResult {
        result
            .map(|ret| {
                if let Some(ref output) = *ret {
                    println!("{output}");
                }
            })
            .map_err(Error::DBusApiClient)
    }

    fn api_vmm_ping(&self) -> ApiResult {
        self.vmm_ping()
            .map(|ping| println!("{ping}"))
            .map_err(Error::DBusApiClient)
    }

    fn api_vmm_shutdown(&self) -> ApiResult {
        self.vmm_shutdown().map_err(Error::DBusApiClient)
    }

    fn api_vm_add_device(&self, device_config: &str) -> ApiResult {
        self.print_response(self.vm_add_device(device_config))
    }

    fn api_vm_add_disk(&self, disk_config: &str) -> ApiResult {
        self.print_response(self.vm_add_disk(disk_config))
    }

    fn api_vm_add_fs(&self, fs_config: &str) -> ApiResult {
        self.print_response(self.vm_add_fs(fs_config))
    }

    fn api_vm_add_net(&self, net_config: &str) -> ApiResult {
        self.print_response(self.vm_add_net(net_config))
    }

    fn api_vm_add_pmem(&self, pmem_config: &str) -> ApiResult {
        self.print_response(self.vm_add_pmem(pmem_config))
    }

    fn api_vm_add_user_device(&self, vm_add_user_device: &str) -> ApiResult {
        self.print_response(self.vm_add_user_device(vm_add_user_device))
    }

    fn api_vm_add_vdpa(&self, vdpa_config: &str) -> ApiResult {
        self.print_response(self.vm_add_vdpa(vdpa_config))
    }

    fn api_vm_add_vsock(&self, vsock_config: &str) -> ApiResult {
        self.print_response(self.vm_add_vsock(vsock_config))
    }

    fn api_vm_boot(&self) -> ApiResult {
        self.vm_boot().map_err(Error::DBusApiClient)
    }

    fn api_vm_coredump(&self, vm_coredump_data: &str) -> ApiResult {
        self.vm_coredump(vm_coredump_data)
            .map_err(Error::DBusApiClient)
    }

    fn api_vm_counters(&self) -> ApiResult {
        self.print_response(self.vm_counters())
    }

    fn api_vm_create(&self, vm_config: &str) -> ApiResult {
        self.vm_create(vm_config).map_err(Error::DBusApiClient)
    }

    fn api_vm_delete(&self) -> ApiResult {
        self.vm_delete().map_err(Error::DBusApiClient)
    }

    fn api_vm_info(&self) -> ApiResult {
        self.vm_info()
            .map(|info| println!("{info}"))
            .map_err(Error::DBusApiClient)
    }

    fn api_vm_pause(&self) -> ApiResult {
        self.vm_pause().map_err(Error::DBusApiClient)
    }

    fn api_vm_power_button(&self) -> ApiResult {
        self.vm_power_button().map_err(Error::DBusApiClient)
    }

    fn api_vm_reboot(&self) -> ApiResult {
        self.vm_reboot().map_err(Error::DBusApiClient)
    }

    fn api_vm_remove_device(&self, vm_remove_device: &str) -> ApiResult {
        self.vm_remove_device(vm_remove_device)
            .map_err(Error::DBusApiClient)
    }

    fn api_vm_resize(&self, vm_resize: &str) -> ApiResult {
        self.vm_resize(vm_resize).map_err(Error::DBusApiClient)
    }

    fn api_vm_resize_zone(&self, vm_resize_zone: &str) -> ApiResult {
        self.vm_resize_zone(vm_resize_zone)
            .map_err(Error::DBusApiClient)
    }

    fn api_vm_restore(&self, restore_config: &str) -> ApiResult {
        self.vm_restore(restore_config)
            .map_err(Error::DBusApiClient)
    }

    fn api_vm_receive_migration(&self, receive_migration_data: &str) -> ApiResult {
        self.vm_receive_migration(receive_migration_data)
            .map_err(Error::DBusApiClient)
    }

    fn api_vm_send_migration(&self, send_migration_data: &str) -> ApiResult {
        self.vm_send_migration(send_migration_data)
            .map_err(Error::DBusApiClient)
    }

    fn api_vm_resume(&self) -> ApiResult {
        self.vm_resume().map_err(Error::DBusApiClient)
    }

    fn api_vm_shutdown(&self) -> ApiResult {
        self.vm_shutdown().map_err(Error::DBusApiClient)
    }

    fn api_vm_snapshot(&self, vm_snapshot_config: &str) -> ApiResult {
        self.vm_snapshot(vm_snapshot_config)
            .map_err(Error::DBusApiClient)
    }
}

impl<'a> TargetApi<'a> {
    fn do_command(&mut self, matches: &ArgMatches) -> ApiResult {
        match self {
            Self::HttpApi(api_socket, _) => rest_api_do_command(matches, api_socket),
            #[cfg(feature = "dbus_api")]
            Self::DBusApi(proxy) => dbus_api_do_command(matches, proxy),
        }
    }
}

fn rest_api_do_command(matches: &ArgMatches, socket: &mut UnixStream) -> ApiResult {
    match matches.subcommand_name() {
        Some("boot") => {
            simple_api_command(socket, "PUT", "boot", None).map_err(Error::HttpApiClient)
        }
        Some("delete") => {
            simple_api_command(socket, "PUT", "delete", None).map_err(Error::HttpApiClient)
        }
        Some("shutdown-vmm") => simple_api_full_command(socket, "PUT", "vmm.shutdown", None)
            .map_err(Error::HttpApiClient),
        Some("resume") => {
            simple_api_command(socket, "PUT", "resume", None).map_err(Error::HttpApiClient)
        }
        Some("power-button") => {
            simple_api_command(socket, "PUT", "power-button", None).map_err(Error::HttpApiClient)
        }
        Some("reboot") => {
            simple_api_command(socket, "PUT", "reboot", None).map_err(Error::HttpApiClient)
        }
        Some("pause") => {
            simple_api_command(socket, "PUT", "pause", None).map_err(Error::HttpApiClient)
        }
        Some("info") => {
            simple_api_command(socket, "GET", "info", None).map_err(Error::HttpApiClient)
        }
        Some("counters") => {
            simple_api_command(socket, "GET", "counters", None).map_err(Error::HttpApiClient)
        }
        Some("ping") => {
            simple_api_full_command(socket, "GET", "vmm.ping", None).map_err(Error::HttpApiClient)
        }
        Some("shutdown") => {
            simple_api_command(socket, "PUT", "shutdown", None).map_err(Error::HttpApiClient)
        }
        Some("resize") => {
            let resize = resize_config(
                matches
                    .subcommand_matches("resize")
                    .unwrap()
                    .get_one::<String>("cpus")
                    .map(|x| x as &str),
                matches
                    .subcommand_matches("resize")
                    .unwrap()
                    .get_one::<String>("memory")
                    .map(|x| x as &str),
                matches
                    .subcommand_matches("resize")
                    .unwrap()
                    .get_one::<String>("balloon")
                    .map(|x| x as &str),
            )?;
            simple_api_command(socket, "PUT", "resize", Some(&resize)).map_err(Error::HttpApiClient)
        }
        Some("resize-zone") => {
            let resize_zone = resize_zone_config(
                matches
                    .subcommand_matches("resize-zone")
                    .unwrap()
                    .get_one::<String>("id")
                    .unwrap(),
                matches
                    .subcommand_matches("resize-zone")
                    .unwrap()
                    .get_one::<String>("size")
                    .unwrap(),
            )?;
            simple_api_command(socket, "PUT", "resize-zone", Some(&resize_zone))
                .map_err(Error::HttpApiClient)
        }
        Some("add-device") => {
            let device_config = add_device_config(
                matches
                    .subcommand_matches("add-device")
                    .unwrap()
                    .get_one::<String>("device_config")
                    .unwrap(),
            )?;
            simple_api_command(socket, "PUT", "add-device", Some(&device_config))
                .map_err(Error::HttpApiClient)
        }
        Some("remove-device") => {
            let remove_device_data = remove_device_config(
                matches
                    .subcommand_matches("remove-device")
                    .unwrap()
                    .get_one::<String>("id")
                    .unwrap(),
            );
            simple_api_command(socket, "PUT", "remove-device", Some(&remove_device_data))
                .map_err(Error::HttpApiClient)
        }
        Some("add-disk") => {
            let disk_config = add_disk_config(
                matches
                    .subcommand_matches("add-disk")
                    .unwrap()
                    .get_one::<String>("disk_config")
                    .unwrap(),
            )?;
            simple_api_command(socket, "PUT", "add-disk", Some(&disk_config))
                .map_err(Error::HttpApiClient)
        }
        Some("add-fs") => {
            let fs_config = add_fs_config(
                matches
                    .subcommand_matches("add-fs")
                    .unwrap()
                    .get_one::<String>("fs_config")
                    .unwrap(),
            )?;
            simple_api_command(socket, "PUT", "add-fs", Some(&fs_config))
                .map_err(Error::HttpApiClient)
        }
        Some("add-pmem") => {
            let pmem_config = add_pmem_config(
                matches
                    .subcommand_matches("add-pmem")
                    .unwrap()
                    .get_one::<String>("pmem_config")
                    .unwrap(),
            )?;
            simple_api_command(socket, "PUT", "add-pmem", Some(&pmem_config))
                .map_err(Error::HttpApiClient)
        }
        Some("add-net") => {
            let (net_config, fds) = add_net_config(
                matches
                    .subcommand_matches("add-net")
                    .unwrap()
                    .get_one::<String>("net_config")
                    .unwrap(),
            )?;
            simple_api_command_with_fds(socket, "PUT", "add-net", Some(&net_config), fds)
                .map_err(Error::HttpApiClient)
        }
        Some("add-user-device") => {
            let device_config = add_user_device_config(
                matches
                    .subcommand_matches("add-user-device")
                    .unwrap()
                    .get_one::<String>("device_config")
                    .unwrap(),
            )?;
            simple_api_command(socket, "PUT", "add-user-device", Some(&device_config))
                .map_err(Error::HttpApiClient)
        }
        Some("add-vdpa") => {
            let vdpa_config = add_vdpa_config(
                matches
                    .subcommand_matches("add-vdpa")
                    .unwrap()
                    .get_one::<String>("vdpa_config")
                    .unwrap(),
            )?;
            simple_api_command(socket, "PUT", "add-vdpa", Some(&vdpa_config))
                .map_err(Error::HttpApiClient)
        }
        Some("add-vsock") => {
            let vsock_config = add_vsock_config(
                matches
                    .subcommand_matches("add-vsock")
                    .unwrap()
                    .get_one::<String>("vsock_config")
                    .unwrap(),
            )?;
            simple_api_command(socket, "PUT", "add-vsock", Some(&vsock_config))
                .map_err(Error::HttpApiClient)
        }
        Some("snapshot") => {
            let snapshot_config = snapshot_config(
                matches
                    .subcommand_matches("snapshot")
                    .unwrap()
                    .get_one::<String>("snapshot_config")
                    .unwrap(),
            );
            simple_api_command(socket, "PUT", "snapshot", Some(&snapshot_config))
                .map_err(Error::HttpApiClient)
        }
        Some("restore") => {
            let restore_config = restore_config(
                matches
                    .subcommand_matches("restore")
                    .unwrap()
                    .get_one::<String>("restore_config")
                    .unwrap(),
            )?;
            simple_api_command(socket, "PUT", "restore", Some(&restore_config))
                .map_err(Error::HttpApiClient)
        }
        Some("coredump") => {
            let coredump_config = coredump_config(
                matches
                    .subcommand_matches("coredump")
                    .unwrap()
                    .get_one::<String>("coredump_config")
                    .unwrap(),
            );
            simple_api_command(socket, "PUT", "coredump", Some(&coredump_config))
                .map_err(Error::HttpApiClient)
        }
        Some("send-migration") => {
            let send_migration_data = send_migration_data(
                matches
                    .subcommand_matches("send-migration")
                    .unwrap()
                    .get_one::<String>("send_migration_config")
                    .unwrap(),
                matches
                    .subcommand_matches("send-migration")
                    .unwrap()
                    .get_flag("send_migration_local"),
            );
            simple_api_command(socket, "PUT", "send-migration", Some(&send_migration_data))
                .map_err(Error::HttpApiClient)
        }
        Some("receive-migration") => {
            let receive_migration_data = receive_migration_data(
                matches
                    .subcommand_matches("receive-migration")
                    .unwrap()
                    .get_one::<String>("receive_migration_config")
                    .unwrap(),
            );
            simple_api_command(
                socket,
                "PUT",
                "receive-migration",
                Some(&receive_migration_data),
            )
            .map_err(Error::HttpApiClient)
        }
        Some("create") => {
            let data = create_data(
                matches
                    .subcommand_matches("create")
                    .unwrap()
                    .get_one::<String>("path")
                    .unwrap(),
            )?;
            simple_api_command(socket, "PUT", "create", Some(&data)).map_err(Error::HttpApiClient)
        }
        _ => unreachable!(),
    }
}

#[cfg(feature = "dbus_api")]
fn dbus_api_do_command(matches: &ArgMatches, proxy: &DBusApi1ProxyBlocking<'_>) -> ApiResult {
    match matches.subcommand_name() {
        Some("boot") => proxy.api_vm_boot(),
        Some("delete") => proxy.api_vm_delete(),
        Some("shutdown-vmm") => proxy.api_vmm_shutdown(),
        Some("resume") => proxy.api_vm_resume(),
        Some("power-button") => proxy.api_vm_power_button(),
        Some("reboot") => proxy.api_vm_reboot(),
        Some("pause") => proxy.api_vm_pause(),
        Some("info") => proxy.api_vm_info(),
        Some("counters") => proxy.api_vm_counters(),
        Some("ping") => proxy.api_vmm_ping(),
        Some("shutdown") => proxy.api_vm_shutdown(),
        Some("resize") => {
            let resize = resize_config(
                matches
                    .subcommand_matches("resize")
                    .unwrap()
                    .get_one::<String>("cpus")
                    .map(|x| x as &str),
                matches
                    .subcommand_matches("resize")
                    .unwrap()
                    .get_one::<String>("memory")
                    .map(|x| x as &str),
                matches
                    .subcommand_matches("resize")
                    .unwrap()
                    .get_one::<String>("balloon")
                    .map(|x| x as &str),
            )?;
            proxy.api_vm_resize(&resize)
        }
        Some("resize-zone") => {
            let resize_zone = resize_zone_config(
                matches
                    .subcommand_matches("resize-zone")
                    .unwrap()
                    .get_one::<String>("id")
                    .unwrap(),
                matches
                    .subcommand_matches("resize-zone")
                    .unwrap()
                    .get_one::<String>("size")
                    .unwrap(),
            )?;
            proxy.api_vm_resize_zone(&resize_zone)
        }
        Some("add-device") => {
            let device_config = add_device_config(
                matches
                    .subcommand_matches("add-device")
                    .unwrap()
                    .get_one::<String>("device_config")
                    .unwrap(),
            )?;
            proxy.api_vm_add_device(&device_config)
        }
        Some("remove-device") => {
            let remove_device_data = remove_device_config(
                matches
                    .subcommand_matches("remove-device")
                    .unwrap()
                    .get_one::<String>("id")
                    .unwrap(),
            );
            proxy.api_vm_remove_device(&remove_device_data)
        }
        Some("add-disk") => {
            let disk_config = add_disk_config(
                matches
                    .subcommand_matches("add-disk")
                    .unwrap()
                    .get_one::<String>("disk_config")
                    .unwrap(),
            )?;
            proxy.api_vm_add_disk(&disk_config)
        }
        Some("add-fs") => {
            let fs_config = add_fs_config(
                matches
                    .subcommand_matches("add-fs")
                    .unwrap()
                    .get_one::<String>("fs_config")
                    .unwrap(),
            )?;
            proxy.api_vm_add_fs(&fs_config)
        }
        Some("add-pmem") => {
            let pmem_config = add_pmem_config(
                matches
                    .subcommand_matches("add-pmem")
                    .unwrap()
                    .get_one::<String>("pmem_config")
                    .unwrap(),
            )?;
            proxy.api_vm_add_pmem(&pmem_config)
        }
        Some("add-net") => {
            let (net_config, _fds) = add_net_config(
                matches
                    .subcommand_matches("add-net")
                    .unwrap()
                    .get_one::<String>("net_config")
                    .unwrap(),
            )?;
            proxy.api_vm_add_net(&net_config)
        }
        Some("add-user-device") => {
            let device_config = add_user_device_config(
                matches
                    .subcommand_matches("add-user-device")
                    .unwrap()
                    .get_one::<String>("device_config")
                    .unwrap(),
            )?;
            proxy.api_vm_add_user_device(&device_config)
        }
        Some("add-vdpa") => {
            let vdpa_config = add_vdpa_config(
                matches
                    .subcommand_matches("add-vdpa")
                    .unwrap()
                    .get_one::<String>("vdpa_config")
                    .unwrap(),
            )?;
            proxy.api_vm_add_vdpa(&vdpa_config)
        }
        Some("add-vsock") => {
            let vsock_config = add_vsock_config(
                matches
                    .subcommand_matches("add-vsock")
                    .unwrap()
                    .get_one::<String>("vsock_config")
                    .unwrap(),
            )?;
            proxy.api_vm_add_vsock(&vsock_config)
        }
        Some("snapshot") => {
            let snapshot_config = snapshot_config(
                matches
                    .subcommand_matches("snapshot")
                    .unwrap()
                    .get_one::<String>("snapshot_config")
                    .unwrap(),
            );
            proxy.api_vm_snapshot(&snapshot_config)
        }
        Some("restore") => {
            let restore_config = restore_config(
                matches
                    .subcommand_matches("restore")
                    .unwrap()
                    .get_one::<String>("restore_config")
                    .unwrap(),
            )?;
            proxy.api_vm_restore(&restore_config)
        }
        Some("coredump") => {
            let coredump_config = coredump_config(
                matches
                    .subcommand_matches("coredump")
                    .unwrap()
                    .get_one::<String>("coredump_config")
                    .unwrap(),
            );
            proxy.api_vm_coredump(&coredump_config)
        }
        Some("send-migration") => {
            let send_migration_data = send_migration_data(
                matches
                    .subcommand_matches("send-migration")
                    .unwrap()
                    .get_one::<String>("send_migration_config")
                    .unwrap(),
                matches
                    .subcommand_matches("send-migration")
                    .unwrap()
                    .get_flag("send_migration_local"),
            );
            proxy.api_vm_send_migration(&send_migration_data)
        }
        Some("receive-migration") => {
            let receive_migration_data = receive_migration_data(
                matches
                    .subcommand_matches("receive-migration")
                    .unwrap()
                    .get_one::<String>("receive_migration_config")
                    .unwrap(),
            );
            proxy.api_vm_receive_migration(&receive_migration_data)
        }
        Some("create") => {
            let data = create_data(
                matches
                    .subcommand_matches("create")
                    .unwrap()
                    .get_one::<String>("path")
                    .unwrap(),
            )?;
            proxy.api_vm_create(&data)
        }
        _ => unreachable!(),
    }
}

fn resize_config(
    cpus: Option<&str>,
    memory: Option<&str>,
    balloon: Option<&str>,
) -> Result<String, Error> {
    let desired_vcpus: Option<u8> = if let Some(cpus) = cpus {
        Some(cpus.parse().map_err(Error::InvalidCpuCount)?)
    } else {
        None
    };

    let desired_ram: Option<u64> = if let Some(memory) = memory {
        Some(
            memory
                .parse::<ByteSized>()
                .map_err(Error::InvalidMemorySize)?
                .0,
        )
    } else {
        None
    };

    let desired_balloon: Option<u64> = if let Some(balloon) = balloon {
        Some(
            balloon
                .parse::<ByteSized>()
                .map_err(Error::InvalidBalloonSize)?
                .0,
        )
    } else {
        None
    };

    let resize = vmm::api::VmResizeData {
        desired_vcpus,
        desired_ram,
        desired_balloon,
    };

    Ok(serde_json::to_string(&resize).unwrap())
}

fn resize_zone_config(id: &str, size: &str) -> Result<String, Error> {
    let resize_zone = vmm::api::VmResizeZoneData {
        id: id.to_owned(),
        desired_ram: size
            .parse::<ByteSized>()
            .map_err(Error::InvalidMemorySize)?
            .0,
    };

    Ok(serde_json::to_string(&resize_zone).unwrap())
}

fn add_device_config(config: &str) -> Result<String, Error> {
    let device_config = vmm::config::DeviceConfig::parse(config).map_err(Error::AddDeviceConfig)?;
    let device_config = serde_json::to_string(&device_config).unwrap();

    Ok(device_config)
}

fn add_user_device_config(config: &str) -> Result<String, Error> {
    let device_config =
        vmm::config::UserDeviceConfig::parse(config).map_err(Error::AddUserDeviceConfig)?;
    let device_config = serde_json::to_string(&device_config).unwrap();

    Ok(device_config)
}

fn remove_device_config(id: &str) -> String {
    let remove_device_data = vmm::api::VmRemoveDeviceData { id: id.to_owned() };

    serde_json::to_string(&remove_device_data).unwrap()
}

fn add_disk_config(config: &str) -> Result<String, Error> {
    let disk_config = vmm::config::DiskConfig::parse(config).map_err(Error::AddDiskConfig)?;
    let disk_config = serde_json::to_string(&disk_config).unwrap();

    Ok(disk_config)
}

fn add_fs_config(config: &str) -> Result<String, Error> {
    let fs_config = vmm::config::FsConfig::parse(config).map_err(Error::AddFsConfig)?;
    let fs_config = serde_json::to_string(&fs_config).unwrap();

    Ok(fs_config)
}

fn add_pmem_config(config: &str) -> Result<String, Error> {
    let pmem_config = vmm::config::PmemConfig::parse(config).map_err(Error::AddPmemConfig)?;
    let pmem_config = serde_json::to_string(&pmem_config).unwrap();

    Ok(pmem_config)
}

fn add_net_config(config: &str) -> Result<(String, Vec<i32>), Error> {
    let mut net_config = vmm::config::NetConfig::parse(config).map_err(Error::AddNetConfig)?;

    // NetConfig is modified on purpose here by taking the list of file
    // descriptors out. Keeping the list and send it to the server side
    // process would not make any sense since the file descriptor may be
    // represented with different values.
    let fds = net_config.fds.take().unwrap_or_default();
    let net_config = serde_json::to_string(&net_config).unwrap();

    Ok((net_config, fds))
}

fn add_vdpa_config(config: &str) -> Result<String, Error> {
    let vdpa_config = vmm::config::VdpaConfig::parse(config).map_err(Error::AddVdpaConfig)?;
    let vdpa_config = serde_json::to_string(&vdpa_config).unwrap();

    Ok(vdpa_config)
}

fn add_vsock_config(config: &str) -> Result<String, Error> {
    let vsock_config = vmm::config::VsockConfig::parse(config).map_err(Error::AddVsockConfig)?;
    let vsock_config = serde_json::to_string(&vsock_config).unwrap();

    Ok(vsock_config)
}

fn snapshot_config(url: &str) -> String {
    let snapshot_config = vmm::api::VmSnapshotConfig {
        destination_url: String::from(url),
    };

    serde_json::to_string(&snapshot_config).unwrap()
}

fn restore_config(config: &str) -> Result<String, Error> {
    let restore_config = vmm::config::RestoreConfig::parse(config).map_err(Error::Restore)?;
    let restore_config = serde_json::to_string(&restore_config).unwrap();

    Ok(restore_config)
}

fn coredump_config(destination_url: &str) -> String {
    let coredump_config = vmm::api::VmCoredumpData {
        destination_url: String::from(destination_url),
    };

    serde_json::to_string(&coredump_config).unwrap()
}

fn receive_migration_data(url: &str) -> String {
    let receive_migration_data = vmm::api::VmReceiveMigrationData {
        receiver_url: url.to_owned(),
    };

    serde_json::to_string(&receive_migration_data).unwrap()
}

fn send_migration_data(url: &str, local: bool) -> String {
    let send_migration_data = vmm::api::VmSendMigrationData {
        destination_url: url.to_owned(),
        local,
    };

    serde_json::to_string(&send_migration_data).unwrap()
}

fn create_data(path: &str) -> Result<String, Error> {
    let mut data = String::default();
    if path == "-" {
        std::io::stdin()
            .read_to_string(&mut data)
            .map_err(Error::ReadingStdin)?;
    } else {
        data = std::fs::read_to_string(path).map_err(Error::ReadingFile)?;
    }

    Ok(data)
}

fn main() {
    let app = Command::new("ch-remote")
        .author(env!("CARGO_PKG_AUTHORS"))
        .version(env!("BUILD_VERSION"))
        .about("Remotely control a cloud-hypervisor VMM.")
        .args([
            Arg::new("api-socket")
                .long("api-socket")
                .help("HTTP API socket path (UNIX domain socket).")
                .num_args(1),
            #[cfg(feature = "dbus_api")]
            Arg::new("dbus-service-name")
                .long("dbus-service-name")
                .help("Well known name of the dbus service")
                .num_args(1),
            #[cfg(feature = "dbus_api")]
            Arg::new("dbus-object-path")
                .long("dbus-object-path")
                .help("Object path which the interface is being served at")
                .num_args(1),
            #[cfg(feature = "dbus_api")]
            Arg::new("dbus-system-bus")
                .long("dbus-system-bus")
                .action(ArgAction::SetTrue)
                .num_args(0)
                .help("Use the system bus instead of a session bus"),
        ])
        .subcommand(
            Command::new("add-device").about("Add VFIO device").arg(
                Arg::new("device_config")
                    .index(1)
                    .help(vmm::config::DeviceConfig::SYNTAX),
            ),
        )
        .subcommand(
            Command::new("add-disk").about("Add block device").arg(
                Arg::new("disk_config")
                    .index(1)
                    .help(vmm::config::DiskConfig::SYNTAX),
            ),
        )
        .subcommand(
            Command::new("add-fs")
                .about("Add virtio-fs backed fs device")
                .arg(
                    Arg::new("fs_config")
                        .index(1)
                        .help(vmm::config::FsConfig::SYNTAX),
                ),
        )
        .subcommand(
            Command::new("add-pmem")
                .about("Add persistent memory device")
                .arg(
                    Arg::new("pmem_config")
                        .index(1)
                        .help(vmm::config::PmemConfig::SYNTAX),
                ),
        )
        .subcommand(
            Command::new("add-net").about("Add network device").arg(
                Arg::new("net_config")
                    .index(1)
                    .help(vmm::config::NetConfig::SYNTAX),
            ),
        )
        .subcommand(
            Command::new("add-user-device")
                .about("Add userspace device")
                .arg(
                    Arg::new("device_config")
                        .index(1)
                        .help(vmm::config::UserDeviceConfig::SYNTAX),
                ),
        )
        .subcommand(
            Command::new("add-vdpa").about("Add vDPA device").arg(
                Arg::new("vdpa_config")
                    .index(1)
                    .help(vmm::config::VdpaConfig::SYNTAX),
            ),
        )
        .subcommand(
            Command::new("add-vsock").about("Add vsock device").arg(
                Arg::new("vsock_config")
                    .index(1)
                    .help(vmm::config::VsockConfig::SYNTAX),
            ),
        )
        .subcommand(
            Command::new("remove-device")
                .about("Remove VFIO device")
                .arg(Arg::new("id").index(1).help("<device_id>")),
        )
        .subcommand(Command::new("info").about("Info on the VM"))
        .subcommand(Command::new("counters").about("Counters from the VM"))
        .subcommand(Command::new("pause").about("Pause the VM"))
        .subcommand(Command::new("reboot").about("Reboot the VM"))
        .subcommand(Command::new("power-button").about("Trigger a power button in the VM"))
        .subcommand(
            Command::new("resize")
                .about("Resize the VM")
                .arg(
                    Arg::new("cpus")
                        .long("cpus")
                        .help("New vCPUs count")
                        .num_args(1),
                )
                .arg(
                    Arg::new("memory")
                        .long("memory")
                        .help("New memory size in bytes (supports K/M/G suffix)")
                        .num_args(1),
                )
                .arg(
                    Arg::new("balloon")
                        .long("balloon")
                        .help("New balloon size in bytes (supports K/M/G suffix)")
                        .num_args(1),
                ),
        )
        .subcommand(
            Command::new("resize-zone")
                .about("Resize a memory zone")
                .arg(
                    Arg::new("id")
                        .long("id")
                        .help("Memory zone identifier")
                        .num_args(1),
                )
                .arg(
                    Arg::new("size")
                        .long("size")
                        .help("New memory zone size in bytes (supports K/M/G suffix)")
                        .num_args(1),
                ),
        )
        .subcommand(Command::new("resume").about("Resume the VM"))
        .subcommand(Command::new("boot").about("Boot a created VM"))
        .subcommand(Command::new("delete").about("Delete a VM"))
        .subcommand(Command::new("shutdown").about("Shutdown the VM"))
        .subcommand(
            Command::new("snapshot")
                .about("Create a snapshot from VM")
                .arg(
                    Arg::new("snapshot_config")
                        .index(1)
                        .help("<destination_url>"),
                ),
        )
        .subcommand(
            Command::new("restore")
                .about("Restore VM from a snapshot")
                .arg(
                    Arg::new("restore_config")
                        .index(1)
                        .help(vmm::config::RestoreConfig::SYNTAX),
                ),
        )
        .subcommand(
            Command::new("coredump")
                .about("Create a coredump from VM")
                .arg(Arg::new("coredump_config").index(1).help("<file_path>")),
        )
        .subcommand(
            Command::new("send-migration")
                .about("Initiate a VM migration")
                .arg(
                    Arg::new("send_migration_config")
                        .index(1)
                        .help("<destination_url>"),
                )
                .arg(
                    Arg::new("send_migration_local")
                        .long("local")
                        .num_args(0)
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("receive-migration")
                .about("Receive a VM migration")
                .arg(
                    Arg::new("receive_migration_config")
                        .index(1)
                        .help("<receiver_url>"),
                ),
        )
        .subcommand(
            Command::new("create")
                .about("Create VM from a JSON configuration")
                .arg(Arg::new("path").index(1).default_value("-")),
        )
        .subcommand(Command::new("ping").about("Ping the VMM to check for API server availability"))
        .subcommand(Command::new("shutdown-vmm").about("Shutdown the VMM"));

    let matches = app.get_matches();

    let mut target_api = match (
        matches.get_one::<String>("api-socket"),
        #[cfg(feature = "dbus_api")]
        matches.get_one::<String>("dbus-service-name"),
        #[cfg(feature = "dbus_api")]
        matches.get_one::<String>("dbus-object-path"),
    ) {
        #[cfg(not(feature = "dbus_api"))]
        (Some(api_sock),) => TargetApi::HttpApi(
            UnixStream::connect(api_sock).unwrap_or_else(|e| {
                eprintln!("Error opening HTTP socket: {e}");
                process::exit(1)
            }),
            PhantomData,
        ),
        #[cfg(feature = "dbus_api")]
        (Some(api_sock), None, None) => TargetApi::HttpApi(
            UnixStream::connect(api_sock).unwrap_or_else(|e| {
                eprintln!("Error opening HTTP socket: {e}");
                process::exit(1)
            }),
            PhantomData,
        ),
        #[cfg(feature = "dbus_api")]
        (None, Some(dbus_name), Some(dbus_path)) => TargetApi::DBusApi(
            DBusApi1ProxyBlocking::new_connection(
                dbus_name,
                dbus_path,
                matches.get_flag("dbus-system-bus"),
            )
            .map_err(Error::DBusApiClient)
            .unwrap_or_else(|e| {
                eprintln!("Error creating D-Bus proxy: {e}");
                process::exit(1)
            }),
        ),
        #[cfg(feature = "dbus_api")]
        (Some(_), Some(_) | None, Some(_) | None) => {
            println!(
                "`api-socket` and (dbus-service-name or dbus-object-path) are mutually exclusive"
            );
            process::exit(1);
        }
        _ => {
            println!("Please either provide the api-socket option or dbus-service-name and dbus-object-path options");
            process::exit(1);
        }
    };

    if let Err(e) = target_api.do_command(&matches) {
        eprintln!("Error running command: {e}");
        process::exit(1)
    };
}
