// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[cfg(test)]
#[path = "../test_util.rs"]
mod test_util;

use std::io::{self, Read};
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::{error, fs, iter, num, process};

use api_client::{
    Error as ApiClientError, simple_api_command, simple_api_command_with_fds,
    simple_api_full_command,
};
use clap::{Parser, Subcommand};
use log::error;
use option_parser::{ByteSized, ByteSizedParseError};
use thiserror::Error;
use vmm::api;
use vmm::config::{self, RestoreConfig};
use vmm::vm_config::{
    DeviceConfig, DiskConfig, FsConfig, GenericVhostUserConfig, NetConfig, PmemConfig,
    UserDeviceConfig, VdpaConfig, VsockConfig,
};
#[cfg(feature = "dbus_api")]
use zbus::{blocking::Connection, proxy, zvariant::Optional};

type ApiResult = Result<(), Error>;
type FdCommand = (String, Vec<Arc<OwnedFd>>);

#[derive(Error, Debug)]
enum Error {
    #[error("HTTP Client Error")]
    HttpApiClient(#[source] ApiClientError),
    #[cfg(feature = "dbus_api")]
    #[error("D-Bus API Client Error")]
    DBusApiClient(#[source] zbus::Error),
    #[error("Error parsing CPU count")]
    InvalidCpuCount(#[source] num::ParseIntError),
    #[error("Error parsing memory size")]
    InvalidMemorySize(#[source] ByteSizedParseError),
    #[error("Error parsing balloon size")]
    InvalidBalloonSize(#[source] ByteSizedParseError),
    #[error("Error parsing device syntax")]
    AddDeviceConfig(#[source] config::Error),
    #[error("Error parsing disk syntax")]
    AddDiskConfig(#[source] config::Error),
    #[error("Error parsing filesystem syntax")]
    AddFsConfig(#[source] config::Error),
    #[error("Error parsing generic vhost-user syntax")]
    AddGenericVhostUserConfig(#[source] config::Error),
    #[error("Error parsing persistent memory syntax")]
    AddPmemConfig(#[source] config::Error),
    #[error("Error parsing network syntax")]
    AddNetConfig(#[source] config::Error),
    #[error("Error parsing user device syntax")]
    AddUserDeviceConfig(#[source] config::Error),
    #[error("Error parsing vDPA device syntax")]
    AddVdpaConfig(#[source] config::Error),
    #[error("Error parsing vsock syntax")]
    AddVsockConfig(#[source] config::Error),
    #[error("Error parsing restore syntax")]
    Restore(#[source] config::Error),
    #[error("Error reading from stdin")]
    ReadingStdin(#[source] io::Error),
    #[error("Error reading from file")]
    ReadingFile(#[source] io::Error),
    #[error("Invalid disk size")]
    InvalidDiskSize(#[source] ByteSizedParseError),
    #[error("Error parsing receive migration configuration")]
    ReceiveMigrationConfig(#[from] api::VmReceiveMigrationConfigError),
    #[error("Error parsing send migration configuration")]
    SendMigrationConfig(#[from] api::VmSendMigrationConfigError),
}

enum TargetApi<'a> {
    HttpApi(UnixStream, PhantomData<&'a ()>),
    #[cfg(feature = "dbus_api")]
    DBusApi(DBusApi1ProxyBlocking<'a>),
}

#[cfg(feature = "dbus_api")]
#[proxy(name = "org.cloudhypervisor.DBusApi1", assume_defaults = false)]
trait DBusApi1 {
    fn vmm_ping(&self) -> zbus::Result<String>;
    fn vmm_shutdown(&self) -> zbus::Result<()>;
    fn vm_add_device(&self, device_config: &str) -> zbus::Result<Optional<String>>;
    fn vm_add_disk(&self, disk_config: &str) -> zbus::Result<Optional<String>>;
    fn vm_add_fs(&self, fs_config: &str) -> zbus::Result<Optional<String>>;
    fn vm_add_generic_vhost_user(
        &self,
        generic_vhost_user_config: &str,
    ) -> zbus::Result<Optional<String>>;
    fn vm_add_net(&self, net_config: &str) -> zbus::Result<Optional<String>>;
    fn vm_add_pmem(&self, pmem_config: &str) -> zbus::Result<Optional<String>>;
    fn vm_add_user_device(&self, vm_add_user_device: &str) -> zbus::Result<Optional<String>>;
    fn vm_add_vdpa(&self, vdpa_config: &str) -> zbus::Result<Optional<String>>;
    fn vm_add_vsock(&self, vsock_config: &str) -> zbus::Result<Optional<String>>;
    fn vm_balloon_stats(&self) -> zbus::Result<String>;
    fn vm_boot(&self) -> zbus::Result<()>;
    fn vm_coredump(&self, vm_coredump_data: &str) -> zbus::Result<()>;
    fn vm_counters(&self) -> zbus::Result<Optional<String>>;
    fn vm_create(&self, vm_config: &str) -> zbus::Result<()>;
    fn vm_delete(&self) -> zbus::Result<()>;
    fn vm_info(&self) -> zbus::Result<String>;
    fn vm_pause(&self) -> zbus::Result<()>;
    fn vm_nmi(&self) -> zbus::Result<()>;
    fn vm_power_button(&self) -> zbus::Result<()>;
    fn vm_reboot(&self) -> zbus::Result<()>;
    fn vm_remove_device(&self, vm_remove_device: &str) -> zbus::Result<()>;
    fn vm_resize(&self, vm_resize: &str) -> zbus::Result<()>;
    fn vm_resize_disk(&self, vm_resize_disk: &str) -> zbus::Result<()>;
    fn vm_resize_zone(&self, vm_resize_zone: &str) -> zbus::Result<()>;
    fn vm_restore(&self, restore_config: &str) -> zbus::Result<()>;
    fn vm_cancel_migration(&self) -> zbus::Result<()>;
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
            Connection::system()?
        } else {
            Connection::session()?
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

    fn api_vm_add_generic_vhost_user(&self, generic_vhost_user_config: &str) -> ApiResult {
        self.print_response(self.vm_add_generic_vhost_user(generic_vhost_user_config))
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

    fn api_vm_balloon_stats(&self) -> ApiResult {
        self.vm_balloon_stats()
            .map(|stats| println!("{stats}"))
            .map_err(Error::DBusApiClient)
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

    fn api_vm_nmi(&self) -> ApiResult {
        self.vm_nmi().map_err(Error::DBusApiClient)
    }

    fn api_vm_resize(&self, vm_resize: &str) -> ApiResult {
        self.vm_resize(vm_resize).map_err(Error::DBusApiClient)
    }

    fn api_vm_resize_disk(&self, vm_resize_disk: &str) -> ApiResult {
        self.vm_resize_disk(vm_resize_disk)
            .map_err(Error::DBusApiClient)
    }

    fn api_vm_resize_zone(&self, vm_resize_zone: &str) -> ApiResult {
        self.vm_resize_zone(vm_resize_zone)
            .map_err(Error::DBusApiClient)
    }

    fn api_vm_restore(&self, restore_config: &str) -> ApiResult {
        self.vm_restore(restore_config)
            .map_err(Error::DBusApiClient)
    }

    fn api_vm_cancel_migration(&self) -> ApiResult {
        self.vm_cancel_migration().map_err(Error::DBusApiClient)
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

impl TargetApi<'_> {
    fn do_command(&mut self, command: &Command, fd_command: Option<FdCommand>) -> ApiResult {
        match self {
            Self::HttpApi(api_socket, _) => rest_api_do_command(command, api_socket, fd_command),
            #[cfg(feature = "dbus_api")]
            Self::DBusApi(proxy) => dbus_api_do_command(command, proxy, fd_command),
        }
    }
}

fn prepare_fd_command(command: &Command) -> Result<Option<FdCommand>, Error> {
    let fd_command = match command {
        Command::AddDevice { device_config } => Some(add_device_config(device_config)?),
        Command::AddNet { net_config } => Some(add_net_config(net_config)?),
        Command::Restore {
            restore_config: config,
        } => Some(restore_config(config)?),
        Command::ReceiveMigration {
            receive_migration_config,
        } => Some(receive_migration_data(receive_migration_config)?),
        _ => None,
    };
    Ok(fd_command)
}

fn rest_api_do_command(
    command: &Command,
    socket: &mut UnixStream,
    fd_command: Option<FdCommand>,
) -> ApiResult {
    let (fd_request_body, fds) = fd_command
        .map(|(body, fds)| (Some(body), fds))
        .unwrap_or_default();
    match command {
        Command::Boot => {
            simple_api_command(socket, "PUT", "boot", None).map_err(Error::HttpApiClient)
        }
        Command::Delete => {
            simple_api_command(socket, "PUT", "delete", None).map_err(Error::HttpApiClient)
        }
        Command::ShutdownVmm => simple_api_full_command(socket, "PUT", "vmm.shutdown", None)
            .map_err(Error::HttpApiClient),
        Command::Resume => {
            simple_api_command(socket, "PUT", "resume", None).map_err(Error::HttpApiClient)
        }
        Command::PowerButton => {
            simple_api_command(socket, "PUT", "power-button", None).map_err(Error::HttpApiClient)
        }
        Command::Reboot => {
            simple_api_command(socket, "PUT", "reboot", None).map_err(Error::HttpApiClient)
        }
        Command::Pause => {
            simple_api_command(socket, "PUT", "pause", None).map_err(Error::HttpApiClient)
        }
        Command::Info => {
            simple_api_command(socket, "GET", "info", None).map_err(Error::HttpApiClient)
        }
        Command::BalloonStats => {
            simple_api_command(socket, "GET", "balloon-stats", None).map_err(Error::HttpApiClient)
        }
        Command::Counters => {
            simple_api_command(socket, "GET", "counters", None).map_err(Error::HttpApiClient)
        }
        Command::Ping => {
            simple_api_full_command(socket, "GET", "vmm.ping", None).map_err(Error::HttpApiClient)
        }
        Command::Shutdown => {
            simple_api_command(socket, "PUT", "shutdown", None).map_err(Error::HttpApiClient)
        }
        Command::Nmi => {
            simple_api_command(socket, "PUT", "nmi", None).map_err(Error::HttpApiClient)
        }
        Command::Resize {
            balloon: arg_balloon,
            cpus: arg_cpus,
            memory: arg_memory,
        } => {
            let resize = resize_config(
                arg_cpus.as_deref(),
                arg_memory.as_deref(),
                arg_balloon.as_deref(),
            )?;
            simple_api_command(socket, "PUT", "resize", Some(&resize)).map_err(Error::HttpApiClient)
        }
        Command::ResizeDisk {
            disk: arg_disk,
            size: arg_size,
        } => {
            let resize_disk = resize_disk_config(arg_disk, arg_size)?;
            simple_api_command(socket, "PUT", "resize-disk", Some(&resize_disk))
                .map_err(Error::HttpApiClient)
        }
        Command::ResizeZone {
            id: arg_id,
            size: arg_size,
        } => {
            let resize_zone = resize_zone_config(arg_id, arg_size)?;
            simple_api_command(socket, "PUT", "resize-zone", Some(&resize_zone))
                .map_err(Error::HttpApiClient)
        }
        Command::AddDevice { .. } => simple_api_command_with_fds(
            socket,
            "PUT",
            "add-device",
            fd_request_body.as_deref(),
            &fds.iter().map(|fd| fd.as_raw_fd()).collect::<Vec<_>>(),
        )
        .map_err(Error::HttpApiClient),
        Command::RemoveDevice { id: arg_id } => {
            let remove_device_data = remove_device_config(arg_id);
            simple_api_command(socket, "PUT", "remove-device", Some(&remove_device_data))
                .map_err(Error::HttpApiClient)
        }
        Command::AddDisk {
            disk_config: arg_disk_config,
        } => {
            let disk_config = add_disk_config(arg_disk_config)?;
            simple_api_command(socket, "PUT", "add-disk", Some(&disk_config))
                .map_err(Error::HttpApiClient)
        }
        Command::AddFs {
            fs_config: arg_fs_config,
        } => {
            let fs_config = add_fs_config(arg_fs_config)?;
            simple_api_command(socket, "PUT", "add-fs", Some(&fs_config))
                .map_err(Error::HttpApiClient)
        }
        Command::AddGenericVhostUser {
            generic_vhost_user_config: arg_generic_vhost_user_config,
        } => {
            let device_config = add_generic_vhost_user_config(arg_generic_vhost_user_config)?;
            simple_api_command(
                socket,
                "PUT",
                "add-generic-vhost-user",
                Some(&device_config),
            )
            .map_err(Error::HttpApiClient)
        }
        Command::AddPmem {
            pmem_config: arg_pmem_config,
        } => {
            let pmem_config = add_pmem_config(arg_pmem_config)?;
            simple_api_command(socket, "PUT", "add-pmem", Some(&pmem_config))
                .map_err(Error::HttpApiClient)
        }
        Command::AddNet { .. } => simple_api_command_with_fds(
            socket,
            "PUT",
            "add-net",
            fd_request_body.as_deref(),
            &fds.iter().map(|fd| fd.as_raw_fd()).collect::<Vec<_>>(),
        )
        .map_err(Error::HttpApiClient),
        Command::AddUserDevice {
            device_config: arg_device_config,
        } => {
            let device_config = add_user_device_config(arg_device_config)?;
            simple_api_command(socket, "PUT", "add-user-device", Some(&device_config))
                .map_err(Error::HttpApiClient)
        }
        Command::AddVdpa {
            vdpa_config: arg_vdpa_config,
        } => {
            let vdpa_config = add_vdpa_config(arg_vdpa_config)?;
            simple_api_command(socket, "PUT", "add-vdpa", Some(&vdpa_config))
                .map_err(Error::HttpApiClient)
        }
        Command::AddVsock {
            vsock_config: arg_vsock_config,
        } => {
            let vsock_config = add_vsock_config(arg_vsock_config)?;
            simple_api_command(socket, "PUT", "add-vsock", Some(&vsock_config))
                .map_err(Error::HttpApiClient)
        }
        Command::Snapshot {
            snapshot_config: arg_snapshot_config,
        } => {
            let snapshot_config = snapshot_config(arg_snapshot_config);
            simple_api_command(socket, "PUT", "snapshot", Some(&snapshot_config))
                .map_err(Error::HttpApiClient)
        }
        Command::Restore { .. } => simple_api_command_with_fds(
            socket,
            "PUT",
            "restore",
            fd_request_body.as_deref(),
            &fds.iter().map(|fd| fd.as_raw_fd()).collect::<Vec<_>>(),
        )
        .map_err(Error::HttpApiClient),
        Command::Coredump {
            coredump_config: arg_coredump_config,
        } => {
            let coredump_config = coredump_config(arg_coredump_config);
            simple_api_command(socket, "PUT", "coredump", Some(&coredump_config))
                .map_err(Error::HttpApiClient)
        }
        Command::SendMigration {
            send_migration_config: arg_send_migration_config,
        } => {
            let send_migration_data = send_migration_data(arg_send_migration_config)?;
            simple_api_command(socket, "PUT", "send-migration", Some(&send_migration_data))
                .map_err(Error::HttpApiClient)
        }
        Command::ReceiveMigration { .. } => simple_api_command_with_fds(
            socket,
            "PUT",
            "receive-migration",
            fd_request_body.as_deref(),
            &fds.iter().map(|fd| fd.as_raw_fd()).collect::<Vec<_>>(),
        )
        .map_err(Error::HttpApiClient),
        Command::Create { path: arg_path } => {
            let data = create_data(arg_path)?;
            simple_api_command(socket, "PUT", "create", Some(&data)).map_err(Error::HttpApiClient)
        }
        Command::CancelMigration => simple_api_command(socket, "PUT", "cancel-migration", None)
            .map_err(Error::HttpApiClient),
    }
}

#[cfg(feature = "dbus_api")]
fn dbus_api_do_command(
    command: &Command,
    proxy: &DBusApi1ProxyBlocking<'_>,
    fd_command: Option<FdCommand>,
) -> ApiResult {
    let (fd_request_body, _fds) = fd_command
        .map(|(body, fds)| (Some(body), fds))
        .unwrap_or_default();
    match command {
        Command::Boot => proxy.api_vm_boot(),
        Command::Delete => proxy.api_vm_delete(),
        Command::ShutdownVmm => proxy.api_vmm_shutdown(),
        Command::Resume => proxy.api_vm_resume(),
        Command::PowerButton => proxy.api_vm_power_button(),
        Command::Reboot => proxy.api_vm_reboot(),
        Command::Pause => proxy.api_vm_pause(),
        Command::Info => proxy.api_vm_info(),
        Command::BalloonStats => proxy.api_vm_balloon_stats(),
        Command::Counters => proxy.api_vm_counters(),
        Command::Ping => proxy.api_vmm_ping(),
        Command::Nmi => proxy.api_vm_nmi(),
        Command::Shutdown => proxy.api_vm_shutdown(),
        Command::Resize {
            balloon: arg_balloon,
            cpus: arg_cpus,
            memory: arg_memory,
        } => {
            let resize = resize_config(
                arg_cpus.as_deref(),
                arg_memory.as_deref(),
                arg_balloon.as_deref(),
            )?;
            proxy.api_vm_resize(&resize)
        }
        Command::ResizeDisk {
            disk: arg_disk,
            size: arg_size,
        } => {
            let resize_disk = resize_disk_config(arg_disk, arg_size)?;
            proxy.api_vm_resize_disk(&resize_disk)
        }
        Command::ResizeZone {
            id: arg_id,
            size: arg_size,
        } => {
            let resize_zone = resize_zone_config(arg_id, arg_size)?;
            proxy.api_vm_resize_zone(&resize_zone)
        }
        Command::AddDevice { .. } => proxy.api_vm_add_device(fd_request_body.as_deref().unwrap()),
        Command::RemoveDevice { id: arg_id } => {
            let remove_device_data = remove_device_config(arg_id);
            proxy.api_vm_remove_device(&remove_device_data)
        }
        Command::AddDisk {
            disk_config: arg_disk_config,
        } => {
            let disk_config = add_disk_config(arg_disk_config)?;
            proxy.api_vm_add_disk(&disk_config)
        }
        Command::AddFs {
            fs_config: arg_fs_config,
        } => {
            let fs_config = add_fs_config(arg_fs_config)?;
            proxy.api_vm_add_fs(&fs_config)
        }
        Command::AddGenericVhostUser {
            generic_vhost_user_config: arg_generic_vhost_user_config,
        } => {
            let generic_vhost_user_config =
                add_generic_vhost_user_config(arg_generic_vhost_user_config)?;
            proxy.api_vm_add_generic_vhost_user(&generic_vhost_user_config)
        }
        Command::AddPmem {
            pmem_config: arg_pmem_config,
        } => {
            let pmem_config = add_pmem_config(arg_pmem_config)?;
            proxy.api_vm_add_pmem(&pmem_config)
        }
        Command::AddNet { .. } => proxy.api_vm_add_net(fd_request_body.as_deref().unwrap()),
        Command::AddUserDevice {
            device_config: arg_device_config,
        } => {
            let device_config = add_user_device_config(arg_device_config)?;
            proxy.api_vm_add_user_device(&device_config)
        }
        Command::AddVdpa {
            vdpa_config: arg_vdpa_config,
        } => {
            let vdpa_config = add_vdpa_config(arg_vdpa_config)?;
            proxy.api_vm_add_vdpa(&vdpa_config)
        }
        Command::AddVsock {
            vsock_config: arg_vsock_config,
        } => {
            let vsock_config = add_vsock_config(arg_vsock_config)?;
            proxy.api_vm_add_vsock(&vsock_config)
        }
        Command::Snapshot {
            snapshot_config: arg_snapshot_config,
        } => {
            let snapshot_config = snapshot_config(arg_snapshot_config);
            proxy.api_vm_snapshot(&snapshot_config)
        }
        Command::Restore { .. } => proxy.api_vm_restore(fd_request_body.as_deref().unwrap()),
        Command::Coredump {
            coredump_config: arg_coredump_config,
        } => {
            let coredump_config = coredump_config(arg_coredump_config);
            proxy.api_vm_coredump(&coredump_config)
        }
        Command::CancelMigration => proxy.api_vm_cancel_migration(),
        Command::SendMigration {
            send_migration_config: arg_send_migration_config,
        } => {
            let send_migration_data = send_migration_data(arg_send_migration_config)?;
            proxy.api_vm_send_migration(&send_migration_data)
        }
        Command::ReceiveMigration { .. } => {
            proxy.api_vm_receive_migration(fd_request_body.as_deref().unwrap())
        }
        Command::Create { path: arg_path } => {
            let data = create_data(arg_path)?;
            proxy.api_vm_create(&data)
        }
    }
}

fn resize_config(
    cpus: Option<&str>,
    memory: Option<&str>,
    balloon: Option<&str>,
) -> Result<String, Error> {
    let desired_vcpus: Option<u32> = if let Some(cpus) = cpus {
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

    let resize = api::VmResizeData {
        desired_vcpus,
        desired_ram,
        desired_balloon,
    };

    Ok(serde_json::to_string(&resize).unwrap())
}

fn resize_disk_config(id: &str, size: &str) -> Result<String, Error> {
    let resize_disk = api::VmResizeDiskData {
        id: id.to_owned(),
        desired_size: size.parse::<ByteSized>().map_err(Error::InvalidDiskSize)?.0,
    };

    Ok(serde_json::to_string(&resize_disk).unwrap())
}

fn resize_zone_config(id: &str, size: &str) -> Result<String, Error> {
    let resize_zone = api::VmResizeZoneData {
        id: id.to_owned(),
        desired_ram: size
            .parse::<ByteSized>()
            .map_err(Error::InvalidMemorySize)?
            .0,
    };

    Ok(serde_json::to_string(&resize_zone).unwrap())
}

fn add_device_config(config: &str) -> Result<FdCommand, Error> {
    let mut device_config =
        // SAFETY: The CLI transfers ownership of the inherited descriptors.
        unsafe { DeviceConfig::parse(config) }.map_err(Error::AddDeviceConfig)?;

    // DeviceConfig is modified on purpose here by taking the file
    // descriptor out. Keeping it and sending it over to the server side
    // process would not make any sense since the file descriptor may be
    // represented with different values.
    let fds = device_config
        .fd
        .take()
        .map(|fd| vec![fd])
        .unwrap_or_default();
    let device_config = serde_json::to_string(&device_config).unwrap();

    Ok((device_config, fds))
}

fn add_user_device_config(config: &str) -> Result<String, Error> {
    let device_config = UserDeviceConfig::parse(config).map_err(Error::AddUserDeviceConfig)?;
    let device_config = serde_json::to_string(&device_config).unwrap();

    Ok(device_config)
}

fn remove_device_config(id: &str) -> String {
    let remove_device_data = api::VmRemoveDeviceData { id: id.to_owned() };

    serde_json::to_string(&remove_device_data).unwrap()
}

fn add_disk_config(config: &str) -> Result<String, Error> {
    let disk_config = DiskConfig::parse(config).map_err(Error::AddDiskConfig)?;
    let disk_config = serde_json::to_string(&disk_config).unwrap();

    Ok(disk_config)
}

fn add_fs_config(config: &str) -> Result<String, Error> {
    let fs_config = FsConfig::parse(config).map_err(Error::AddFsConfig)?;
    let fs_config = serde_json::to_string(&fs_config).unwrap();

    Ok(fs_config)
}

fn add_generic_vhost_user_config(config: &str) -> Result<String, Error> {
    let generic_vhost_user_config =
        GenericVhostUserConfig::parse(config).map_err(Error::AddGenericVhostUserConfig)?;
    let generic_vhost_user_config = serde_json::to_string(&generic_vhost_user_config).unwrap();

    Ok(generic_vhost_user_config)
}

fn add_pmem_config(config: &str) -> Result<String, Error> {
    let pmem_config = PmemConfig::parse(config).map_err(Error::AddPmemConfig)?;
    let pmem_config = serde_json::to_string(&pmem_config).unwrap();

    Ok(pmem_config)
}

fn add_net_config(config: &str) -> Result<FdCommand, Error> {
    // SAFETY: The CLI transfers ownership of the inherited descriptors.
    let mut net_config = unsafe { NetConfig::parse(config) }.map_err(Error::AddNetConfig)?;

    // NetConfig is modified on purpose here by taking the list of file
    // descriptors out. Keeping the list and send it to the server side
    // process would not make any sense since the file descriptor may be
    // represented with different values.
    let fds = net_config
        .fds
        .take()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|mut fd| fd.take())
        .collect();
    let net_config = serde_json::to_string(&net_config).unwrap();

    Ok((net_config, fds))
}

fn add_vdpa_config(config: &str) -> Result<String, Error> {
    let vdpa_config = VdpaConfig::parse(config).map_err(Error::AddVdpaConfig)?;
    let vdpa_config = serde_json::to_string(&vdpa_config).unwrap();

    Ok(vdpa_config)
}

fn add_vsock_config(config: &str) -> Result<String, Error> {
    let vsock_config = VsockConfig::parse(config).map_err(Error::AddVsockConfig)?;
    let vsock_config = serde_json::to_string(&vsock_config).unwrap();

    Ok(vsock_config)
}

fn snapshot_config(url: &str) -> String {
    let snapshot_config = api::VmSnapshotConfig {
        destination_url: String::from(url),
    };

    serde_json::to_string(&snapshot_config).unwrap()
}

fn restore_config(config: &str) -> Result<FdCommand, Error> {
    // SAFETY: The CLI transfers ownership of the inherited descriptors.
    let mut restore_config = unsafe { RestoreConfig::parse(config) }.map_err(Error::Restore)?;
    // RestoreConfig is modified on purpose to take out the file descriptors.
    // These fds are passed to the server side process via SCM_RIGHTS, in the
    // order net_fds, then vfio_fds, then the iommufd FD, matching the
    // server's split.
    let mut fds: Vec<Arc<OwnedFd>> = match &mut restore_config.net_fds {
        Some(net_fds) => net_fds
            .iter_mut()
            .flat_map(|net| net.fds.take().unwrap_or_default())
            .filter_map(|mut fd| fd.take())
            .collect(),
        None => Vec::new(),
    };
    if let Some(vfio_fds) = restore_config.vfio_fds.as_mut() {
        fds.extend(vfio_fds.iter_mut().filter_map(|v| v.fd.take()));
    }
    if let Some(iommufd_fd) = restore_config.iommufd_fd.take() {
        fds.push(iommufd_fd);
    }
    let restore_config = serde_json::to_string(&restore_config).unwrap();

    Ok((restore_config, fds))
}

fn coredump_config(destination_url: &str) -> String {
    let coredump_config = api::VmCoredumpData {
        destination_url: String::from(destination_url),
    };

    serde_json::to_string(&coredump_config).unwrap()
}

fn receive_migration_data(config: &str) -> Result<FdCommand, Error> {
    // SAFETY: The CLI transfers ownership of the inherited descriptors.
    let mut data = unsafe { api::VmReceiveMigrationData::parse(config) }
        .map_err(Error::ReceiveMigrationConfig)?;

    // The FDs are passed to the server side process via SCM_RIGHTS, in the
    // order vfio_fds then the iommufd FD, matching the server's split.
    let mut fds: Vec<Arc<OwnedFd>> = match data.vfio_fds.as_mut() {
        Some(vfio_fds) => vfio_fds.iter_mut().filter_map(|v| v.fd.take()).collect(),
        None => Vec::new(),
    };
    if let Some(iommufd_fd) = data.iommufd_fd.take() {
        fds.push(iommufd_fd);
    }

    Ok((serde_json::to_string(&data).unwrap(), fds))
}

fn send_migration_data(config: &str) -> Result<String, Error> {
    let send_migration_data =
        api::VmSendMigrationData::parse(config).map_err(Error::SendMigrationConfig)?;
    let send_migration_config = serde_json::to_string(&send_migration_data).unwrap();
    Ok(send_migration_config)
}

fn create_data(path: &str) -> Result<String, Error> {
    let mut data = String::default();
    if path == "-" {
        io::stdin()
            .read_to_string(&mut data)
            .map_err(Error::ReadingStdin)?;
    } else {
        data = fs::read_to_string(path).map_err(Error::ReadingFile)?;
    }

    Ok(data)
}

#[derive(Debug, Parser)]
#[command(name = "ch-remote", author, version = env!("BUILD_VERSION"), about = "Remotely control a cloud-hypervisor VMM.", arg_required_else_help = true, subcommand_required = true)]
#[group(skip)]
struct Cli {
    #[arg(
        value_name = "api-socket",
        long,
        help = "HTTP API socket path (UNIX domain socket)."
    )]
    api_socket: Option<String>,
    #[cfg(feature = "dbus_api")]
    #[arg(
        value_name = "dbus-object-path",
        long,
        help = "Object path which the interface is being served at"
    )]
    dbus_object_path: Option<String>,
    #[cfg(feature = "dbus_api")]
    #[arg(
        value_name = "dbus-service-name",
        long,
        help = "Well known name of the dbus service"
    )]
    dbus_service_name: Option<String>,
    #[cfg(feature = "dbus_api")]
    #[arg(long, help = "Use the system bus instead of a session bus")]
    dbus_system_bus: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Add VFIO device")]
    AddDevice {
        #[arg(
            value_name = "device_config",
            index = 1,
            help = DeviceConfig::SYNTAX,
        )]
        device_config: String,
    },
    #[command(about = "Add block device")]
    AddDisk {
        #[arg(
            value_name = "disk_config",
            index = 1,
            help = DiskConfig::SYNTAX,
        )]
        disk_config: String,
    },
    #[command(about = "Add virtio-fs backed fs device")]
    AddFs {
        #[arg(
            value_name = "fs_config",
            index = 1,
            help = FsConfig::SYNTAX,
        )]
        fs_config: String,
    },
    #[command(about = "Add generic vhost-user device")]
    AddGenericVhostUser {
        #[arg(
            value_name = "generic_vhost_user_config",
            index = 1,
            help = GenericVhostUserConfig::SYNTAX,
        )]
        generic_vhost_user_config: String,
    },
    #[command(about = "Add network device")]
    AddNet {
        #[arg(
            value_name = "net_config",
            index = 1,
            help = NetConfig::SYNTAX,
        )]
        net_config: String,
    },
    #[command(about = "Add persistent memory device")]
    AddPmem {
        #[arg(
            value_name = "pmem_config",
            index = 1,
            help = PmemConfig::SYNTAX,
        )]
        pmem_config: String,
    },
    #[command(about = "Add userspace device")]
    AddUserDevice {
        #[arg(
            value_name = "device_config",
            index = 1,
            help = UserDeviceConfig::SYNTAX,
        )]
        device_config: String,
    },
    #[command(about = "Add vDPA device")]
    AddVdpa {
        #[arg(
            value_name = "vdpa_config",
            index = 1,
            help = VdpaConfig::SYNTAX,
        )]
        vdpa_config: String,
    },
    #[command(about = "Add vsock device")]
    AddVsock {
        #[arg(
            value_name = "vsock_config",
            index = 1,
            help = VsockConfig::SYNTAX,
        )]
        vsock_config: String,
    },
    #[command(about = "Statistics from the virtio-balloon device")]
    BalloonStats,
    #[command(about = "Boot a created VM")]
    Boot,
    #[command(about = "Cancel any ongoing migration")]
    CancelMigration,
    #[command(about = "Create a coredump from VM")]
    Coredump {
        #[arg(value_name = "coredump_config", index = 1, help = "<file_path>")]
        coredump_config: String,
    },
    #[command(about = "Counters from the VM")]
    Counters,
    #[command(about = "Create VM from a JSON configuration")]
    Create {
        #[arg(value_name = "path", index = 1, default_value = "-")]
        path: String,
    },
    #[command(about = "Delete a VM")]
    Delete,
    #[command(about = "Info on the VM")]
    Info,
    #[command(about = "Trigger NMI")]
    Nmi,
    #[command(about = "Pause the VM")]
    Pause,
    #[command(about = "Ping the VMM to check for API server availability")]
    Ping,
    #[command(about = "Trigger a power button in the VM")]
    PowerButton,
    #[command(about = "Reboot the VM")]
    Reboot,
    #[command(about = "Receive a VM migration")]
    ReceiveMigration {
        #[arg(
            value_name = "receive_migration_config",
            index = 1,
            help = api::VmReceiveMigrationData::SYNTAX,
        )]
        receive_migration_config: String,
    },
    #[command(about = "Remove VFIO and PCI device")]
    RemoveDevice {
        #[arg(value_name = "id", index = 1, help = "<device_id>")]
        id: String,
    },
    #[command(about = "Resize the VM")]
    Resize {
        #[arg(
            value_name = "balloon",
            long,
            help = "New balloon size in bytes (supports K/M/G suffix)"
        )]
        balloon: Option<String>,
        #[arg(value_name = "cpus", long, help = "New vCPUs count")]
        cpus: Option<String>,
        #[arg(
            value_name = "memory",
            long,
            help = "New memory size in bytes (supports K/M/G suffix)"
        )]
        memory: Option<String>,
    },
    #[command(about = "Resize an attached disk")]
    ResizeDisk {
        #[arg(value_name = "disk", long, help = "Disk identifier")]
        disk: String,
        #[arg(value_name = "size", long, help = "New disk size")]
        size: String,
    },
    #[command(about = "Resize a memory zone")]
    ResizeZone {
        #[arg(value_name = "id", long, help = "Memory zone identifier")]
        id: String,
        #[arg(
            value_name = "size",
            long,
            help = "New memory zone size in bytes (supports K/M/G suffix)"
        )]
        size: String,
    },
    #[command(about = "Restore VM from a snapshot")]
    Restore {
        #[arg(
            value_name = "restore_config",
            index = 1,
            help = RestoreConfig::SYNTAX,
        )]
        restore_config: String,
    },
    #[command(about = "Resume the VM")]
    Resume,
    #[command(about = "Initiate a VM migration")]
    SendMigration {
        #[arg(
            value_name = "send_migration_config",
            index = 1,
            help = api::VmSendMigrationData::SYNTAX,
        )]
        send_migration_config: String,
    },
    #[command(about = "Shutdown the VM")]
    Shutdown,
    #[command(about = "Shutdown the VMM")]
    ShutdownVmm,
    #[command(about = "Create a snapshot from VM")]
    Snapshot {
        #[arg(value_name = "snapshot_config", index = 1, help = "<destination_url>")]
        snapshot_config: String,
    },
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    let fd_command = prepare_fd_command(&cli.command).unwrap_or_else(|error| {
        cloud_hypervisor::cli_print_error_chain(&error, "ch-remote", |_, _, _| None);
        process::exit(1);
    });

    let mut target_api = match (
        cli.api_socket.as_ref(),
        #[cfg(feature = "dbus_api")]
        cli.dbus_service_name.as_ref(),
        #[cfg(feature = "dbus_api")]
        cli.dbus_object_path.as_ref(),
    ) {
        #[cfg(not(feature = "dbus_api"))]
        (Some(api_sock),) => TargetApi::HttpApi(
            UnixStream::connect(api_sock).unwrap_or_else(|e| {
                error!("Error opening HTTP socket: {e}");
                process::exit(1)
            }),
            PhantomData,
        ),
        #[cfg(feature = "dbus_api")]
        (Some(api_sock), None, None) => TargetApi::HttpApi(
            UnixStream::connect(api_sock).unwrap_or_else(|e| {
                error!("Error opening HTTP socket: {e}");
                process::exit(1)
            }),
            PhantomData,
        ),
        #[cfg(feature = "dbus_api")]
        (None, Some(dbus_name), Some(dbus_path)) => TargetApi::DBusApi(
            DBusApi1ProxyBlocking::new_connection(dbus_name, dbus_path, cli.dbus_system_bus)
                .map_err(Error::DBusApiClient)
                .unwrap_or_else(|e| {
                    error!("Error creating D-Bus proxy: {e}");
                    process::exit(1)
                }),
        ),
        #[cfg(feature = "dbus_api")]
        (Some(_), Some(_) | None, Some(_) | None) => {
            error!(
                "`api-socket` and (dbus-service-name or dbus-object-path) are mutually exclusive"
            );
            process::exit(1);
        }
        _ => {
            error!(
                "Please either provide the api-socket option or dbus-service-name and dbus-object-path options"
            );
            process::exit(1);
        }
    };

    if let Err(top_error) = target_api.do_command(&cli.command, fd_command) {
        // Helper to join strings with a newline.
        #[expect(clippy::needless_pass_by_value)]
        fn join_strs(mut acc: String, next: String) -> String {
            if !acc.is_empty() {
                acc.push('\n');
            }
            acc.push_str(&next);
            acc
        }

        // This function helps to modify the Display representation of remote
        // API failures so that it aligns with the regular output of error
        // messages. As we transfer a deep/rich chain of errors as String via
        // the HTTP API, the nested error chain is lost. We retrieve it from
        // the error response.
        //
        // In case the repose itself is broken, the error is printed directly
        // by using the `X` level.
        fn server_api_error_display_modifier(
            level: usize,
            indention: usize,
            error: &(dyn error::Error + 'static),
        ) -> Option<String> {
            if let Some(api_client::Error::ServerResponse(status_code, body)) =
                error.downcast_ref::<api_client::Error>()
            {
                let body = body.as_ref().map_or("", |body| body.as_str());

                // Retrieve the list of error messages back.
                let lines: Vec<String> = match serde_json::from_str(body) {
                    Ok(json) => json,
                    Err(e) => {
                        return Some(format!(
                            "{idention}X: Can't get remote's error messages from JSON response: {e}: body='{body}'",
                            idention = " ".repeat(indention)
                        ));
                    }
                };

                let error_status = format!("Server responded with {status_code:?}");
                // Prepend the error status line to the lines iter.
                let lines =
                    iter::once(error_status.as_str()).chain(lines.iter().map(|s| s.as_str()));
                let error_msg_multiline = lines
                    .enumerate()
                    .map(|(index, error_msg)| (index + level, error_msg))
                    .map(|(level, error_msg)| {
                        format!(
                            "{idention}{level}: {error_msg}",
                            idention = " ".repeat(indention)
                        )
                    })
                    .fold(String::new(), join_strs);

                return Some(error_msg_multiline);
            }

            None
        }

        let top_error: &dyn error::Error = &top_error;
        cloud_hypervisor::cli_print_error_chain(
            top_error,
            "ch-remote",
            server_api_error_display_modifier,
        );
        process::exit(1)
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;
    use crate::test_util::assert_args_sorted;

    #[test]
    fn clap_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_cli_args_sorted() {
        let command = Cli::command();
        assert_args_sorted(|| command.get_arguments());
    }

    #[test]
    fn test_cli_commands_sorted() {
        let command = Cli::command();
        assert!(
            command
                .get_subcommands()
                .map(|cmd| cmd.get_name())
                .is_sorted()
        );
        for subcommand in command.get_subcommands() {
            assert_args_sorted(|| subcommand.get_arguments());
        }
    }

    #[test]
    fn test_typed_command_dispatch() {
        use std::io::Write;
        use std::time::Duration;

        // A local socket pair provides a successful reply without a VMM.
        for (args, request_line, body) in [
            (vec!["boot"], "PUT /api/v1/vm.boot HTTP/1.1", None),
            (vec!["ping"], "GET /api/v1/vmm.ping HTTP/1.1", None),
            (
                vec!["resize", "--cpus", "4", "--memory", "1G", "--balloon", "2M"],
                "PUT /api/v1/vm.resize HTTP/1.1",
                Some(
                    serde_json::json!({"desired_vcpus": 4, "desired_ram": 1073741824u64, "desired_balloon": 2097152}),
                ),
            ),
            (
                vec!["resize-disk", "--disk", "disk0", "--size", "2G"],
                "PUT /api/v1/vm.resize-disk HTTP/1.1",
                Some(serde_json::json!({"id": "disk0", "desired_size": 2147483648u64})),
            ),
            (
                vec!["resize-zone", "--id", "zone0", "--size", "1G"],
                "PUT /api/v1/vm.resize-zone HTTP/1.1",
                Some(serde_json::json!({"id": "zone0", "desired_ram": 1073741824u64})),
            ),
            (
                vec!["snapshot", "file:///tmp/snapshot"],
                "PUT /api/v1/vm.snapshot HTTP/1.1",
                Some(serde_json::json!({"destination_url": "file:///tmp/snapshot"})),
            ),
        ] {
            let cli = Cli::try_parse_from(iter::once("ch-remote").chain(args))
                .expect("the command should parse");
            let (mut client, mut server) =
                UnixStream::pair().expect("the local socket pair should be created");
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("the read timeout should be set");
            server
                .write_all(b"HTTP/1.1 204\r\n\r\n")
                .expect("the response should fit in the socket buffer");

            // Check that typed fields reach the correct HTTP endpoint and body.
            rest_api_do_command(&cli.command, &mut client, None)
                .expect("the command should accept the successful response");
            drop(client);
            let mut request = String::new();
            server
                .read_to_string(&mut request)
                .expect("the request should be readable after the client closes");
            let (headers, actual_body) = request
                .split_once("\r\n\r\n")
                .expect("the request should contain a header terminator");
            assert_eq!(headers.lines().next(), Some(request_line));
            if let Some(body) = body {
                let actual: serde_json::Value =
                    serde_json::from_str(actual_body).expect("the request body should be JSON");
                assert_eq!(actual, body);
            } else {
                assert!(actual_body.is_empty());
            }
        }
    }

    #[test]
    fn test_error_deserialization() {
        let body = r#"["Error from API","The VM could not be snapshotted","Cannot send VM snapshot","Failed to send migratable component snapshot","Destination is not a directory: \"/tmp/ch.dump\""]"#;
        let lines: Result<Vec<String>, _> = serde_json::from_str(body);
        assert!(lines.is_ok());
        let lines = lines.unwrap();
        assert_eq!(lines.len(), 5);
        assert_eq!(
            lines[4],
            r#"Destination is not a directory: "/tmp/ch.dump""#
        );
    }
}
