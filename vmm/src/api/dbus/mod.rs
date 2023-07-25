// Copyright © 2023 Sartura Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
use super::{ApiRequest, VmAction};
use crate::seccomp_filters::{get_seccomp_filter, Thread};
use crate::{Error as VmmError, Result as VmmResult};
use crate::{NetConfig, VmConfig};
use futures::channel::oneshot;
use futures::{executor, FutureExt};
use hypervisor::HypervisorType;
use seccompiler::{apply_filter, SeccompAction};
use std::panic::AssertUnwindSafe;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use vmm_sys_util::eventfd::EventFd;
use zbus::fdo::{self, Result};
use zbus::zvariant::Optional;
use zbus::{dbus_interface, ConnectionBuilder};

pub type DBusApiShutdownChannels = (oneshot::Sender<()>, oneshot::Receiver<()>);

pub struct DBusApiOptions {
    pub service_name: String,
    pub object_path: String,
    pub system_bus: bool,
}

pub struct DBusApi {
    api_notifier: EventFd,
    api_sender: futures::lock::Mutex<Sender<ApiRequest>>,
}

fn api_error(error: impl std::fmt::Debug) -> fdo::Error {
    fdo::Error::Failed(format!("{error:?}"))
}

// This method is intended to ensure that the DBusApi thread has enough time to
// send a response to the VmmShutdown method call before it is terminated. If
// this step is omitted, the thread may be terminated before it can send a
// response, resulting in an error message stating that the message recipient
// disconnected from the message bus without providing a reply.
pub fn dbus_api_graceful_shutdown(ch: DBusApiShutdownChannels) {
    let (send_shutdown, mut recv_done) = ch;

    // send the shutdown signal and return
    // if it errors out
    if send_shutdown.send(()).is_err() {
        return;
    }

    // loop until `recv_err` errors out
    // or as long as the return value indicates
    // "immediately stale" (None)
    while let Ok(None) = recv_done.try_recv() {}
}

impl DBusApi {
    pub fn new(api_notifier: EventFd, api_sender: Sender<ApiRequest>) -> Self {
        Self {
            api_notifier,
            api_sender: futures::lock::Mutex::new(api_sender),
        }
    }

    async fn clone_api_sender(&self) -> Sender<ApiRequest> {
        // lock the async mutex, clone the `Sender` and then immediately
        // drop the MutexGuard so that other tasks can clone the
        // `Sender` as well
        self.api_sender.lock().await.clone()
    }

    fn clone_api_notifier(&self) -> Result<EventFd> {
        self.api_notifier
            .try_clone()
            .map_err(|err| fdo::Error::IOError(format!("{err:?}")))
    }

    async fn vm_action(&self, action: VmAction) -> Result<Optional<String>> {
        let api_sender = self.clone_api_sender().await;
        let api_notifier = self.clone_api_notifier()?;

        let result = blocking::unblock(move || super::vm_action(api_notifier, api_sender, action))
            .await
            .map_err(api_error)?
            // We're using `from_utf8_lossy` here to not deal with the
            // error case of `from_utf8` as we know that `b.body` is valid JSON.
            .map(|b| String::from_utf8_lossy(&b.body).to_string());

        Ok(result.into())
    }
}

#[dbus_interface(name = "org.cloudhypervisor.DBusApi1")]
impl DBusApi {
    async fn vmm_ping(&self) -> Result<String> {
        let api_sender = self.clone_api_sender().await;
        let api_notifier = self.clone_api_notifier()?;

        let result = blocking::unblock(move || super::vmm_ping(api_notifier, api_sender))
            .await
            .map_err(api_error)?;
        serde_json::to_string(&result).map_err(api_error)
    }

    async fn vmm_shutdown(&self) -> Result<()> {
        let api_sender = self.clone_api_sender().await;
        let api_notifier = self.clone_api_notifier()?;

        blocking::unblock(move || super::vmm_shutdown(api_notifier, api_sender))
            .await
            .map_err(api_error)
    }

    async fn vm_add_device(&self, device_config: String) -> Result<Optional<String>> {
        let device_config = serde_json::from_str(&device_config).map_err(api_error)?;
        self.vm_action(VmAction::AddDevice(Arc::new(device_config)))
            .await
    }

    async fn vm_add_disk(&self, disk_config: String) -> Result<Optional<String>> {
        let disk_config = serde_json::from_str(&disk_config).map_err(api_error)?;
        self.vm_action(VmAction::AddDisk(Arc::new(disk_config)))
            .await
    }

    async fn vm_add_fs(&self, fs_config: String) -> Result<Optional<String>> {
        let fs_config = serde_json::from_str(&fs_config).map_err(api_error)?;
        self.vm_action(VmAction::AddFs(Arc::new(fs_config))).await
    }

    async fn vm_add_net(&self, net_config: String) -> Result<Optional<String>> {
        let mut net_config: NetConfig = serde_json::from_str(&net_config).map_err(api_error)?;
        if net_config.fds.is_some() {
            warn!("Ignoring FDs sent via the D-Bus request body");
            net_config.fds = None;
        }
        self.vm_action(VmAction::AddNet(Arc::new(net_config))).await
    }

    async fn vm_add_pmem(&self, pmem_config: String) -> Result<Optional<String>> {
        let pmem_config = serde_json::from_str(&pmem_config).map_err(api_error)?;
        self.vm_action(VmAction::AddPmem(Arc::new(pmem_config)))
            .await
    }

    async fn vm_add_user_device(&self, vm_add_user_device: String) -> Result<Optional<String>> {
        let vm_add_user_device = serde_json::from_str(&vm_add_user_device).map_err(api_error)?;
        self.vm_action(VmAction::AddUserDevice(Arc::new(vm_add_user_device)))
            .await
    }

    async fn vm_add_vdpa(&self, vdpa_config: String) -> Result<Optional<String>> {
        let vdpa_config = serde_json::from_str(&vdpa_config).map_err(api_error)?;
        self.vm_action(VmAction::AddVdpa(Arc::new(vdpa_config)))
            .await
    }

    async fn vm_add_vsock(&self, vsock_config: String) -> Result<Optional<String>> {
        let vsock_config = serde_json::from_str(&vsock_config).map_err(api_error)?;
        self.vm_action(VmAction::AddVsock(Arc::new(vsock_config)))
            .await
    }

    async fn vm_boot(&self) -> Result<()> {
        self.vm_action(VmAction::Boot).await.map(|_| ())
    }

    #[allow(unused_variables)]
    // zbus doesn't support cfg attributes on interface methods
    // as a workaround, we make the *call to the internal API* conditionally
    // compile and return an error on unsupported platforms.
    async fn vm_coredump(&self, vm_coredump_data: String) -> Result<()> {
        #[cfg(all(target_arch = "x86_64", feature = "guest_debug"))]
        {
            let vm_coredump_data = serde_json::from_str(&vm_coredump_data).map_err(api_error)?;
            self.vm_action(VmAction::Coredump(Arc::new(vm_coredump_data)))
                .await
                .map(|_| ())
        }

        #[cfg(not(all(target_arch = "x86_64", feature = "guest_debug")))]
        Err(api_error(
            "VmCoredump only works on x86_64 with the `guest_debug` feature enabled",
        ))
    }

    async fn vm_counters(&self) -> Result<Optional<String>> {
        self.vm_action(VmAction::Counters).await
    }

    async fn vm_create(&self, vm_config: String) -> Result<()> {
        let api_sender = self.clone_api_sender().await;
        let api_notifier = self.clone_api_notifier()?;

        let mut vm_config: VmConfig = serde_json::from_str(&vm_config).map_err(api_error)?;

        if let Some(ref mut nets) = vm_config.net {
            if nets.iter().any(|net| net.fds.is_some()) {
                warn!("Ignoring FDs sent via the D-Bus request body");
            }
            for net in nets {
                net.fds = None;
            }
        }

        blocking::unblock(move || {
            super::vm_create(api_notifier, api_sender, Arc::new(Mutex::new(vm_config)))
        })
        .await
        .map_err(api_error)?;

        Ok(())
    }

    async fn vm_delete(&self) -> Result<()> {
        self.vm_action(VmAction::Delete).await.map(|_| ())
    }

    async fn vm_info(&self) -> Result<String> {
        let api_sender = self.clone_api_sender().await;
        let api_notifier = self.clone_api_notifier()?;

        let result = blocking::unblock(move || super::vm_info(api_notifier, api_sender))
            .await
            .map_err(api_error)?;
        serde_json::to_string(&result).map_err(api_error)
    }

    async fn vm_pause(&self) -> Result<()> {
        self.vm_action(VmAction::Pause).await.map(|_| ())
    }

    async fn vm_power_button(&self) -> Result<()> {
        self.vm_action(VmAction::PowerButton).await.map(|_| ())
    }

    async fn vm_reboot(&self) -> Result<()> {
        self.vm_action(VmAction::Reboot).await.map(|_| ())
    }

    async fn vm_remove_device(&self, vm_remove_device: String) -> Result<()> {
        let vm_remove_device = serde_json::from_str(&vm_remove_device).map_err(api_error)?;
        self.vm_action(VmAction::RemoveDevice(Arc::new(vm_remove_device)))
            .await
            .map(|_| ())
    }

    async fn vm_resize(&self, vm_resize: String) -> Result<()> {
        let vm_resize = serde_json::from_str(&vm_resize).map_err(api_error)?;
        self.vm_action(VmAction::Resize(Arc::new(vm_resize)))
            .await
            .map(|_| ())
    }

    async fn vm_resize_zone(&self, vm_resize_zone: String) -> Result<()> {
        let vm_resize_zone = serde_json::from_str(&vm_resize_zone).map_err(api_error)?;
        self.vm_action(VmAction::ResizeZone(Arc::new(vm_resize_zone)))
            .await
            .map(|_| ())
    }

    async fn vm_restore(&self, restore_config: String) -> Result<()> {
        let restore_config = serde_json::from_str(&restore_config).map_err(api_error)?;
        self.vm_action(VmAction::Restore(Arc::new(restore_config)))
            .await
            .map(|_| ())
    }

    async fn vm_receive_migration(&self, receive_migration_data: String) -> Result<()> {
        let receive_migration_data =
            serde_json::from_str(&receive_migration_data).map_err(api_error)?;
        self.vm_action(VmAction::ReceiveMigration(Arc::new(receive_migration_data)))
            .await
            .map(|_| ())
    }

    async fn vm_send_migration(&self, send_migration_data: String) -> Result<()> {
        let send_migration_data = serde_json::from_str(&send_migration_data).map_err(api_error)?;
        self.vm_action(VmAction::SendMigration(Arc::new(send_migration_data)))
            .await
            .map(|_| ())
    }

    async fn vm_resume(&self) -> Result<()> {
        self.vm_action(VmAction::Resume).await.map(|_| ())
    }

    async fn vm_shutdown(&self) -> Result<()> {
        self.vm_action(VmAction::Shutdown).await.map(|_| ())
    }

    async fn vm_snapshot(&self, vm_snapshot_config: String) -> Result<()> {
        let vm_snapshot_config = serde_json::from_str(&vm_snapshot_config).map_err(api_error)?;
        self.vm_action(VmAction::Snapshot(Arc::new(vm_snapshot_config)))
            .await
            .map(|_| ())
    }
}

pub fn start_dbus_thread(
    dbus_options: DBusApiOptions,
    api_notifier: EventFd,
    api_sender: Sender<ApiRequest>,
    seccomp_action: &SeccompAction,
    exit_evt: EventFd,
    hypervisor_type: HypervisorType,
) -> VmmResult<(thread::JoinHandle<VmmResult<()>>, DBusApiShutdownChannels)> {
    let dbus_iface = DBusApi::new(api_notifier, api_sender);
    let connection = executor::block_on(async move {
        let conn_builder = if dbus_options.system_bus {
            ConnectionBuilder::system()?
        } else {
            ConnectionBuilder::session()?
        };

        conn_builder
            .internal_executor(false)
            .name(dbus_options.service_name)?
            .serve_at(dbus_options.object_path, dbus_iface)?
            .build()
            .await
    })
    .map_err(VmmError::CreateDBusSession)?;

    let (send_shutdown, recv_shutdown) = oneshot::channel::<()>();
    let (send_done, recv_done) = oneshot::channel::<()>();

    // Retrieve seccomp filter for API thread
    let api_seccomp_filter = get_seccomp_filter(seccomp_action, Thread::DBusApi, hypervisor_type)
        .map_err(VmmError::CreateSeccompFilter)?;

    let thread_join_handle = thread::Builder::new()
        .name("dbus-thread".to_string())
        .spawn(move || {
            // Apply seccomp filter for API thread.
            if !api_seccomp_filter.is_empty() {
                apply_filter(&api_seccomp_filter)
                    .map_err(VmmError::ApplySeccompFilter)
                    .map_err(|e| {
                        error!("Error applying seccomp filter: {:?}", e);
                        exit_evt.write(1).ok();
                        e
                    })?;
            }

            std::panic::catch_unwind(AssertUnwindSafe(move || {
                executor::block_on(async move {
                    let recv_shutdown = recv_shutdown.fuse();
                    let executor_tick = futures::future::Fuse::terminated();
                    futures::pin_mut!(recv_shutdown, executor_tick);
                    executor_tick.set(connection.executor().tick().fuse());

                    loop {
                        futures::select! {
                            _ = executor_tick => executor_tick.set(connection.executor().tick().fuse()),
                            _ = recv_shutdown => {
                                send_done.send(()).ok();
                                break;
                            },
                        }
                    }
                })
            }))
            .map_err(|_| {
                error!("dbus-api thread panicked");
                exit_evt.write(1).ok()
            })
            .ok();

            Ok(())
        })
        .map_err(VmmError::DBusThreadSpawn)?;

    Ok((thread_join_handle, (send_shutdown, recv_done)))
}
