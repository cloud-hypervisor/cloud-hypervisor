// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};
use std::sync::LazyLock;
use std::thread;

use libfuzzer_sys::{fuzz_target, Corpus};
use micro_http::Request;
use vm_migration::MigratableError;
use vmm::api::http::*;
use vmm::api::{
    ApiRequest, RequestHandler, VmInfoResponse, VmReceiveMigrationData, VmSendMigrationData,
    VmmPingResponse,
};
use vmm::config::RestoreConfig;
use vmm::vm::{Error as VmError, VmState};
use vmm::vm_config::*;
use vmm::{EpollContext, EpollDispatch};
use vmm_sys_util::eventfd::EventFd;

// Need to be ordered for test case reproducibility
static ROUTES: LazyLock<Vec<&Box<dyn EndpointHandler + Sync + Send>>> =
    LazyLock::new(|| HTTP_ROUTES.routes.values().collect());

fuzz_target!(|bytes: &[u8]| -> Corpus {
    if bytes.len() < 2 {
        return Corpus::Reject;
    }

    let route = ROUTES[bytes[0] as usize % ROUTES.len()];
    if let Some(request) = generate_request(&bytes[1..]) {
        let exit_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let api_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let (api_sender, api_receiver) = channel();

        let http_receiver_thread = {
            let exit_evt = exit_evt.try_clone().unwrap();
            let api_evt = api_evt.try_clone().unwrap();
            thread::Builder::new()
                .name("http_receiver".to_string())
                .spawn(move || {
                    http_receiver_stub(exit_evt, api_evt, api_receiver);
                })
                .unwrap()
        };

        route.handle_request(&request, api_evt, api_sender);
        exit_evt.write(1).ok();
        http_receiver_thread.join().unwrap();
    };

    Corpus::Keep
});

fn generate_request(bytes: &[u8]) -> Option<Request> {
    let req_method = match bytes[0] % 5 {
        0 => "GET",
        1 => "PUT",
        2 => "PATCH",
        3 => "POST",
        _ => "INVALID",
    };
    let request_line = format!("{} http://localhost/home HTTP/1.1\r\n", req_method);

    let req_body = &bytes[1..];
    let request = if req_body.len() > 0 {
        [
            format!("{}Content-Length: {}\r\n", request_line, req_body.len()).as_bytes(),
            req_body,
        ]
        .concat()
    } else {
        format!("{}\r\n", request_line).as_bytes().to_vec()
    };

    Request::try_from(&request, None).ok()
}

struct StubApiRequestHandler;

impl RequestHandler for StubApiRequestHandler {
    fn vm_create(&mut self, _: Box<VmConfig>) -> Result<(), VmError> {
        Ok(())
    }

    fn vm_boot(&mut self) -> Result<(), VmError> {
        Ok(())
    }

    fn vm_pause(&mut self) -> Result<(), VmError> {
        Ok(())
    }

    fn vm_resume(&mut self) -> Result<(), VmError> {
        Ok(())
    }

    fn vm_snapshot(&mut self, _: &str) -> Result<(), VmError> {
        Ok(())
    }

    fn vm_restore(&mut self, _: RestoreConfig) -> Result<(), VmError> {
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn vm_coredump(&mut self, _: &str) -> Result<(), VmError> {
        Ok(())
    }

    fn vm_shutdown(&mut self) -> Result<(), VmError> {
        Ok(())
    }

    fn vm_reboot(&mut self) -> Result<(), VmError> {
        Ok(())
    }

    fn vm_info(&self) -> Result<VmInfoResponse, VmError> {
        Ok(VmInfoResponse {
            config: Box::new(VmConfig {
                cpus: CpusConfig {
                    boot_vcpus: 1,
                    max_vcpus: 1,
                    topology: None,
                    kvm_hyperv: false,
                    max_phys_bits: 46,
                    affinity: None,
                    features: CpuFeatures::default(),
                },
                memory: MemoryConfig {
                    size: 536_870_912,
                    mergeable: false,
                    hotplug_method: HotplugMethod::Acpi,
                    hotplug_size: None,
                    hotplugged_size: None,
                    shared: false,
                    hugepages: false,
                    hugepage_size: None,
                    prefault: false,
                    zones: None,
                    thp: true,
                },
                payload: Some(PayloadConfig {
                    kernel: Some(PathBuf::from("/path/to/kernel")),
                    firmware: None,
                    cmdline: None,
                    initramfs: None,
                    #[cfg(feature = "igvm")]
                    igvm: None,
                }),
                rate_limit_groups: None,
                disks: None,
                net: None,
                rng: RngConfig {
                    src: PathBuf::from("/dev/urandom"),
                    iommu: false,
                },
                balloon: None,
                fs: None,
                pmem: None,
                serial: ConsoleConfig {
                    file: None,
                    mode: ConsoleOutputMode::Null,
                    iommu: false,
                    socket: None,
                },
                console: ConsoleConfig {
                    file: None,
                    mode: ConsoleOutputMode::Tty,
                    iommu: false,
                    socket: None,
                },
                #[cfg(target_arch = "x86_64")]
                debug_console: DebugConsoleConfig::default(),
                devices: None,
                user_devices: None,
                vdpa: None,
                vsock: None,
                pvpanic: false,
                #[cfg(feature = "pvmemcontrol")]
                pvmemcontrol: None,
                iommu: false,
                numa: None,
                watchdog: false,
                gdb: false,
                pci_segments: None,
                platform: None,
                tpm: None,
                preserved_fds: None,
                landlock_enable: false,
                landlock_rules: None,
                #[cfg(feature = "ivshmem")]
                ivshmem: None,
            }),
            state: VmState::Running,
            memory_actual_size: 0,
            device_tree: None,
        })
    }

    fn vmm_ping(&self) -> VmmPingResponse {
        VmmPingResponse {
            build_version: String::new(),
            version: String::new(),
            pid: 0,
            features: Vec::new(),
        }
    }

    fn vm_delete(&mut self) -> Result<(), VmError> {
        Ok(())
    }

    fn vmm_shutdown(&mut self) -> Result<(), VmError> {
        Ok(())
    }

    fn vm_resize(&mut self, _: Option<u32>, _: Option<u64>, _: Option<u64>) -> Result<(), VmError> {
        Ok(())
    }

    fn vm_resize_zone(&mut self, _: String, _: u64) -> Result<(), VmError> {
        Ok(())
    }

    fn vm_add_device(&mut self, _: DeviceConfig) -> Result<Option<Vec<u8>>, VmError> {
        Ok(None)
    }

    fn vm_add_user_device(&mut self, _: UserDeviceConfig) -> Result<Option<Vec<u8>>, VmError> {
        Ok(None)
    }

    fn vm_remove_device(&mut self, _: String) -> Result<(), VmError> {
        Ok(())
    }

    fn vm_add_disk(&mut self, _: DiskConfig) -> Result<Option<Vec<u8>>, VmError> {
        Ok(None)
    }

    fn vm_add_fs(&mut self, _: FsConfig) -> Result<Option<Vec<u8>>, VmError> {
        Ok(None)
    }

    fn vm_add_pmem(&mut self, _: PmemConfig) -> Result<Option<Vec<u8>>, VmError> {
        Ok(None)
    }

    fn vm_add_net(&mut self, _: NetConfig) -> Result<Option<Vec<u8>>, VmError> {
        Ok(None)
    }

    fn vm_add_vdpa(&mut self, _: VdpaConfig) -> Result<Option<Vec<u8>>, VmError> {
        Ok(None)
    }

    fn vm_add_vsock(&mut self, _: VsockConfig) -> Result<Option<Vec<u8>>, VmError> {
        Ok(None)
    }

    fn vm_counters(&mut self) -> Result<Option<Vec<u8>>, VmError> {
        Ok(None)
    }

    fn vm_power_button(&mut self) -> Result<(), VmError> {
        Ok(())
    }

    fn vm_receive_migration(&mut self, _: VmReceiveMigrationData) -> Result<(), MigratableError> {
        Ok(())
    }

    fn vm_send_migration(&mut self, _: VmSendMigrationData) -> Result<(), MigratableError> {
        Ok(())
    }

    fn vm_nmi(&mut self) -> Result<(), VmError> {
        Ok(())
    }
}

fn http_receiver_stub(exit_evt: EventFd, api_evt: EventFd, api_receiver: Receiver<ApiRequest>) {
    let mut epoll = EpollContext::new().unwrap();
    epoll.add_event(&exit_evt, EpollDispatch::Exit).unwrap();
    epoll.add_event(&api_evt, EpollDispatch::Api).unwrap();

    let epoll_fd = epoll.as_raw_fd();
    let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); 2];
    let num_events;
    loop {
        num_events = match epoll::wait(epoll_fd, -1, &mut events[..]) {
            Ok(num_events) => num_events,
            Err(e) => match e.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => continue,
                _ => panic!("Unexpected epoll::wait error!"),
            },
        };

        break;
    }

    for event in events.iter().take(num_events) {
        let dispatch_event: EpollDispatch = event.data.into();
        match dispatch_event {
            EpollDispatch::Exit => {
                break;
            }
            EpollDispatch::Api => {
                for _ in 0..api_evt.read().unwrap() {
                    let api_request = api_receiver.recv().unwrap();
                    api_request(&mut StubApiRequestHandler).unwrap();
                }
            }
            _ => {
                panic!("Unexpected Epoll event");
            }
        }
    }
}
