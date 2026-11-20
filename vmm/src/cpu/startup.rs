// Copyright © 2020, Oracle and/or its affiliates.
//
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//

use std::mem::{self, zeroed};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread::JoinHandle;
use std::{hint, io, thread};

use anyhow::anyhow;
use libc::{c_void, siginfo_t};
use log::{debug, error, info};
use seccompiler::{BpfProgram, apply_filter};
use vmm_sys_util::signal::{SIGRTMIN, register_signal_handler};

use super::run::VcpuRunLoop;
use super::{
    CoreSchedulingLeader, CpuManager, Error, Result, Vcpu, core_scheduling_cookie,
    core_scheduling_create, core_scheduling_share_from,
};
use crate::seccomp_filters::{Thread, get_seccomp_filter};
use crate::vm_config::CoreScheduling;

fn set_vcpu_affinity(cpuset: &libc::cpu_set_t) -> io::Result<()> {
    // SAFETY: cpuset is a valid initialized set of the supplied size, and pid
    // zero applies the affinity to the calling thread.
    if unsafe { libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), cpuset) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(super) struct VcpuStartup {
    ready_tx: Option<mpsc::Sender<Result<()>>>,
    ready_rx: mpsc::Receiver<Result<()>>,
    start: Arc<OnceLock<bool>>,
    threads: Vec<(u32, bool, JoinHandle<()>)>,
}

impl VcpuStartup {
    pub(super) fn new() -> Self {
        let (ready_tx, ready_rx) = mpsc::channel();
        Self {
            ready_tx: Some(ready_tx),
            ready_rx,
            start: Arc::new(OnceLock::new()),
            threads: Vec::new(),
        }
    }

    pub(super) fn cancelled(&self) -> bool {
        self.start.get() == Some(&false)
    }

    pub(super) fn spawn(
        &mut self,
        vcpu_id: u32,
        inserting: bool,
        spawn: impl FnOnce(VcpuStartupGuard) -> Result<JoinHandle<()>>,
    ) -> Result<()> {
        let guard = VcpuStartupGuard {
            vcpu_id,
            ready_tx: Some(self.ready_tx.as_ref().unwrap().clone()),
            start: Arc::clone(&self.start),
        };
        let handle = spawn(guard).map_err(|source| Error::VcpuStartup {
            vcpu_id,
            source: Box::new(source),
        })?;
        self.threads.push((vcpu_id, inserting, handle));
        Ok(())
    }

    pub(super) fn finish(
        mut self,
        register: impl FnOnce(Vec<(u32, bool, JoinHandle<()>)>),
    ) -> Result<()> {
        self.ready_tx.take();
        for _ in &self.threads {
            self.ready_rx.recv().map_err(Error::VcpuStartupReceive)??;
        }

        register(mem::take(&mut self.threads));
        // All workers disarmed their failure guards before reporting ready.
        // Register their handles before any worker enters the vCPU run loop.
        self.start
            .set(true)
            .expect("vCPU startup cancelled after every worker reported ready");
        Ok(())
    }
}

impl Drop for VcpuStartup {
    fn drop(&mut self) {
        let _ = self.start.set(false);
        for (vcpu_id, _, handle) in self.threads.drain(..) {
            if let Err(e) = handle.join() {
                error!("vCPU {vcpu_id} panicked during initialization: {e:?}");
            }
        }
    }
}

pub(super) struct VcpuStartupGuard {
    vcpu_id: u32,
    ready_tx: Option<mpsc::Sender<Result<()>>>,
    start: Arc<OnceLock<bool>>,
}

impl VcpuStartupGuard {
    pub(super) fn cancelled(&self) -> bool {
        self.start.get() == Some(&false)
    }

    pub(super) fn fail(&mut self, source: Error) {
        if let Some(sender) = self.ready_tx.take() {
            // Publish the original error before cancellation makes other
            // workers exit and report their own initialization failures.
            let _ = sender.send(Err(Error::VcpuStartup {
                vcpu_id: self.vcpu_id,
                source: Box::new(source),
            }));
            let _ = self.start.set(false);
        }
    }

    pub(super) fn ready(mut self) -> bool {
        if self.ready_tx.take().unwrap().send(Ok(())).is_err() {
            return false;
        }
        *self.start.wait()
    }
}

impl Drop for VcpuStartupGuard {
    fn drop(&mut self) {
        if self.ready_tx.is_some() {
            self.fail(Error::VcpuInitializationExited);
        }
    }
}

fn initialize_core_scheduling(
    vcpu_id: u32,
    core_scheduling: CoreScheduling,
    core_scheduling_group_leader: &AtomicI32,
    startup: &mut VcpuStartupGuard,
) -> bool {
    // Set up core scheduling before seccomp locks down prctl.
    match core_scheduling {
        CoreScheduling::Vcpu => {
            // Each vCPU gets its own unique cookie
            if let Err(e) = core_scheduling_create() {
                startup.fail(e);
                return false;
            }
        }
        CoreScheduling::Vm => {
            // First vCPU creates a cookie; all others share from it.
            // SAFETY: gettid() is always safe to call.
            let my_tid = unsafe { libc::gettid() };
            if core_scheduling_group_leader
                .compare_exchange(
                    CoreSchedulingLeader::Initial as i32,
                    CoreSchedulingLeader::Elected as i32,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                // We are the group leader — create the cookie
                if let Err(e) = core_scheduling_create() {
                    startup.fail(e);
                    // This will force the loop in the other threads to break out
                    core_scheduling_group_leader
                        .store(CoreSchedulingLeader::Error as i32, Ordering::Release);
                    return false;
                }
                // Signal that the cookie is ready by storing real TID
                core_scheduling_group_leader.store(my_tid, Ordering::Release);
            } else {
                // Wait for the leader to finish creating the cookie
                let leader_tid = loop {
                    if startup.cancelled() {
                        return false;
                    }
                    let v = core_scheduling_group_leader.load(Ordering::Acquire);
                    match CoreSchedulingLeader::try_from(v) {
                        Ok(CoreSchedulingLeader::Error) => return false,
                        Ok(CoreSchedulingLeader::Initial | CoreSchedulingLeader::Elected) => {
                            hint::spin_loop();
                        }
                        Err(()) => break v,
                    }
                };
                if let Err(e) = core_scheduling_share_from(leader_tid) {
                    startup.fail(e);
                    return false;
                }
            }
        }
        CoreScheduling::Off => {}
    }

    if core_scheduling != CoreScheduling::Off {
        info!(
            "vCPU {vcpu_id}: core scheduling cookie = {:#x}",
            core_scheduling_cookie()
        );
    }

    true
}

impl CpuManager {
    fn start_vcpu(
        &mut self,
        vcpu: Arc<Mutex<Vcpu>>,
        vcpu_id: u32,
        mut startup: VcpuStartupGuard,
        vcpu_seccomp_filter: Arc<BpfProgram>,
    ) -> Result<thread::JoinHandle<()>> {
        let reset_evt = self.reset_evt.try_clone().map_err(Error::EventFdClone)?;
        let exit_evt = self.exit_evt.try_clone().map_err(Error::EventFdClone)?;
        let guest_exit_evt = self
            .guest_exit_evt
            .try_clone()
            .map_err(Error::EventFdClone)?;

        #[cfg(feature = "kvm")]
        let hypervisor_type = self.hypervisor.hypervisor_type();
        #[cfg(feature = "guest_debug")]
        let vm_debug_evt = self.vm_debug_evt.try_clone().map_err(Error::EventFdClone)?;
        let panic_exit_evt = self.exit_evt.try_clone().map_err(Error::EventFdClone)?;
        let vcpus_kill_signalled = Arc::clone(&self.vcpus_kill_signalled);
        let vcpus_pause_signalled = Arc::clone(&self.vcpus_pause_signalled);
        let vcpus_kick_signalled = Arc::clone(&self.vcpus_kick_signalled);

        let (vcpu_kill, vcpu_run_interrupted, vcpu_paused) = {
            let vcpu_states = self.vcpu_states.lock().unwrap();
            let state = &vcpu_states[usize::try_from(vcpu_id).unwrap()];
            (
                Arc::clone(&state.kill),
                Arc::clone(&state.vcpu_run_interrupted),
                Arc::clone(&state.paused),
            )
        };
        let panic_vcpu_run_interrupted = Arc::clone(&vcpu_run_interrupted);

        // Prepare the CPU set the current vCPU is expected to run onto.
        let cpuset = self.affinity.get(&vcpu_id).map(|host_cpus| {
            // SAFETY: all zeros is a valid pattern
            let mut cpuset: libc::cpu_set_t = unsafe { zeroed() };
            // SAFETY: FFI call, trivially safe
            unsafe { libc::CPU_ZERO(&mut cpuset) };
            for host_cpu in host_cpus {
                // SAFETY: FFI call, trivially safe
                unsafe { libc::CPU_SET(*host_cpu, &mut cpuset) };
            }
            cpuset
        });

        let core_scheduling = self.config.core_scheduling;
        let core_scheduling_group_leader = Arc::clone(&self.core_scheduling_group_leader);

        #[cfg(target_arch = "x86_64")]
        let interrupt_controller_clone = self.interrupt_controller.as_ref().cloned();

        let run_loop = VcpuRunLoop {
            vcpu,
            #[cfg(feature = "guest_debug")]
            vcpu_id,
            reset_evt,
            exit_evt,
            guest_exit_evt,
            panic_exit_evt,
            #[cfg(feature = "guest_debug")]
            vm_debug_evt,
            #[cfg(feature = "kvm")]
            hypervisor_type,
            vcpus_kill_signalled,
            vcpus_pause_signalled,
            vcpus_kick_signalled,
            vcpu_kill,
            vcpu_run_interrupted,
            panic_vcpu_run_interrupted,
            vcpu_paused,
            #[cfg(target_arch = "x86_64")]
            interrupt_controller_clone,
        };

        debug!("Starting vCPU: cpu_id = {vcpu_id}");

        thread::Builder::new()
            .name(format!("vcpu{vcpu_id}"))
            .spawn(move || {
                if startup.cancelled() {
                    return;
                }
                // Schedule the thread to run on the expected CPU set
                if let Some(cpuset) = cpuset.as_ref()
                    && let Err(e) = set_vcpu_affinity(cpuset)
                {
                    startup.fail(Error::SetVcpuAffinity(e));
                    return;
                }

                if !initialize_core_scheduling(
                    vcpu_id,
                    core_scheduling,
                    &core_scheduling_group_leader,
                    &mut startup,
                ) {
                    return;
                }

                // Apply seccomp filter for vcpu thread.
                if !vcpu_seccomp_filter.is_empty()
                    && let Err(e) =
                        apply_filter(&vcpu_seccomp_filter).map_err(Error::ApplySeccompFilter)
                {
                    startup.fail(e);
                    return;
                }

                extern "C" fn handle_signal(_: i32, _: *mut siginfo_t, _: *mut c_void) {}
                // This uses an async signal safe handler to kill the vcpu handles.
                if let Err(e) = register_signal_handler(SIGRTMIN(), handle_signal) {
                    startup.fail(Error::RegisterVcpuSignal(e));
                    return;
                }
                if !startup.ready() {
                    return;
                }

                run_loop.run();
            })
            .map_err(Error::VcpuSpawn)
    }

    fn start_vcpus(&mut self, vcpus: Vec<(u32, bool)>, paused: Option<bool>) -> Result<()> {
        if vcpus.is_empty() {
            if let Some(paused) = paused {
                self.vcpus_pause_signalled.store(paused, Ordering::SeqCst);
            }
            return Ok(());
        }

        let seccomp_filter = Arc::new(
            get_seccomp_filter(
                &self.seccomp_action,
                Thread::Vcpu,
                Some(self.hypervisor.hypervisor_type()),
            )
            .map_err(Error::CreateSeccompFilter)?,
        );
        let previous_paused =
            paused.map(|paused| self.vcpus_pause_signalled.swap(paused, Ordering::SeqCst));
        let previous_leader = self.core_scheduling_group_leader.load(Ordering::Acquire);

        let result = (|| {
            let mut startup = VcpuStartup::new();
            for (vcpu_id, inserting) in vcpus {
                let vcpu = Arc::clone(&self.vcpus[vcpu_id as usize]);
                startup.spawn(vcpu_id, inserting, |guard| {
                    self.start_vcpu(vcpu, vcpu_id, guard, Arc::clone(&seccomp_filter))
                })?;
                if startup.cancelled() {
                    break;
                }
            }
            startup.finish(|threads| {
                let mut states = self.vcpu_states.lock().unwrap();
                for (vcpu_id, inserting, handle) in threads {
                    let state = &mut states[vcpu_id as usize];
                    state.handle = Some(handle);
                    state.inserting = inserting;
                }
            })
        })();

        // The startup guard cancels and joins the new threads before rollback.
        if result.is_err() {
            if let Some(paused) = previous_paused {
                self.vcpus_pause_signalled.store(paused, Ordering::SeqCst);
            }
            self.core_scheduling_group_leader
                .store(previous_leader, Ordering::Release);
        }
        result
    }

    /// Start up as many vCPUs threads as needed to reach `desired_vcpus`
    pub(super) fn activate_vcpus(
        &mut self,
        desired_vcpus: u32,
        inserting: bool,
        paused: Option<bool>,
    ) -> Result<()> {
        if desired_vcpus > self.config.max_vcpus {
            return Err(Error::DesiredVCpuCountExceedsMax);
        }

        let present_vcpus = self.present_vcpus();

        info!(
            "Starting vCPUs: desired = {}, allocated = {}, present = {}, paused = {}",
            desired_vcpus,
            self.vcpus.len(),
            present_vcpus,
            paused.unwrap_or_else(|| self.vcpus_pause_signalled.load(Ordering::SeqCst))
        );

        self.start_vcpus(
            (present_vcpus..desired_vcpus)
                .map(|vcpu_id| (vcpu_id, inserting))
                .collect(),
            paused,
        )
    }

    // Starts all the vCPUs that the VM is booting with. Blocks until all vCPUs are running.
    pub fn start_boot_vcpus(&mut self, paused: bool) -> Result<()> {
        self.activate_vcpus(self.boot_vcpus(), false, Some(paused))
    }

    pub fn start_restored_vcpus(&mut self) -> Result<()> {
        if let Some(state) = self.state.as_ref() {
            let vcpus = state
                .active_vcpus
                .iter()
                .enumerate()
                .filter(|(_, active)| **active)
                .map(|(id, _)| (id as u32, self.vcpu_states.lock().unwrap()[id].inserting))
                .collect();
            self.start_vcpus(vcpus, Some(true))?;
            self.state = None;
            return Ok(());
        }

        self.activate_vcpus(self.vcpus.len() as u32, false, Some(true))
            .map_err(|e| {
                Error::StartRestoreVcpu(anyhow!("Failed to start restored vCPUs: {e:#?}"))
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::{io, thread};

    use super::*;

    #[derive(Clone, Default)]
    struct Progress {
        ready: Arc<AtomicUsize>,
        ran: Arc<AtomicUsize>,
        exited: Arc<AtomicUsize>,
    }

    impl Progress {
        fn spawn(&self, startup: &mut VcpuStartup, id: u32, inserting: bool) {
            let progress = self.clone();
            startup
                .spawn(id, inserting, |guard| {
                    thread::Builder::new()
                        .spawn(move || {
                            progress.ready.fetch_add(1, Ordering::SeqCst);
                            if guard.ready() {
                                progress.ran.fetch_add(1, Ordering::SeqCst);
                            }
                            progress.exited.fetch_add(1, Ordering::SeqCst);
                        })
                        .map_err(Error::VcpuSpawn)
                })
                .unwrap();
        }
    }

    #[test]
    fn register_sparse_vcpus_before_running() {
        let mut startup = VcpuStartup::new();
        let progress = Progress::default();
        progress.spawn(&mut startup, 0, false);
        progress.spawn(&mut startup, 2, true);

        let mut registered = Vec::new();
        startup
            .finish(|threads| {
                assert_eq!(progress.ready.load(Ordering::SeqCst), 2);
                assert_eq!(progress.ran.load(Ordering::SeqCst), 0);
                assert_eq!(
                    threads
                        .iter()
                        .map(|(id, inserting, _)| (*id, *inserting))
                        .collect::<Vec<_>>(),
                    [(0, false), (2, true)]
                );
                registered = threads;
            })
            .unwrap();
        for (_, _, handle) in registered {
            handle.join().unwrap();
        }
        assert_eq!(progress.ran.load(Ordering::SeqCst), 2);
        assert_eq!(progress.exited.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn failure_cancels_ready_and_initializing_workers() {
        let mut startup = VcpuStartup::new();
        let progress = Progress::default();
        progress.spawn(&mut startup, 0, false);
        let exited = Arc::clone(&progress.exited);
        startup
            .spawn(1, false, |guard| {
                Ok(thread::spawn(move || {
                    while !guard.cancelled() {
                        thread::yield_now();
                    }
                    exited.fetch_add(1, Ordering::SeqCst);
                }))
            })
            .unwrap();
        let exited = Arc::clone(&progress.exited);
        startup
            .spawn(2, false, |mut guard| {
                Ok(thread::spawn(move || {
                    guard.fail(Error::SetVcpuAffinity(io::Error::other(
                        "Injected initialization failure",
                    )));
                    exited.fetch_add(1, Ordering::SeqCst);
                }))
            })
            .unwrap();

        let error = startup
            .finish(|_| panic!("Failed vCPUs must not be registered"))
            .unwrap_err();
        let Error::VcpuStartup { vcpu_id, source } = error else {
            panic!("Unexpected startup error: {error}");
        };
        assert_eq!(vcpu_id, 2);
        let Error::SetVcpuAffinity(source) = *source else {
            panic!("Unexpected initialization error");
        };
        assert_eq!(source.to_string(), "Injected initialization failure");
        assert_eq!(progress.ran.load(Ordering::SeqCst), 0);
        assert_eq!(progress.exited.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn panic_before_ready_aborts_startup() {
        let mut startup = VcpuStartup::new();
        let progress = Progress::default();
        progress.spawn(&mut startup, 0, false);
        startup
            .spawn(1, false, |guard| {
                Ok(thread::spawn(move || {
                    let _guard = guard;
                    panic!("Injected initialization panic");
                }))
            })
            .unwrap();

        assert!(matches!(
            startup.finish(|_| panic!("Panicked vCPUs must not be registered")),
            Err(Error::VcpuStartup { vcpu_id: 1, .. })
        ));
        assert_eq!(progress.ran.load(Ordering::SeqCst), 0);
        assert_eq!(progress.exited.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn early_exit_before_ready_aborts_startup() {
        let mut startup = VcpuStartup::new();
        startup
            .spawn(3, false, |guard| Ok(thread::spawn(move || drop(guard))))
            .unwrap();
        assert!(matches!(
            startup.finish(|_| panic!("Exited vCPUs must not be registered")),
            Err(Error::VcpuStartup { vcpu_id: 3, .. })
        ));
    }

    #[test]
    fn partial_spawn_failure_joins_started_workers() {
        let progress = Progress::default();
        let result = (|| {
            let mut startup = VcpuStartup::new();
            progress.spawn(&mut startup, 0, false);
            startup.spawn(1, false, |_guard| {
                Err(Error::VcpuSpawn(io::Error::other("Injected spawn failure")))
            })?;
            startup.finish(|_| panic!("Partially spawned vCPUs must not be registered"))
        })();
        assert!(matches!(result, Err(Error::VcpuStartup { vcpu_id: 1, .. })));
        assert_eq!(progress.ran.load(Ordering::SeqCst), 0);
        assert_eq!(progress.exited.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dropping_startup_joins_waiting_workers() {
        let mut startup = VcpuStartup::new();
        let progress = Progress::default();
        progress.spawn(&mut startup, 0, false);
        progress.spawn(&mut startup, 1, false);
        drop(startup);
        assert_eq!(progress.ran.load(Ordering::SeqCst), 0);
        assert_eq!(progress.exited.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn empty_startup_completes() {
        VcpuStartup::new()
            .finish(|threads| assert!(threads.is_empty()))
            .unwrap();
    }
}
