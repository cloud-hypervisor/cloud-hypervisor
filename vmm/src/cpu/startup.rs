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

use std::mem::zeroed;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Barrier, Mutex};
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

fn initialize_core_scheduling(
    vcpu_id: u32,
    core_scheduling: CoreScheduling,
    core_scheduling_group_leader: &AtomicI32,
) -> bool {
    // Set up core scheduling before seccomp locks down prctl.
    match core_scheduling {
        CoreScheduling::Vcpu => {
            // Each vCPU gets its own unique cookie
            if let Err(e) = core_scheduling_create() {
                error!("Failed to enable core scheduling for vCPU {vcpu_id}: {e:?}");
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
                    error!("Failed to create core scheduling cookie: {e:?}");
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
                    error!(
                        "Failed to share core scheduling cookie \
                             to vCPU {vcpu_id}: {e:?}"
                    );
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
        vcpu_thread_barrier: Arc<Barrier>,
        vcpu_seccomp_filter: Arc<BpfProgram>,
        inserting: bool,
    ) -> Result<()> {
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

        let handle = Some(
            thread::Builder::new()
                .name(format!("vcpu{vcpu_id}"))
                .spawn(move || {
                    // Schedule the thread to run on the expected CPU set
                    if let Some(cpuset) = cpuset.as_ref()
                        && let Err(e) = set_vcpu_affinity(cpuset)
                    {
                        error!("Failed scheduling the vCPU {vcpu_id} on the expected CPU set: {e}");
                        return;
                    }

                    if !initialize_core_scheduling(
                        vcpu_id,
                        core_scheduling,
                        &core_scheduling_group_leader,
                    ) {
                        return;
                    }

                    // Apply seccomp filter for vcpu thread.
                    if !vcpu_seccomp_filter.is_empty()
                        && let Err(e) =
                            apply_filter(&vcpu_seccomp_filter).map_err(Error::ApplySeccompFilter)
                    {
                        error!("Error applying seccomp filter: {e:?}");
                        return;
                    }

                    extern "C" fn handle_signal(_: i32, _: *mut siginfo_t, _: *mut c_void) {}
                    // This uses an async signal safe handler to kill the vcpu handles.
                    register_signal_handler(SIGRTMIN(), handle_signal)
                        .expect("Failed to register vcpu signal handler");
                    // Block until all CPUs are ready.
                    vcpu_thread_barrier.wait();

                    run_loop.run();
                })
                .map_err(Error::VcpuSpawn)?,
        );

        // On hot plug calls into this function entry_point is None. It is for
        // those hotplug CPU additions that we need to set the inserting flag.
        let mut vcpu_states = self.vcpu_states.lock().unwrap();
        vcpu_states[usize::try_from(vcpu_id).unwrap()].handle = handle;
        vcpu_states[usize::try_from(vcpu_id).unwrap()].inserting = inserting;

        Ok(())
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
        let vcpu_thread_barrier =
            Arc::new(Barrier::new((desired_vcpus - present_vcpus + 1) as usize));

        if let Some(paused) = paused {
            self.vcpus_pause_signalled.store(paused, Ordering::SeqCst);
        }

        info!(
            "Starting vCPUs: desired = {}, allocated = {}, present = {}, paused = {}",
            desired_vcpus,
            self.vcpus.len(),
            present_vcpus,
            self.vcpus_pause_signalled.load(Ordering::SeqCst)
        );

        if present_vcpus < desired_vcpus {
            let vcpu_seccomp_filter = Arc::new(
                get_seccomp_filter(
                    &self.seccomp_action,
                    Thread::Vcpu,
                    Some(self.hypervisor.hypervisor_type()),
                )
                .map_err(Error::CreateSeccompFilter)?,
            );

            // This reuses any inactive vCPUs as well as any that were newly created
            for vcpu_id in present_vcpus..desired_vcpus {
                let vcpu = Arc::clone(&self.vcpus[vcpu_id as usize]);
                self.start_vcpu(
                    vcpu,
                    vcpu_id,
                    Arc::clone(&vcpu_thread_barrier),
                    Arc::clone(&vcpu_seccomp_filter),
                    inserting,
                )?;
            }
        }

        // Unblock all CPU threads.
        vcpu_thread_barrier.wait();
        Ok(())
    }

    // Starts all the vCPUs that the VM is booting with. Blocks until all vCPUs are running.
    pub fn start_boot_vcpus(&mut self, paused: bool) -> Result<()> {
        self.activate_vcpus(self.boot_vcpus(), false, Some(paused))
    }

    pub fn start_restored_vcpus(&mut self) -> Result<()> {
        if let Some(state) = self.state.take() {
            self.vcpus_pause_signalled.store(true, Ordering::SeqCst);
            let active_vcpus = state.active_vcpus.iter().filter(|&&active| active).count();
            let barrier = Arc::new(Barrier::new(active_vcpus + 1));
            let seccomp_filter = Arc::new(
                get_seccomp_filter(
                    &self.seccomp_action,
                    Thread::Vcpu,
                    Some(self.hypervisor.hypervisor_type()),
                )
                .map_err(Error::CreateSeccompFilter)?,
            );

            for (id, active) in state.active_vcpus.into_iter().enumerate() {
                if active {
                    let inserting = self.vcpu_states.lock().unwrap()[id].inserting;
                    self.start_vcpu(
                        Arc::clone(&self.vcpus[id]),
                        id as u32,
                        Arc::clone(&barrier),
                        Arc::clone(&seccomp_filter),
                        inserting,
                    )?;
                }
            }
            barrier.wait();
            return Ok(());
        }

        self.activate_vcpus(self.vcpus.len() as u32, false, Some(true))
            .map_err(|e| {
                Error::StartRestoreVcpu(anyhow!("Failed to start restored vCPUs: {e:#?}"))
            })?;

        Ok(())
    }
}
