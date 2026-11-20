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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{panic, thread};

#[cfg(target_arch = "x86_64")]
use devices::interrupt_controller::InterruptController;
#[cfg(feature = "kvm")]
use hypervisor::HypervisorType;
use hypervisor::VmExit;
use log::{error, info};
use vmm_sys_util::eventfd::EventFd;

use super::{Error, Vcpu};
#[cfg(feature = "guest_debug")]
use crate::gdb::get_raw_tid;

pub(super) struct VcpuRunLoop {
    pub(super) vcpu: Arc<Mutex<Vcpu>>,
    #[cfg(feature = "guest_debug")]
    pub(super) vcpu_id: u32,
    pub(super) reset_evt: EventFd,
    pub(super) exit_evt: EventFd,
    pub(super) guest_exit_evt: EventFd,
    pub(super) panic_exit_evt: EventFd,
    #[cfg(feature = "guest_debug")]
    pub(super) vm_debug_evt: EventFd,
    #[cfg(feature = "kvm")]
    pub(super) hypervisor_type: HypervisorType,
    pub(super) vcpus_kill_signalled: Arc<AtomicBool>,
    pub(super) vcpus_pause_signalled: Arc<AtomicBool>,
    pub(super) vcpus_kick_signalled: Arc<AtomicBool>,
    pub(super) vcpu_kill: Arc<AtomicBool>,
    pub(super) vcpu_run_interrupted: Arc<AtomicBool>,
    pub(super) panic_vcpu_run_interrupted: Arc<AtomicBool>,
    pub(super) vcpu_paused: Arc<AtomicBool>,
    #[cfg(target_arch = "x86_64")]
    pub(super) interrupt_controller_clone: Option<Arc<Mutex<dyn InterruptController>>>,
}

impl VcpuRunLoop {
    pub(super) fn run(self) {
        let Self {
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
        } = self;

        panic::catch_unwind(move || {
            loop {
                // If we are being told to pause, we park the thread
                // until the pause boolean is toggled.
                // The resume operation is responsible for toggling
                // the boolean and unpark the thread.
                // We enter a loop because park() could spuriously
                // return. We will then park() again unless the
                // pause boolean has been toggled.

                // Need to use Ordering::SeqCst as we have multiple
                // loads and stores to different atomics and we need
                // to see them in a consistent order in all threads

                if vcpus_pause_signalled.load(Ordering::SeqCst) {
                    // As a pause can be caused by PIO & MMIO exits then we need to ensure they are
                    // completed by returning to KVM_RUN. From the kernel docs:
                    //
                    // For KVM_EXIT_IO, KVM_EXIT_MMIO, KVM_EXIT_OSI, KVM_EXIT_PAPR, KVM_EXIT_XEN,
                    // KVM_EXIT_EPR, KVM_EXIT_X86_RDMSR and KVM_EXIT_X86_WRMSR the corresponding
                    // operations are complete (and guest state is consistent) only after userspace
                    // has re-entered the kernel with KVM_RUN.  The kernel side will first finish
                    // incomplete operations and then check for pending signals.
                    // The pending state of the operation is not preserved in state which is
                    // visible to userspace, thus userspace should ensure that the operation is
                    // completed before performing a live migration.  Userspace can re-enter the
                    // guest with an unmasked signal pending or with the immediate_exit field set
                    // to complete pending operations without allowing any further instructions
                    // to be executed.

                    #[cfg(feature = "kvm")]
                    if matches!(hypervisor_type, HypervisorType::Kvm) {
                        let mut lock = vcpu.lock().unwrap();
                        lock.vcpu.set_immediate_exit(true);
                        if !matches!(lock.run(), Ok(VmExit::Ignore)) {
                            error!("Unexpected VM exit on \"immediate_exit\" run");
                            break;
                        }
                        lock.vcpu.set_immediate_exit(false);
                    }

                    vcpu_run_interrupted.store(true, Ordering::SeqCst);

                    vcpu_paused.store(true, Ordering::SeqCst);
                    while vcpus_pause_signalled.load(Ordering::SeqCst) {
                        thread::park();
                    }
                    vcpu_paused.store(false, Ordering::SeqCst);
                    vcpu_run_interrupted.store(false, Ordering::SeqCst);
                }

                if vcpus_kick_signalled.load(Ordering::SeqCst) {
                    vcpu_run_interrupted.store(true, Ordering::SeqCst);
                    #[cfg(target_arch = "x86_64")]
                    match vcpu.lock().as_ref().unwrap().vcpu.nmi() {
                        Ok(()) => {}
                        Err(e) => {
                            error!("Error when inject nmi {e}");
                            break;
                        }
                    }
                }

                // We've been told to terminate
                if vcpus_kill_signalled.load(Ordering::SeqCst) || vcpu_kill.load(Ordering::SeqCst) {
                    vcpu_run_interrupted.store(true, Ordering::SeqCst);
                    break;
                }

                let mut vcpu = vcpu.lock().unwrap();
                // vcpu.run() returns false on a triple-fault so trigger a reset
                match vcpu.run() {
                    Ok(run) => match run {
                        #[cfg(feature = "kvm")]
                        VmExit::Debug => {
                            info!("VmExit::Debug");
                            #[cfg(feature = "guest_debug")]
                            {
                                vcpus_pause_signalled.store(true, Ordering::SeqCst);
                                let raw_tid = get_raw_tid(vcpu_id as usize);
                                vm_debug_evt.write(raw_tid as u64).unwrap();
                            }
                        }
                        #[cfg(target_arch = "x86_64")]
                        VmExit::IoapicEoi(vector) => {
                            if let Some(interrupt_controller) = &interrupt_controller_clone {
                                interrupt_controller
                                    .lock()
                                    .unwrap()
                                    .end_of_interrupt(vector);
                            }
                        }
                        VmExit::Ignore => {}
                        VmExit::Hyperv => {}
                        VmExit::Reset => {
                            info!("VmExit::Reset");
                            vcpu_run_interrupted.store(true, Ordering::SeqCst);
                            reset_evt.write(1).unwrap();
                            break;
                        }
                        VmExit::Shutdown => {
                            info!("VmExit::Shutdown");
                            vcpu_run_interrupted.store(true, Ordering::SeqCst);
                            guest_exit_evt.write(1).unwrap();
                            break;
                        }
                    },

                    Err(e) => {
                        error!("VCPU generated error: {:?}", Error::VcpuRun(e));
                        vcpu_run_interrupted.store(true, Ordering::SeqCst);
                        exit_evt.write(1).unwrap();
                        break;
                    }
                }

                // We've been told to terminate
                if vcpus_kill_signalled.load(Ordering::SeqCst) || vcpu_kill.load(Ordering::SeqCst) {
                    vcpu_run_interrupted.store(true, Ordering::SeqCst);
                    break;
                }
            }
        })
        .or_else(|_| {
            panic_vcpu_run_interrupted.store(true, Ordering::SeqCst);
            error!("vCPU thread panicked");
            panic_exit_evt.write(1)
        })
        .ok();
    }
}
