// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use hypervisor::arch::x86::MsrEntry;
use log::{debug, error};

use crate::x86_64::Error;
use crate::x86_64::cpu_profile::msr_adjustments::RequiredMsrUpdates;

/// The register address of the IA32_ARCH_CAPABILITIES MSR
const IA32_ARCH_CAPABILITIES: u32 = 0x10a;

/// Check that the MSR updates required by the CPU profile are compatible with the
/// host's feature MSRs.
pub fn valid_required_arch_capabilities_update(
    required_updates: &RequiredMsrUpdates,
    host_feature_msrs: &[MsrEntry],
) -> Result<(), Error> {
    let find_arch_capabilities = |msrs: &[MsrEntry]| {
        msrs.iter()
            .find(|msr| msr.index == IA32_ARCH_CAPABILITIES)
            .map(|entry| entry.data)
    };

    let Some(required_arch_capabilities_msr) =
        find_arch_capabilities(&required_updates.feature_msrs)
    else {
        return Ok(());
    };

    let Some(host_arch_capabilities) = find_arch_capabilities(host_feature_msrs) else {
        error!(
            "The host seems to be missing MSR IA32_ARCH_CAPABILITIES, but the CPU profile demands its existence"
        );
        return Err(Error::CpuProfileMissingMsr);
    };

    if is_arch_capabilities_compatible(
        required_arch_capabilities_msr,
        host_arch_capabilities,
        "CPU Profile",
        "Host",
    ) {
        Ok(())
    } else {
        Err(Error::CpuProfileMsrIncompatibility)
    }
}

/// If `src_val` and `dest_val` are two different possible values of IA32_ARCH_CAPABILITIES, then
/// this returns `true` when `src_val` is considered compatible with `dest_val`.
///
/// If this check fails then programs that work when the value is `src_val`, may possibly
/// no longer work if the value is `dest_val`.
///
/// The `src_id` and `dest_id` parameters are used to identify where `src_val` and `dest_val`
/// originate from (e.g. CPU profile, Host) when logging the detected incompatibility.
pub fn is_arch_capabilities_compatible(
    src_val: u64,
    dest_val: u64,
    src_id: &str,
    dest_id: &str,
) -> bool {
    const RSBA_MASK: u64 = 1 << 2;
    const RRSBA_MASK: u64 = 1 << 19;
    // We consider it unsafe to migrate from a machine without RSBA or RRSBA to one that advertises this behavior.
    // We consider the converse safe: Return stack buffer underflow mitigations can still be applied even if they
    // may no longer be necessary after migrating. This of course assumes that the destination is capable of applying
    // said mitigations, but that should be ensured by other CPUID and/or MSR value checks.
    const SUPERSET_MASK: u64 = RSBA_MASK | RRSBA_MASK;

    // Bits 31 and 32..=61 are (currently) reserved
    const RESERVED_MASK: u64 = {
        let bits_0_to_61 = (1_u64 << 62) - 1;
        let bits_0_to_32 = (1_u64 << 33) - 1;
        (bits_0_to_61 ^ bits_0_to_32) | (1 << 31)
    };

    const SUBSET_MASK: u64 = !(SUPERSET_MASK | RESERVED_MASK);
    const CHECK_ID: &str = "IA32_ARCH_CAPABILITIES";

    const MDS_NO_MASK: u64 = 1 << 5;
    const TAA_NO_MASK: u64 = 1 << 8;
    const SBDR_SSDP_NO_MASK: u64 = 1 << 13;
    const FBSDP_NO_MASK: u64 = 1 << 14;
    const PSDP_NO_MASK: u64 = 1 << 15;
    const FB_CLEAR_MASK: u64 = 1 << 17;
    const TOLERATE_MISSING_FB_CLEAR_MASK: u64 =
        MDS_NO_MASK | TAA_NO_MASK | SBDR_SSDP_NO_MASK | FBSDP_NO_MASK | PSDP_NO_MASK;

    // For safety reasons we will require equality on the reserved bits for now: If/when they become unreserved then we can adjust the checks
    // accordingly.
    let reserved_eq_check = is_eq_debug_log(
        src_val & RESERVED_MASK,
        dest_val & RESERVED_MASK,
        src_id,
        dest_id,
        CHECK_ID,
    );

    let mut subset_check = true;
    if let Err(only_in_src) = check_subset(src_val & SUBSET_MASK, dest_val & SUBSET_MASK) {
        // If the only bit that is only in source is 17 (FB_CLEAR) and dest_val has
        // certain mitigation bits set, then src_val is actually compatible with
        // dest_val. QEMU does in fact always artificially set bit 17 in that case: See
        // https://github.com/qemu/qemu/blob/v11.0.1/target/i386/kvm/kvm.c#L679-L685
        //
        // TODO: Perhaps we should also rather make Hypervisor::get_msr_based_features() adjust bit
        // 17? With CPU profiles this doesn't seem necessary though.
        if !(((dest_val & TOLERATE_MISSING_FB_CLEAR_MASK) == TOLERATE_MISSING_FB_CLEAR_MASK)
            && (only_in_src == FB_CLEAR_MASK))
        {
            subset_check = false;
            debug_log_features_only_in(only_in_src, src_id, CHECK_ID);
        }
    }

    let superset_check = is_subset_debug_log(
        dest_val & SUPERSET_MASK,
        src_val & SUPERSET_MASK,
        dest_id,
        CHECK_ID,
    );

    let is_err = !(reserved_eq_check && subset_check && superset_check);

    if is_err {
        error!(
            "IA32_ARCH_CAPABILITIES compatibility check failed: {src_id} value:={src_val:#x}, {dest_id} value:={dest_val:#x}"
        );

        false
    } else {
        true
    }
}

/// Check that no bits are only in `a`.
///
/// Upon error a bitset is returned with the bits that are only available in
/// `a`.
fn check_subset(a: u64, b: u64) -> Result<(), u64> {
    let only_in_a = a & (a ^ b);
    if only_in_a != 0 {
        Err(only_in_a)
    } else {
        Ok(())
    }
}

/// Logs that the `check_id` compatibility check failed with each bit position in `only_in`.
///
/// The `id` parameter is used to identify where `only_in` originates from (e.g. the CPU profile, or the host).
#[inline(never)]
#[cold]
fn debug_log_features_only_in(only_in: u64, id: &str, check_id: &str) {
    for_each_bitpos(only_in, |bit_pos| {
        debug!("{check_id} compatibility check failed: bit:={bit_pos} is only set for {id}");
    });
}

/// Verifies whether `a` is a subset of `b`.
///
/// Returns `true` on success and `false` otherwise. In the latter case a log
/// is produced at the debug level for each offending bit.
///
/// The parameter `a_id` is used to identify where `a` originates from and
/// `check_id` is used to describe the check when logging.
fn is_subset_debug_log(a: u64, b: u64, a_id: &str, check_id: &str) -> bool {
    if let Err(only_in) = check_subset(a, b) {
        debug_log_features_only_in(only_in, a_id, check_id);
        false
    } else {
        true
    }
}

/// Verifies whether `a` is equal to `b`.
///
/// Returns `true` on success and `false` otherwise. In the latter case a log
/// is produced at the debug level for each offending bit.
///
/// The parameters `a_id` and `b_id` are used to identify where `a` and `b` originate from and
/// `check_id` is used to describe the check when logging.
fn is_eq_debug_log(a: u64, b: u64, a_id: &str, b_id: &str, check_id: &str) -> bool {
    if a == b {
        true
    } else {
        let only_in_a = a & (a ^ b);
        let only_in_b = b & (b ^ a);
        debug_log_features_only_in(only_in_a, a_id, check_id);
        debug_log_features_only_in(only_in_b, b_id, check_id);
        false
    }
}

/// Calls the given callback with the bit-position of each set bit in `bits`.
fn for_each_bitpos(bits: u64, mut cb: impl FnMut(u8)) {
    let mut bits = bits;
    while bits != 0 {
        let pos = bits.trailing_zeros() as u8;
        cb(pos);
        bits &= bits - 1;
    }
}

#[cfg(test)]
mod unit_tests {
    use super::is_arch_capabilities_compatible;

    #[test]
    fn check_arch_compatibilities_cascade_lake_sapphire_rapids() {
        // Value of IA32_ARCH_CAPABILITIES on Intel Cascade Lake obtained from KVM (kernel version 6.12.60)
        let cascade_lake_msr_value: u64 = 0xc0aa0eb;

        // Value of IA32_ARCH_CAPABILITIES on Sapphire Rapids obtained from KVM (kernel version 6.18.33)
        let sapphire_rapids_msr_value: u64 = 0x400000000c08e1eb;

        // Live migration from Intel Cascade Lake to Sapphire Rapids should work as far as IA32_ARCH_CAPABILITIES
        // is concerned.
        // NOTE: The Cascade Lake has the FB_CLEAR bit set (bit 17), but this is not the case for Sapphire Rapids.
        // This means that the code path for the fallback compatibility check must necessarily get exercised.
        assert!(is_arch_capabilities_compatible(
            cascade_lake_msr_value,
            sapphire_rapids_msr_value,
            "Cascade Lake",
            "Sapphire Rapids",
        ));
    }

    #[test]
    fn check_arch_capabilities_sapphire_rapids_granite_rapids() {
        // Value of IA32_ARCH_CAPABILITIES on Sapphire Rapids (obtained from KVM with kernel version 6.18.33)
        let sapphire_rapids_msr_value: u64 = 0x400000000c08e1eb;
        // Value of IA32_ARCH_CAPABILITIES on Granite Rapids (obtained from KVM with kernel version 6.12.91)
        // TODO: Consider extracting the values from KVM with the same Linux Kernel versions, but we do not
        // expect this to change the values of this MSR though.
        let granite_rapids_msr_value: u64 = 0x400000000d08e1eb;

        // Migration from sapphire rapids to granite rapids without a CPU profile should work
        assert!(is_arch_capabilities_compatible(
            sapphire_rapids_msr_value,
            granite_rapids_msr_value,
            "Sapphire Rapids",
            "Granite Rapids",
        ));

        // On the other hand it should NOT be possible to migrate from the
        // Granite Rapids machine (without applying a CPU profile) to the
        // Sapphire Rapids, because PRBS_NO (IA32_ARCH_CAPABILITIES[24]) is set
        // on the former, but not the latter.
        assert!(!is_arch_capabilities_compatible(
            granite_rapids_msr_value,
            sapphire_rapids_msr_value,
            "Granite Rapids",
            "Sapphire Rapids",
        ));

        // The value extracted from the Sapphire Rapids machine, but with the
        // TSX CTRL bit unset.  All CPU profiles apart from host will adapt
        // CPUID to indicate that TSX is not available because that feature is
        // riddled with CVEs and we expect operators to disable it globally (at
        // the kernel level).
        let restricted_sapphire_rapids_msr_value: u64 = 0x400000000c08e16b;

        // It must be possible to apply the Sapphire Rapids CPU profile on
        // the host that the profile is based on
        assert!(is_arch_capabilities_compatible(
            restricted_sapphire_rapids_msr_value,
            sapphire_rapids_msr_value,
            "Sapphire Rapids profile",
            "Sapphire Rapids host",
        ));

        // It should also be possible to apply the Sapphire Rapids profile on
        // the Granite Rapids machine
        assert!(is_arch_capabilities_compatible(
            restricted_sapphire_rapids_msr_value,
            granite_rapids_msr_value,
            "Sapphire Rapids profile",
            "Granite Rapids host",
        ));
    }

    // Check that if reserved bits are different then we get an error.
    //
    // This test is somewhat contrived and simplistic. Reserved bits in
    // IA32_ARCH_CAPABILITIES will be 0 in practice. We do however want to be
    // safe if/when bits are no longer reserved on future hardware generations,
    // hence we add a simple test as a reality check that differing reserved
    // bits is not allowed.
    #[test]
    fn check_arch_capabilities_compatibility_reserved_bits() {
        const RESERVED_ONE: u64 = 1 << 31;
        const RESERVED_TWO: u64 = 1 << 42;
        const RESERVED_THREE: u64 = 1 << 61;
        let sapphire_rapids_msr_value: u64 = 0x400000000c08e1eb;
        let with_reserved_bits = sapphire_rapids_msr_value | RESERVED_ONE | RESERVED_THREE;
        let with_other_reserved_bits = sapphire_rapids_msr_value | RESERVED_TWO;

        assert!(!is_arch_capabilities_compatible(
            with_reserved_bits,
            with_other_reserved_bits,
            "Reserved 1",
            "Reserved 2",
        ));

        assert!(!is_arch_capabilities_compatible(
            with_other_reserved_bits,
            with_reserved_bits,
            "Reserved 2",
            "Reserved 1",
        ));
    }
}
