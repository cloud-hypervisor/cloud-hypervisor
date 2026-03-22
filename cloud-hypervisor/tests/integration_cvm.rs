// Copyright 2026 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
#![cfg(any(devcli_testenv, clippy))]
#![allow(clippy::undocumented_unsafe_blocks)]
// When enabling the `mshv` feature, we skip quite some tests and
// hence have known dead-code. This annotation silences dead-code
// related warnings for our quality workflow to pass.
#![allow(dead_code)]
mod common;

#[cfg(all(feature = "sev_snp", target_arch = "x86_64"))]
mod common_cvm {
    use block::ImageType;
    use common::tests_wrappers::*;
    use common::utils::*;
    use test_infra::*;
    const NUM_PCI_SEGMENTS: u16 = 8;

    use super::*;
    macro_rules! basic_cvm_guest {
        ($image_name:expr) => {{
            let disk_config = UbuntuDiskConfig::new($image_name.to_string());
            GuestFactory::new_confidential_guest_factory().create_guest(Box::new(disk_config))
        }};
    }

    #[test]
    fn test_focal_simple_launch() {
        let guest = basic_cvm_guest!(FOCAL_IMAGE_NAME);

        _test_simple_launch(&guest);
    }

    #[test]
    fn test_api_http_create_boot() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME).with_cpu(4);
        let target_api = TargetApi::new_http_api(&guest.tmp_dir);
        _test_api_create_boot(&target_api, &guest);
    }

    #[test]
    fn test_api_http_shutdown() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME).with_cpu(4);

        let target_api = TargetApi::new_http_api(&guest.tmp_dir);
        _test_api_shutdown(&target_api, &guest);
    }

    #[test]
    fn test_api_http_delete() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        let target_api = TargetApi::new_http_api(&guest.tmp_dir);
        _test_api_delete(&target_api, &guest);
    }

    #[test]
    fn test_power_button() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_power_button(&guest);
    }

    #[test]
    fn test_virtio_vsock() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_virtio_vsock(&guest, false);
    }

    #[test]
    fn test_multi_cpu() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_multi_cpu(&guest);
    }

    #[test]
    fn test_cpu_affinity() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME).with_cpu(2);
        _test_cpu_affinity(&guest);
    }

    #[test]
    fn test_virtio_queue_affinity() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME).with_cpu(4);
        _test_virtio_queue_affinity(&guest);
    }

    #[test]
    fn test_pci_msi() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_pci_msi(&guest);
    }

    #[test]
    fn test_virtio_net_ctrl_queue() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_virtio_net_ctrl_queue(&guest);
    }

    #[test]
    fn test_pci_multiple_segments() {
        // Use 8 segments to test the multiple segment support since it's more than the default 6
        //  supported by Linux
        // IGVM file used by Sev-Snp Guest now support up to 8 segments, so we can use 8 segments for testing.
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_pci_multiple_segments(&guest, NUM_PCI_SEGMENTS, 5);
    }

    #[test]
    fn test_direct_kernel_boot() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_direct_kernel_boot(&guest);
    }

    #[test]
    fn test_virtio_block_io_uring() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_confidential_guest_factory(),
            FOCAL_IMAGE_NAME,
        );
        _test_virtio_block(&guest, false, true, false, false, ImageType::Raw);
    }

    #[test]
    fn test_virtio_block_aio() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_confidential_guest_factory(),
            FOCAL_IMAGE_NAME,
        );
        _test_virtio_block(&guest, true, false, false, false, ImageType::Raw);
    }

    #[test]
    fn test_virtio_block_sync() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_confidential_guest_factory(),
            FOCAL_IMAGE_NAME,
        );
        _test_virtio_block(&guest, true, true, false, false, ImageType::Raw);
    }

    #[test]
    fn test_virtio_block_qcow2() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_confidential_guest_factory(),
            JAMMY_IMAGE_NAME_QCOW2,
        );
        _test_virtio_block(&guest, false, false, true, false, ImageType::Qcow2);
    }

    #[test]
    fn test_virtio_block_qcow2_zlib() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_confidential_guest_factory(),
            JAMMY_IMAGE_NAME_QCOW2_ZLIB,
        );
        _test_virtio_block(&guest, false, false, true, false, ImageType::Qcow2);
    }

    #[test]
    fn test_virtio_block_qcow2_zstd() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_confidential_guest_factory(),
            JAMMY_IMAGE_NAME_QCOW2_ZSTD,
        );
        _test_virtio_block(&guest, false, false, true, false, ImageType::Qcow2);
    }

    #[test]
    fn test_virtio_block_qcow2_backing_zstd_file() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_confidential_guest_factory(),
            JAMMY_IMAGE_NAME_QCOW2_BACKING_ZSTD_FILE,
        );

        _test_virtio_block(&guest, false, false, true, true, ImageType::Qcow2);
    }

    #[test]
    fn test_virtio_block_qcow2_backing_uncompressed_file() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_confidential_guest_factory(),
            JAMMY_IMAGE_NAME_QCOW2_BACKING_UNCOMPRESSED_FILE,
        );

        _test_virtio_block(&guest, false, false, true, true, ImageType::Qcow2);
    }

    #[test]
    fn test_virtio_block_qcow2_backing_raw_file() {
        let guest = make_virtio_block_guest(
            &GuestFactory::new_confidential_guest_factory(),
            JAMMY_IMAGE_NAME_QCOW2_BACKING_RAW_FILE,
        );
        _test_virtio_block(&guest, false, false, true, true, ImageType::Qcow2);
    }

    #[test]
    fn test_virtio_block_dynamic_vhdx_expand() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_virtio_block_dynamic_vhdx_expand(&guest);
    }

    #[test]
    fn test_split_irqchip() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_split_irqchip(&guest);
    }

    #[test]
    fn test_dmi_uuid() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_dmi_uuid(&guest);
    }

    #[test]
    fn test_dmi_oem_strings() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_dmi_oem_strings(&guest);
    }

    #[test]
    fn test_multiple_network_interfaces() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_multiple_network_interfaces(&guest);
    }

    #[test]
    fn test_serial_off() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_serial_off(&guest);
    }

    #[test]
    fn test_virtio_console() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_virtio_console(&guest);
    }

    #[test]
    fn test_console_file() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_console_file(&guest);
    }

    #[test]
    fn test_direct_kernel_boot_noacpi() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_direct_kernel_boot_noacpi(&guest);
    }

    #[test]
    fn test_pci_bar_reprogramming() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_pci_bar_reprogramming(&guest);
    }

    #[test]
    fn test_memory_overhead() {
        let guest_memory_size_kb: u32 = 512 * 1024;
        let guest =
            basic_cvm_guest!(JAMMY_IMAGE_NAME).with_memory(&format!("{guest_memory_size_kb}K"));
        _test_memory_overhead(&guest, guest_memory_size_kb);
    }

    #[test]
    fn test_landlock() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_landlock(&guest);
    }

    #[test]
    fn test_disk_hotplug() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_disk_hotplug(&guest, false);
    }

    #[test]
    fn test_net_hotplug() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_net_hotplug(&guest, NUM_PCI_SEGMENTS, None);
    }

    #[test]
    fn test_counters() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_counters(&guest);
    }

    #[test]
    fn test_watchdog() {
        let guest = basic_cvm_guest!(FOCAL_IMAGE_NAME);
        _test_watchdog(&guest);
    }

    #[test]
    fn test_pvpanic() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME);
        _test_pvpanic(&guest);
    }

    #[test]
    fn test_tap_from_fd() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME).with_cpu(2);
        _test_tap_from_fd(&guest);
    }

    #[test]
    fn test_macvtap() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME).with_cpu(2);
        _test_macvtap(&guest, false, "guestmacvtap0", "hostmacvtap0");
    }

    #[test]
    fn test_macvtap_hotplug() {
        let guest = basic_cvm_guest!(JAMMY_IMAGE_NAME).with_cpu(2);
        _test_macvtap(&guest, true, "guestmacvtap1", "hostmacvtap1");
    }
}
