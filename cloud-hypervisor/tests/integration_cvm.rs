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

    use super::*;

    #[test]
    fn test_focal_simple_launch() {
        let disk_config = UbuntuDiskConfig::new(FOCAL_IMAGE_NAME.to_string());
        let guest =
            GuestFactory::new_confidential_guest_factory().create_guest(Box::new(disk_config));

        _test_simple_launch(&guest);
    }

    #[test]
    fn test_api_http_create_boot() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = GuestFactory::new_confidential_guest_factory()
            .create_guest(Box::new(disk_config))
            .with_cpu(4);
        let target_api = TargetApi::new_http_api(&guest.tmp_dir);
        _test_api_create_boot(&target_api, &guest);
    }

    #[test]
    fn test_api_http_shutdown() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = GuestFactory::new_confidential_guest_factory()
            .create_guest(Box::new(disk_config))
            .with_cpu(4);

        let target_api = TargetApi::new_http_api(&guest.tmp_dir);
        _test_api_shutdown(&target_api, &guest);
    }

    #[test]
    fn test_api_http_delete() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = GuestFactory::new_confidential_guest_factory()
            .create_guest(Box::new(disk_config))
            .with_cpu(4);

        let target_api = TargetApi::new_http_api(&guest.tmp_dir);
        _test_api_delete(&target_api, &guest);
    }

    #[test]
    fn test_power_button() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest =
            GuestFactory::new_confidential_guest_factory().create_guest(Box::new(disk_config));
        _test_power_button(&guest);
    }

    #[test]
    fn test_virtio_vsock() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest =
            GuestFactory::new_confidential_guest_factory().create_guest(Box::new(disk_config));
        _test_virtio_vsock(&guest, false);
    }

    #[test]
    fn test_multi_cpu() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest =
            GuestFactory::new_confidential_guest_factory().create_guest(Box::new(disk_config));
        _test_multi_cpu(&guest);
    }

    #[test]
    fn test_cpu_affinity() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = GuestFactory::new_confidential_guest_factory()
            .create_guest(Box::new(disk_config))
            .with_cpu(2);
        _test_cpu_affinity(&guest);
    }

    #[test]
    fn test_virtio_queue_affinity() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest = GuestFactory::new_confidential_guest_factory()
            .create_guest(Box::new(disk_config))
            .with_cpu(4);
        _test_virtio_queue_affinity(&guest);
    }

    #[test]
    fn test_pci_msi() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest =
            GuestFactory::new_confidential_guest_factory().create_guest(Box::new(disk_config));
        _test_pci_msi(&guest);
    }

    #[test]
    fn test_virtio_net_ctrl_queue() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest =
            GuestFactory::new_confidential_guest_factory().create_guest(Box::new(disk_config));
        _test_virtio_net_ctrl_queue(&guest);
    }

    #[test]
    fn test_pci_multiple_segments() {
        // Use 8 segments to test the multiple segment support since it's more than the default 6
        //  supported by Linux
        // IGVM file used by Sev-Snp Guest now support up to 8 segments, so we can use 8 segments for testing.
        let num_pci_segments: u16 = 8;
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest =
            GuestFactory::new_confidential_guest_factory().create_guest(Box::new(disk_config));
        _test_pci_multiple_segments(&guest, num_pci_segments, 5);
    }

    #[test]
    fn test_direct_kernel_boot() {
        let disk_config = UbuntuDiskConfig::new(JAMMY_IMAGE_NAME.to_string());
        let guest =
            GuestFactory::new_confidential_guest_factory().create_guest(Box::new(disk_config));
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
}
