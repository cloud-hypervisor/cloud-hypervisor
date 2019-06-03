# vm-memory
A library to access virtual machine's physical memory.

For a typical hypervisor, there are seveval components, such as boot loader, virtual device drivers, virtio backend drivers and vhost drivers etc, need to access VM's physical memory. The `vm-memory` crate provides a set of traits to decouple VM memory consumers from VM memory providers. Based on these traits, VM memory consumers could access VM's physical memory without knowing the implementation details of the VM memory provider. Thus hypervisor components based on these traits could be shared and reused by multiple hypervisors.

## Platform Support
- Arch: x86, AMD64, ARM64
- OS: Linux/Unix/Windows

## Usage
First, add the following to your `Cargo.toml`:
```toml
vm-memory = "0.1"
```
Next, add this to your crate root:
```rust
extern crate vm_memory;
```

## Example
- Create VM physical memory objects in hypervisor specific ways. Use the default GuestMemoryMmap as an example:
```
    fn provide_mem_to_virt_dev() {
        let gm = GuestMemoryMmap::new(&[(GuestAddress(0), 0x1000), (GuestAddress(0x1000), 0x1000)]).unwrap();
        virt_device_io(&gm);
    }
```

- Consumers access VM's physical memory
```
    fn virt_device_io<T: GuestMemory>(mem: &T) {
        let sample_buf = &[1, 2, 3, 4, 5];
        assert_eq!(mem.write(sample_buf, GuestAddress(0xffc)).unwrap(), 5);
        let buf = &mut [0u8; 5];
        assert_eq!(mem.read(buf, GuestAddress(0xffc)).unwrap(), 5);
        assert_eq!(buf, sample_buf);
    }
```

## Documentations & References
- [Design of The `vm-memory` Crate](DESIGN.md)
- [TODO List](TODO.md)
- [The rust-vmm Project](https://github.com/rust-vmm/)

## License
This project is licensed under
- Apache License, Version 2.0, (LICENSE or http://www.apache.org/licenses/LICENSE-2.0)
