# RFC: Cloud Hypervisor Block Crate Refactoring

<details open>
<summary><b>Table of Contents</b></summary>

- [Identified Issues](#identified-issues)
  - [Issue 1: Trait Misplacement](#issue-1-trait-misplacement)
  - [Issue 2: Module Organization Chaos](#issue-2-module-organization-chaos)
  - [Issue 3: Naming Inconsistencies](#issue-3-naming-inconsistencies)
  - [Issue 4: Missing Factory Pattern](#issue-4-missing-factory-pattern)
  - [Issue 5: Limited Multi-threading Support](#issue-5-limited-multi-threading-support)
  - [Issue 6: Missing Batch Operation Support](#issue-6-missing-batch-operation-support)
  - [Issue 7: Inconsistent Error Handling](#issue-7-inconsistent-error-handling)
- [Context and Rationale](#context-and-rationale)
  - [Practices from Crosvm](#practices-from-crosvm)
  - [QCOW2 Specification Gaps](#qcow2-specification-gaps)
  - [Async I/O Considerations](#async-io-considerations)
  - [Dependencies Between Improvements](#dependencies-between-improvements)
- [Phased Refactoring Plan](#phased-refactoring-plan)
  - [Phase 1: Foundation](#phase-1-foundation)
  - [Phase 2: Implementation](#phase-2-implementation)
  - [Phase 3: Reorganization](#phase-3-reorganization)
  - [Phase 4: Cleanup](#phase-4-cleanup)
  - [Phase 5: Async Enhancement](#phase-5-async-enhancement)
- [Implementation Strategy](#implementation-strategy)
  - [Timeline & Parallelization](#timeline--parallelization)
  - [Testing Approach](#testing-approach)
  - [Risks & Mitigation](#risks--mitigation)
  - [Success Criteria](#success-criteria)

</details>

---

## Identified Issues

### Issue 1: Trait Misplacement
`DiskFile` trait is defined in [async_io.rs](../../block/src/async_io.rs) but
used by all disk types (sync and async). Should be in dedicated `disk_file.rs`
module for clear separation of concerns.

### Issue 2: Module Organization Chaos
Files mix formats with I/O backends (e.g., `fixed_vhd_sync.rs`,
`raw_async.rs`). Inconsistent structure: some formats are files, others
directories. No clear organizational axis.

**Target**: Separate `formats/` (qcow.rs, vhd.rs, vhdx.rs) and `io/`
(io_uring.rs, aio.rs) directories.

### Issue 3: Naming Inconsistencies
`RawFile` vs `RawFileDisk` vs `RawFileAsync`, `QcowFile` vs `QcowSync`,
`FixedVhd` vs `FixedVhdAsync`.

**Target**: Consistent pattern: `{Format}`, `{Format}Sync`, `{Format}Async`.

### Issue 4: Missing Factory Pattern
Callers must know exact type construction details
(`QcowFile::from(RawFile::new(...)?)`, `Vhdx::from_file(...)`).

**Target**: Unified `open_disk_file(path)` with automatic format detection.

### Issue 5: Limited Multi-threading Support
Each virtio-blk device runs in its own thread, and multiple queues within that
device need concurrent access to the disk file. Without `try_clone()` to create
independent file descriptors, all queue operations serialize on a single file
handle, eliminating parallel I/O performance.

### Issue 6: Missing Batch Operation Support
Virtio-blk collects multiple I/O requests but synchronous I/O adaptors
(QcowSync, VhdxSync) don't implement `submit_batch_requests()`, forcing
one-by-one processing with excessive syscall overhead.

### Issue 7: Inconsistent Error Handling
Error types scattered across modules: `qcow::Error`, `VhdxError`,
`block::Error`, `DiskFileError`, `AsyncIoError`. No consistent context (file
path, offset), manual conversions between layers.

**Target**: Single `block::Error` with rich context throughout.

---

## Context and Rationale

### Practices from Crosvm

Crosvm provides a reference architecture for block device handling, though
Cloud Hypervisor has broader format support (VHD/VHDx, QCOW2 v2+v3 with
zlib/zstd compression) that must be preserved during refactoring.

**Thread Safety by Default**
- Crosvm uses `Mutex` by default for shared state
- Cloud Hypervisor has inconsistent approach: `QcowFile` and `Vhdx` store
  mutable caches (`l2_cache`, `bat_entries`) without synchronization primitives,
  making concurrent access unsafe

**Volatile I/O Support**
- Crosvm has proper volatile memory access traits for guest shared memory
- Cloud Hypervisor doesn't implement this (missing entirely)

**Clone Support for Multi-threading**
- Crosvm has `try_clone()` properly implemented across all disk types
- Cloud Hypervisor: VHD/VHDx have `Clone`, but `QcowFile` doesn't (can't be
  shared across threads)

**Clean Architecture**
- Crosvm has clear trait boundaries, organized modules, factory pattern
- Cloud Hypervisor has traits misplaced, chaotic organization, no factory

### QCOW2 Specification Gaps

The QCOW2 v3 specification defines several features that are currently
unimplemented or only partially supported in Cloud Hypervisor. This section
focuses on features where the refactored architecture would enable cleaner
implementation. Other unimplemented features may exist but are not covered here.

**Incompatible Features That Would Benefit from Refactoring**:
- **Bit 2: External data file** - data clusters stored in separate file
  referenced by header extension. Current implementation: Header field exists
  but never parsed/used. Refactoring benefit - clean format/IO separation makes
  routing I/O to separate data file natural
- **Bit 4: Extended L2 entries** - L2 entries are 128 bits instead of 64 bits,
  enabling subcluster allocation. Not supported. Refactoring benefit -
  thread-safe metadata access enables concurrent subcluster operations

**Compatible Features**:
- **Bit 0: Lazy refcounts** - refcount updates deferred for performance.
  Current implementation: Flag used as marker during refcount rebuilds. Files
  with lazy refcounts trigger full rebuild on open. Refactoring benefit -
  thread-safe refcount cache would enable true lazy update implementation

**Autoclear Features**:
- **Bit 0: Bitmaps** - dirty bitmap extension for incremental backups. Not
  supported. Refactoring benefit - batch operations make bitmap queries
  efficient

**Header Extensions**:
- **0x44415441: External data file** - not implemented, needed for bit 2 above
- **0x23852875: Bitmaps extension** - not implemented, needed for autoclear
  bit 0

**Additional Missing Features**:
- **Encryption**: LUKS encryption - `crypt_method` header field exists but only
  value 0 (no encryption) accepted. Refactoring benefit - format/IO separation
  allows encryption/decryption transforms in I/O layer. Unified error handling
  for decryption failures
- **Snapshots**: Internal snapshots - `nb_snapshots` and `snapshots_offset`
  fields exist but snapshot structures never read/written. Refactoring benefit -
  clean trait boundaries let snapshots be added as separate trait extension
- **Discard/TRIM**: QCOW2 supports marking clusters as unallocated after
  discard. Implementation has `PunchHole` trait but integration with refcount
  updates unclear. Refactoring benefit - unified error handling makes
  multi-step operations (punch hole + update refcounts) more reliable

**How Refactoring Enables These Features**:

1. **Format/IO Separation** (Phase 3): External data files need I/O routed to
   separate file while metadata stays in QCOW2 file - clean separation makes
   this natural

2. **Thread-Safe Metadata** (Phase 2): Extended L2 entries and lazy refcounts
   need concurrent metadata updates - thread-safe metadata access enables this

3. **Batch Operations** (Phase 2): Dirty bitmaps need efficient multi-cluster
   status checks - batch support makes bitmap queries practical

4. **Unified Error Handling** (Phase 1): Complex features like external data
   files fail in intricate ways - error context makes debugging tractable

5. **Clean Trait Boundaries** (Phase 1): Snapshots can be added as separate
   trait extension without polluting core `DiskFile` interface

### Async I/O Considerations

**Current Architecture Blocks Async**

Multiple fundamental issues prevent async I/O:

**1. Mutable Self Everywhere**
```rust
fn logical_size(&mut self) -> DiskFileResult<u64>
fn physical_size(&mut self) -> DiskFileResult<u64>
```
`&mut self` means only one operation at a time - impossible to have multiple
concurrent I/O requests.

**2. Tight Coupling of I/O and Format Logic**

Example from QCOW2:
```rust
fn read_cluster(&mut self, cluster: u64) -> Result<Vec<u8>> {
    let compressed_data = self.file.read_at(...)?;  // I/O
    let data = decompress_cluster(compressed_data)?; // Format logic (CPU-bound)
    Ok(data)
}
```
- Can't separate I/O operations from format processing
- CPU-bound work (decompression, metadata parsing) blocks I/O threads
- No way to pipeline operations

**3. No Trait Separation**

All formats forced into same synchronous traits:
- Can't have async variants coexist with sync ones
- No way to express "this format can do async, that one can't"
- DiskFile trait in wrong module (async_io.rs) creates confusion

**4. Thread Safety Issues**

- No synchronization primitives (Mutex/RwLock) used in any format implementations
- Mutable state in `QcowFile`, `Vhdx` not protected for concurrent access
- No clear threading model: unclear which types should be thread-safe

**What Async I/O Enables**

- **Concurrent operations**: Multiple I/O requests in flight simultaneously
- **Better resource utilization**: I/O waits don't block CPU work
- **Scalability**: Handle more requests with same thread count
- **Proper batch processing**: True parallel I/O via io_uring/AIO
- **Non-blocking format operations**: Can process one cluster while waiting for another

### Dependencies Between Improvements

The identified issues and refactoring phases are interconnected. Fixing one enables others:

**Multi-threading Enables Async I/O (Issue 5 to Phase 5)**
- Async I/O requires multiple concurrent operations on the same disk file
- Without thread-safe metadata, `&mut self` methods block concurrency
- Phase 2 adds `Mutex`/`RwLock` to caches, enabling Phase 5's concurrent async operations

**Trait Organization Blocks Async (Issue 1 to Phase 5)**
- `DiskFile` trait in `async_io.rs` creates circular dependency
- Synchronous formats can't coexist with async variants in same trait
- Phase 1 separates `DiskFile` from `AsyncDiskFile`, enabling Phase 5's async implementations

**Unified Error Handling Critical for Async (Issue 7 to Phase 5)**
- Async operations interleave, making error context tracking harder
- Multi-step operations (metadata update + I/O) need atomic error handling
- Phase 1's unified `block::Error` with context makes Phase 5's async error propagation tractable

**Batch Operations + Async I/O = True Parallelism (Issue 6 + Phase 5)**
- Batch operations alone don't help without async I/O (still blocks on each batch)
- Async I/O alone inefficient without batching (syscall per operation)
- Together: io_uring submits batch, processes other work while kernel handles I/O
- QCOW2 benefits: batch non-compressed cluster reads, async decompress compressed ones

**Factory Pattern Enables Testing (Issue 4 to All Phases)**
- Testing format + I/O backend combinations requires easy instantiation
- Manual construction (`QcowFile::from(RawFile::new(...)?)`) makes tests brittle
- Phase 1's factory pattern simplifies testing all format/backend combinations in Phase 2

**Module Organization Blocks Feature Addition (Issue 2 to QCOW2 Features)**
- Adding QCOW2 external data files requires clear format/I/O separation
- Current mixed organization makes routing I/O to separate files unclear
- Phase 3's `formats/` vs `io/` separation makes external data file feature natural to implement

**Why Phase 5 Depends on Phases 1-4**

Async enhancement (Phase 5) cannot be implemented without the architectural foundation:
1. **Phase 1**: Trait separation (`DiskFile` vs `AsyncDiskFile`) + unified error handling
2. **Phase 2**: Thread-safe implementations with `Mutex`/`RwLock` for shared state
3. **Phase 3**: Format/I/O separation enables async I/O in `io/` layer while format logic stays sync
4. **Phase 4**: Clean codebase without legacy cruft simplifies async complexity

Attempting async first would require solving all architectural issues simultaneously, increasing risk.

---

## Phased Refactoring Plan

### Phase 1: Foundation

**Key principle**: Add new code alongside existing code without changing
anything currently used. Nothing breaks because vmm/ keeps using the old APIs.

**Task 1.1: Create New Trait Hierarchy**

Create **new file** `block/src/disk_file.rs`:
```rust
// block/src/disk_file.rs - NEW FILE
pub trait DiskFile: DiskGetLen + Send + Debug + AsRawFd {
    fn logical_size(&self) -> io::Result<u64>;
    fn physical_size(&self) -> io::Result<u64>;
    fn try_clone(&self) -> io::Result<Box<dyn DiskFile>>;
    fn topology(&self) -> DiskTopology;
}

pub trait AsyncDiskFile: DiskFile {
    fn create_async_io(&self, ring_depth: u32) -> io::Result<Box<dyn AsyncIo>>;
}
```

**Implementation notes**:
- Old trait: `async_io::DiskFile` (stays unchanged)
- New trait: `disk_file::DiskFile` (different module = no conflict)
- Must add `pub mod disk_file;` to lib.rs to include the file

**Task 1.2: Factory Pattern**

Create **new file** `block/src/factory.rs`:
```rust
// block/src/factory.rs - NEW FILE
pub fn open_disk_file(params: DiskFileParams) -> Result<Box<dyn DiskFile>> {
    // Read file header to detect format
    // Return QcowFile, VhdxFile, etc. wrapped in new trait
}
```

Must also add `pub mod factory;` to lib.rs.

**Task 1.3: Documentation**
- Module-level docs with examples
- Trait documentation
- Architecture decision records

**Task 1.4: Error Handling**
- Create `block/src/error.rs` with unified error type
- Add context: file path, offset, operation name
- Migrate format-specific errors (`qcow::Error`, `VhdxError`) to unified hierarchy
- Implement clean `From<T>` conversions
- Use `thiserror` consistently

---

### Phase 2: Implementation

**Task 2.1: Implement New Traits**

Add `impl disk_file::DiskFile` for all existing formats:
- `QcowFile` (QCOW2 format)
- `FixedVhd` (VHD format)
- `Vhdx` (VHDx format)
- `RawFile` and variants (raw format)

Each keeps existing `async_io::DiskFile` impl, adds new trait alongside. Zero
breaking changes.

**Task 2.2: Block Layer Tests**
- Format + I/O backend combinations (e.g., QCOW2 with io_uring vs sync)
- round-trip tests (write/read verification within block crate)
- Format-specific features (unallocated regions, QCOW2 compression, backing
  files)
- Factory pattern (format detection)

These test the block crate components together, not full VM integration.

**Task 2.3: Performance Benchmarks**
- Before/after comparisons
- Sequential and random I/O patterns
- Multiple queue scenarios

---

### Phase 3: Reorganization

**Task 3.1: Reorganize Modules**
```
block/src/
├── disk_file.rs
├── factory.rs
├── formats/
│   ├── qcow.rs       (from qcow/mod.rs)
│   ├── vhd.rs        (from fixed_vhd*.rs)
│   └── vhdx.rs       (from vhdx/mod.rs)
└── io/
    ├── io_uring.rs   (from raw_async.rs)
    └── aio.rs        (from raw_async_aio.rs)
```

**Task 3.2: Apply Naming Conventions**
- Rename types systematically
- Update all references
- Maintain compatibility shims

**Task 3.3: Update Imports**
- Re-export from new locations
- Update vmm/ usage
- Update documentation

---

### Phase 4: Cleanup

Since the block crate is internal to Cloud Hypervisor (not a public API),
cleanup can be done directly after Phase 3:

**Task 4.1: Remove Old Implementations**
- Delete old trait definitions (`async_io::DiskFile`)
- Clean up compatibility shims from Phase 3
- Remove unused code paths

**Task 4.2: Final Code Cleanup**
- Update vmm/ to use new APIs consistently
- Remove any remaining temporary workarounds
- Consolidate duplicate code

**Task 4.3: Documentation**
- Architecture documentation
- Internal API guide for future contributors

---

### Phase 5: Async Enhancement

**Task 5.1: Async Infrastructure**
- Blocking thread pool for decompression
- Async trait implementations
- State management for concurrent ops

**Task 5.2: QCOW2 Async**
- Separate I/O from decompression
- Batch non-compressed clusters
- Handle compressed clusters via thread pool

**Task 5.3: VHDx Async**
- Similar approach to QCOW2

**Expected benefit**: Enables concurrent operations for random I/O workloads

---

## Implementation Strategy

### Timeline & Parallelization

| Phase | Duration | Risk | Parallelizable |
|-------|----------|------|----------------|
| 1-2 | 2-3 weeks each | Low | Yes |
| 3 | 2-3 weeks | Medium | No |
| 4 | 1 week | Low | No |
| 5 | 3-4 weeks | High | Yes |

**Total**: 10-14 weeks (all phases)

### Testing Approach

- **Unit**: Each format/I/O backend independently
- **Integration**: All format + I/O backend combinations, backing file chains
- **Performance**: Sequential/random I/O, multi-queue scenarios
- **Regression**: Existing test suite + real VM workloads
### Risks & Mitigation

**High-risk areas**:
1. Phase 3 reorganization - mitigation: staged rollout, comprehensive test
   coverage
2. Phase 5 async complexity - mitigation: implement after clean architecture
   established, thorough testing
3. Performance regression - mitigation: benchmark suite with before/after
   comparison

**Safety measures**: Feature flags for new code paths, fallback mechanisms,
gradual deployment, CI performance monitoring

### Success Criteria

- **Architecture**: Clear module boundaries, consistent naming, comprehensive
  documentation
- **Performance**: Phase 5 (async) enables improved random I/O. Clean
  architecture from Phases 1-4 facilitates future optimizations
- **Velocity**: Add new format <2 weeks, new I/O backend <1 week

