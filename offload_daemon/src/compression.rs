// Copyright © 2026 The Cloud Hypervisor Authors
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{fmt, io, thread};

use lz4_flex::block::{compress as lz4_compress, decompress as lz4_decompress};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zstd::bulk::{compress as zstd_compress, decompress as zstd_decompress};

#[cfg(feature = "qpl")]
use crate::qpl::{
    Error as QplError, ExecutionPath, HuffmanMode, Job as QplJob, JobPool as QplJobPool,
};

pub(crate) const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Codec {
    Lz4,
    Zstd,
    QplHardware,
    QplHardwareStatic,
    QplHardwareDynamic,
    QplHardwareStaticAsync,
    QplHardwareDynamicAsync,
    QplAuto,
}

impl fmt::Display for Codec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Lz4 => "lz4",
            Self::Zstd => "zstd",
            Self::QplHardware => "qpl-hardware",
            Self::QplHardwareStatic => "qpl-hardware-static",
            Self::QplHardwareDynamic => "qpl-hardware-dynamic",
            Self::QplHardwareStaticAsync => "qpl-hardware-static-async",
            Self::QplHardwareDynamicAsync => "qpl-hardware-dynamic-async",
            Self::QplAuto => "qpl-auto",
        };
        formatter.write_str(name)
    }
}

impl FromStr for Codec {
    type Err = ParseCodecError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "lz4" => Ok(Self::Lz4),
            "zstd" => Ok(Self::Zstd),
            "qpl-hardware" => Ok(Self::QplHardware),
            "qpl-hardware-static" => Ok(Self::QplHardwareStatic),
            "qpl-hardware-dynamic" => Ok(Self::QplHardwareDynamic),
            "qpl-hardware-static-async" => Ok(Self::QplHardwareStaticAsync),
            "qpl-hardware-dynamic-async" => Ok(Self::QplHardwareDynamicAsync),
            "qpl-auto" => Ok(Self::QplAuto),
            _ => Err(ParseCodecError(value.to_owned())),
        }
    }
}

#[cfg(feature = "qpl")]
impl Codec {
    fn async_huffman_mode(self) -> Option<HuffmanMode> {
        match self {
            Self::QplHardwareStaticAsync => Some(HuffmanMode::Static),
            Self::QplHardwareDynamicAsync => Some(HuffmanMode::Dynamic),
            _ => None,
        }
    }
}

#[derive(Debug, Error)]
#[error("Unknown compression codec {0:?}")]
pub(crate) struct ParseCodecError(String);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ChunkRecord {
    pub uncompressed_offset: u64,
    pub uncompressed_length: u32,
    pub compressed_offset: u64,
    pub compressed_length: u32,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub zero: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SlotManifest {
    pub version: u32,
    pub codec: Codec,
    pub chunk_size: u32,
    pub uncompressed_size: u64,
    pub chunks: Vec<ChunkRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CompressionStats {
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub chunks: usize,
    pub elapsed: Duration,
}

impl CompressionStats {
    pub(crate) fn ratio(self) -> f64 {
        if self.input_bytes == 0 {
            return 1.0;
        }
        self.output_bytes as f64 / self.input_bytes as f64
    }

    pub(crate) fn throughput_gib_per_second(self) -> f64 {
        if self.elapsed.is_zero() {
            return 0.0;
        }
        self.input_bytes as f64 / (1_u64 << 30) as f64 / self.elapsed.as_secs_f64()
    }
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[cfg(not(feature = "qpl"))]
    #[error("QPL support is not available in this build")]
    QplUnavailable,
    #[cfg(feature = "qpl")]
    #[error("QPL operation failed")]
    Qpl(#[from] QplError),
    #[error("Invalid chunk size {0}")]
    InvalidChunkSize(usize),
    #[error("Chunk is too large")]
    ChunkTooLarge,
    #[error("Decompressed chunk has length {actual}, expected {expected}")]
    LengthMismatch { expected: usize, actual: usize },
    #[error("Compression failed")]
    Compress(#[source] io::Error),
    #[error("Decompression failed")]
    Decompress(#[source] io::Error),
    #[error("Reading compressed snapshot")]
    Read(#[source] io::Error),
    #[error("Writing compressed snapshot")]
    Write(#[source] io::Error),
    #[error("Reading compression manifest")]
    ReadManifest(#[source] serde_json::Error),
    #[error("Writing compression manifest")]
    WriteManifest(#[source] serde_json::Error),
    #[error("Unsupported compression format version {0}")]
    UnsupportedVersion(u32),
    #[error("Invalid compression manifest: {0}")]
    InvalidManifest(String),
    #[error("Compression worker panicked")]
    WorkerPanic,
}

struct CodecWorker {
    codec: Codec,
    zstd_level: i32,
    output: Vec<u8>,
    #[cfg(feature = "qpl")]
    qpl_job: Option<QplJob>,
}

impl CodecWorker {
    fn new(codec: Codec, zstd_level: i32) -> Result<Self, Error> {
        #[cfg(feature = "qpl")]
        let qpl_job = match codec {
            Codec::QplHardware | Codec::QplHardwareDynamic | Codec::QplHardwareDynamicAsync => {
                Some(QplJob::new_with_mode(
                    ExecutionPath::Hardware,
                    HuffmanMode::Dynamic,
                )?)
            }
            Codec::QplHardwareStatic | Codec::QplHardwareStaticAsync => Some(
                QplJob::new_with_mode(ExecutionPath::Hardware, HuffmanMode::Static)?,
            ),
            Codec::QplAuto => Some(QplJob::new(ExecutionPath::Auto)?),
            Codec::Lz4 | Codec::Zstd => None,
        };
        #[cfg(not(feature = "qpl"))]
        if matches!(
            codec,
            Codec::QplHardware
                | Codec::QplHardwareStatic
                | Codec::QplHardwareDynamic
                | Codec::QplHardwareStaticAsync
                | Codec::QplHardwareDynamicAsync
                | Codec::QplAuto
        ) {
            return Err(Error::QplUnavailable);
        }
        Ok(Self {
            codec,
            zstd_level,
            output: Vec::new(),
            #[cfg(feature = "qpl")]
            qpl_job,
        })
    }

    fn compress(&mut self, input: &[u8]) -> Result<&[u8], Error> {
        match self.codec {
            Codec::Lz4 => self.output = lz4_compress(input),
            Codec::Zstd => {
                self.output = zstd_compress(input, self.zstd_level).map_err(Error::Compress)?;
            }
            Codec::QplHardware
            | Codec::QplHardwareStatic
            | Codec::QplHardwareDynamic
            | Codec::QplHardwareStaticAsync
            | Codec::QplHardwareDynamicAsync
            | Codec::QplAuto => {
                #[cfg(feature = "qpl")]
                self.qpl_job
                    .as_mut()
                    .unwrap()
                    .compress_into(input, &mut self.output)
                    .map_err(Error::Qpl)?;
                #[cfg(not(feature = "qpl"))]
                unreachable!();
            }
        }
        Ok(&self.output)
    }

    fn decompress(&mut self, input: &[u8], expected_length: usize) -> Result<&[u8], Error> {
        match self.codec {
            Codec::Lz4 => {
                self.output = lz4_decompress(input, expected_length)
                    .map_err(|error| Error::Decompress(io::Error::other(error.to_string())))?;
            }
            Codec::Zstd => {
                self.output = zstd_decompress(input, expected_length).map_err(Error::Decompress)?;
            }
            Codec::QplHardware
            | Codec::QplHardwareStatic
            | Codec::QplHardwareDynamic
            | Codec::QplHardwareStaticAsync
            | Codec::QplHardwareDynamicAsync
            | Codec::QplAuto => {
                #[cfg(feature = "qpl")]
                self.qpl_job
                    .as_mut()
                    .unwrap()
                    .decompress_into(input, expected_length, &mut self.output)
                    .map_err(Error::Qpl)?;
                #[cfg(not(feature = "qpl"))]
                unreachable!();
            }
        }
        if self.output.len() != expected_length {
            return Err(Error::LengthMismatch {
                expected: expected_length,
                actual: self.output.len(),
            });
        }
        Ok(&self.output)
    }
}

#[cfg(test)]
fn compress_chunk(codec: Codec, input: &[u8], zstd_level: i32) -> Result<Vec<u8>, Error> {
    Ok(CodecWorker::new(codec, zstd_level)?
        .compress(input)?
        .to_vec())
}

#[cfg(test)]
fn decompress_chunk(codec: Codec, input: &[u8], expected_length: usize) -> Result<Vec<u8>, Error> {
    Ok(CodecWorker::new(codec, 1)?
        .decompress(input, expected_length)?
        .to_vec())
}

pub(crate) fn validate_chunk_size(chunk_size: usize) -> Result<u32, Error> {
    if chunk_size == 0 {
        return Err(Error::InvalidChunkSize(chunk_size));
    }
    u32::try_from(chunk_size).map_err(|_| Error::ChunkTooLarge)
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn compress_file(
    source: &File,
    source_offset: u64,
    source_size: u64,
    data_path: &Path,
    manifest_path: &Path,
    codec: Codec,
    chunk_size: usize,
    workers: usize,
    zstd_level: i32,
) -> Result<CompressionStats, Error> {
    let chunk_size_u32 = validate_chunk_size(chunk_size)?;
    #[cfg(feature = "qpl")]
    if let Some(huffman_mode) = codec.async_huffman_mode() {
        return compress_file_qpl_async(
            source,
            source_offset,
            source_size,
            data_path,
            manifest_path,
            codec,
            huffman_mode,
            chunk_size,
            chunk_size_u32,
            workers,
        );
    }
    let started = Instant::now();
    let output = Arc::new(
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(data_path)
            .map_err(Error::Write)?,
    );
    let chunk_count = source_size.div_ceil(chunk_size as u64) as usize;
    let next_chunk = AtomicUsize::new(0);
    let next_output_offset = AtomicU64::new(0);
    let records = Mutex::new(Vec::with_capacity(chunk_count));
    let first_error = Mutex::new(None);

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers.max(1));
        for _ in 0..workers.max(1) {
            let output = Arc::clone(&output);
            let records = &records;
            let first_error = &first_error;
            let next_chunk = &next_chunk;
            let next_output_offset = &next_output_offset;
            handles.push(scope.spawn(move || {
                let mut worker = match CodecWorker::new(codec, zstd_level) {
                    Ok(worker) => worker,
                    Err(error) => {
                        let mut stored_error = first_error.lock().unwrap();
                        if stored_error.is_none() {
                            *stored_error = Some(error);
                        }
                        return;
                    }
                };
                let mut input = Vec::with_capacity(chunk_size);
                loop {
                    let chunk_index = next_chunk.fetch_add(1, Ordering::Relaxed);
                    if chunk_index >= chunk_count || first_error.lock().unwrap().is_some() {
                        return;
                    }
                    let uncompressed_offset = chunk_index as u64 * chunk_size as u64;
                    let uncompressed_length =
                        (source_size - uncompressed_offset).min(chunk_size as u64) as usize;
                    let result = (|| {
                        input.resize(uncompressed_length, 0);
                        source
                            .read_exact_at(&mut input, source_offset + uncompressed_offset)
                            .map_err(Error::Read)?;
                        if input.iter().all(|byte| *byte == 0) {
                            records.lock().unwrap().push(ChunkRecord {
                                uncompressed_offset,
                                uncompressed_length: uncompressed_length as u32,
                                compressed_offset: 0,
                                compressed_length: 0,
                                zero: true,
                            });
                            return Ok(());
                        }
                        let compressed = worker.compress(&input)?;
                        let compressed_length =
                            u32::try_from(compressed.len()).map_err(|_| Error::ChunkTooLarge)?;
                        let compressed_offset = next_output_offset
                            .fetch_add(compressed.len() as u64, Ordering::Relaxed);
                        output
                            .write_all_at(compressed, compressed_offset)
                            .map_err(Error::Write)?;
                        records.lock().unwrap().push(ChunkRecord {
                            uncompressed_offset,
                            uncompressed_length: uncompressed_length as u32,
                            compressed_offset,
                            compressed_length,
                            zero: false,
                        });
                        Ok(())
                    })();
                    if let Err(error) = result {
                        let mut stored_error = first_error.lock().unwrap();
                        if stored_error.is_none() {
                            *stored_error = Some(error);
                        }
                        return;
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().map_err(|_| Error::WorkerPanic)?;
        }
        Ok::<(), Error>(())
    })?;
    if let Some(error) = first_error.into_inner().unwrap() {
        return Err(error);
    }

    output.sync_all().map_err(Error::Write)?;
    let output_bytes = next_output_offset.load(Ordering::Relaxed);
    let mut chunks = records.into_inner().unwrap();
    chunks.sort_unstable_by_key(|record| record.uncompressed_offset);
    let manifest = SlotManifest {
        version: FORMAT_VERSION,
        codec,
        chunk_size: chunk_size_u32,
        uncompressed_size: source_size,
        chunks,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(Error::WriteManifest)?;
    fs::write(manifest_path, manifest_bytes).map_err(Error::Write)?;

    Ok(CompressionStats {
        input_bytes: source_size,
        output_bytes,
        chunks: chunk_count,
        elapsed: started.elapsed(),
    })
}

#[cfg(feature = "qpl")]
#[expect(clippy::too_many_arguments)]
fn compress_file_qpl_async(
    source: &File,
    source_offset: u64,
    source_size: u64,
    data_path: &Path,
    manifest_path: &Path,
    codec: Codec,
    huffman_mode: HuffmanMode,
    chunk_size: usize,
    chunk_size_u32: u32,
    workers: usize,
) -> Result<CompressionStats, Error> {
    let started = Instant::now();
    let output = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(data_path)
        .map_err(Error::Write)?;
    let chunk_count = source_size.div_ceil(chunk_size as u64) as usize;
    let mut pool = QplJobPool::new(ExecutionPath::Hardware, huffman_mode, workers)?;
    let mut records = Vec::with_capacity(chunk_count);
    let mut output_offset = 0_u64;

    let mut active = vec![None; pool.capacity()];
    let mut next_chunk = 0_usize;
    let mut active_count = 0_usize;
    for (slot, metadata) in active.iter_mut().enumerate() {
        *metadata = submit_next_compression_chunk(
            &mut pool,
            slot,
            source,
            source_offset,
            source_size,
            chunk_size,
            chunk_count,
            &mut next_chunk,
            &mut records,
        )?;
        active_count += usize::from(metadata.is_some());
    }

    while active_count != 0 {
        let mut made_progress = false;
        for (slot, active_entry) in active.iter_mut().enumerate() {
            if active_entry.is_none() {
                continue;
            }
            let Some(output_size) = pool.poll(slot)? else {
                continue;
            };
            let (uncompressed_offset, uncompressed_length) = active_entry.take().unwrap();
            let compressed_length = u32::try_from(output_size).map_err(|_| Error::ChunkTooLarge)?;
            output
                .write_all_at(pool.output(slot, output_size), output_offset)
                .map_err(Error::Write)?;
            records.push(ChunkRecord {
                uncompressed_offset,
                uncompressed_length: uncompressed_length as u32,
                compressed_offset: output_offset,
                compressed_length,
                zero: false,
            });
            output_offset += output_size as u64;
            active_count -= 1;
            made_progress = true;

            *active_entry = submit_next_compression_chunk(
                &mut pool,
                slot,
                source,
                source_offset,
                source_size,
                chunk_size,
                chunk_count,
                &mut next_chunk,
                &mut records,
            )?;
            if active_entry.is_some() {
                active_count += 1;
            }
        }
        if !made_progress {
            thread::yield_now();
        }
    }

    output.sync_all().map_err(Error::Write)?;
    records.sort_unstable_by_key(|record| record.uncompressed_offset);
    let manifest = SlotManifest {
        version: FORMAT_VERSION,
        codec,
        chunk_size: chunk_size_u32,
        uncompressed_size: source_size,
        chunks: records,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(Error::WriteManifest)?;
    fs::write(manifest_path, manifest_bytes).map_err(Error::Write)?;

    Ok(CompressionStats {
        input_bytes: source_size,
        output_bytes: output_offset,
        chunks: chunk_count,
        elapsed: started.elapsed(),
    })
}

#[cfg(feature = "qpl")]
#[expect(clippy::too_many_arguments)]
fn submit_next_compression_chunk(
    pool: &mut QplJobPool,
    slot: usize,
    source: &File,
    source_offset: u64,
    source_size: u64,
    chunk_size: usize,
    chunk_count: usize,
    next_chunk: &mut usize,
    records: &mut Vec<ChunkRecord>,
) -> Result<Option<(u64, usize)>, Error> {
    while *next_chunk < chunk_count {
        let uncompressed_offset = *next_chunk as u64 * chunk_size as u64;
        let uncompressed_length =
            (source_size - uncompressed_offset).min(chunk_size as u64) as usize;
        let input = pool.input_mut(slot, uncompressed_length);
        source
            .read_exact_at(input, source_offset + uncompressed_offset)
            .map_err(Error::Read)?;
        *next_chunk += 1;
        if input.iter().all(|byte| *byte == 0) {
            records.push(ChunkRecord {
                uncompressed_offset,
                uncompressed_length: uncompressed_length as u32,
                compressed_offset: 0,
                compressed_length: 0,
                zero: true,
            });
            continue;
        }
        pool.submit_compress(slot)?;
        return Ok(Some((uncompressed_offset, uncompressed_length)));
    }
    Ok(None)
}

pub(crate) fn decompress_file(
    data_path: &Path,
    manifest_path: &Path,
    destination: &File,
    destination_offset: u64,
    expected_size: u64,
    workers: usize,
) -> Result<CompressionStats, Error> {
    let started = Instant::now();
    let manifest_bytes = fs::read(manifest_path).map_err(Error::Read)?;
    let manifest: SlotManifest =
        serde_json::from_slice(&manifest_bytes).map_err(Error::ReadManifest)?;
    if manifest.version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion(manifest.version));
    }
    if manifest.uncompressed_size != expected_size {
        return Err(Error::LengthMismatch {
            expected: expected_size as usize,
            actual: manifest.uncompressed_size as usize,
        });
    }
    let input = Arc::new(File::open(data_path).map_err(Error::Read)?);
    let compressed_size = input.metadata().map_err(Error::Read)?.len();
    let mut expected_offset = 0_u64;
    for record in &manifest.chunks {
        if record.uncompressed_offset != expected_offset {
            return Err(Error::InvalidManifest(format!(
                "chunk starts at {}, expected {expected_offset}",
                record.uncompressed_offset
            )));
        }
        expected_offset = expected_offset
            .checked_add(record.uncompressed_length as u64)
            .ok_or_else(|| Error::InvalidManifest("uncompressed range overflow".to_owned()))?;
        let compressed_end = record
            .compressed_offset
            .checked_add(record.compressed_length as u64)
            .ok_or_else(|| Error::InvalidManifest("compressed range overflow".to_owned()))?;
        if compressed_end > compressed_size {
            return Err(Error::InvalidManifest(format!(
                "compressed range ends at {compressed_end}, file length is {compressed_size}"
            )));
        }
        if record.zero && record.compressed_length != 0 {
            return Err(Error::InvalidManifest(
                "zero chunk has compressed data".to_owned(),
            ));
        }
        if !record.zero && record.uncompressed_length != 0 && record.compressed_length == 0 {
            return Err(Error::InvalidManifest(
                "non-zero chunk has no compressed data".to_owned(),
            ));
        }
    }
    if expected_offset != expected_size {
        return Err(Error::InvalidManifest(format!(
            "chunks cover {expected_offset} bytes, expected {expected_size}"
        )));
    }
    let codec = manifest.codec;
    let records = Arc::new(manifest.chunks);
    #[cfg(feature = "qpl")]
    if let Some(huffman_mode) = codec.async_huffman_mode() {
        return decompress_file_qpl_async(
            &input,
            &records,
            destination,
            destination_offset,
            expected_size,
            workers,
            huffman_mode,
            started,
        );
    }
    let next_chunk = AtomicUsize::new(0);
    let first_error = Mutex::new(None);

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers.max(1));
        for _ in 0..workers.max(1) {
            let input = Arc::clone(&input);
            let records = Arc::clone(&records);
            let first_error = &first_error;
            let next_chunk = &next_chunk;
            handles.push(scope.spawn(move || {
                let mut worker = match CodecWorker::new(codec, 1) {
                    Ok(worker) => worker,
                    Err(error) => {
                        let mut stored_error = first_error.lock().unwrap();
                        if stored_error.is_none() {
                            *stored_error = Some(error);
                        }
                        return;
                    }
                };
                let mut compressed = Vec::new();
                loop {
                    let chunk_index = next_chunk.fetch_add(1, Ordering::Relaxed);
                    let Some(record) = records.get(chunk_index) else {
                        return;
                    };
                    if first_error.lock().unwrap().is_some() {
                        return;
                    }
                    let result = (|| {
                        if record.zero {
                            return Ok(());
                        }
                        compressed.resize(record.compressed_length as usize, 0);
                        input
                            .read_exact_at(&mut compressed, record.compressed_offset)
                            .map_err(Error::Read)?;
                        let output =
                            worker.decompress(&compressed, record.uncompressed_length as usize)?;
                        destination
                            .write_all_at(output, destination_offset + record.uncompressed_offset)
                            .map_err(Error::Write)
                    })();
                    if let Err(error) = result {
                        let mut stored_error = first_error.lock().unwrap();
                        if stored_error.is_none() {
                            *stored_error = Some(error);
                        }
                        return;
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().map_err(|_| Error::WorkerPanic)?;
        }
        Ok::<(), Error>(())
    })?;
    if let Some(error) = first_error.into_inner().unwrap() {
        return Err(error);
    }

    Ok(CompressionStats {
        input_bytes: expected_size,
        output_bytes: input.metadata().map_err(Error::Read)?.len(),
        chunks: records.len(),
        elapsed: started.elapsed(),
    })
}

#[cfg(feature = "qpl")]
#[expect(clippy::too_many_arguments)]
fn decompress_file_qpl_async(
    input: &File,
    records: &[ChunkRecord],
    destination: &File,
    destination_offset: u64,
    expected_size: u64,
    workers: usize,
    huffman_mode: HuffmanMode,
    started: Instant,
) -> Result<CompressionStats, Error> {
    let mut pool = QplJobPool::new(ExecutionPath::Hardware, huffman_mode, workers)?;
    let mut active = vec![None; pool.capacity()];
    let mut next_chunk = 0_usize;
    let mut active_count = 0_usize;
    for (slot, active_record) in active.iter_mut().enumerate() {
        *active_record =
            submit_next_decompression_chunk(&mut pool, slot, input, records, &mut next_chunk)?;
        active_count += usize::from(active_record.is_some());
    }

    while active_count != 0 {
        let mut made_progress = false;
        for (slot, active_entry) in active.iter_mut().enumerate() {
            if active_entry.is_none() {
                continue;
            }
            let Some(output_size) = pool.poll(slot)? else {
                continue;
            };
            let record_index = active_entry.take().unwrap();
            let record = &records[record_index];
            if output_size != record.uncompressed_length as usize {
                return Err(Error::LengthMismatch {
                    expected: record.uncompressed_length as usize,
                    actual: output_size,
                });
            }
            destination
                .write_all_at(
                    pool.output(slot, output_size),
                    destination_offset + record.uncompressed_offset,
                )
                .map_err(Error::Write)?;
            active_count -= 1;
            made_progress = true;

            *active_entry =
                submit_next_decompression_chunk(&mut pool, slot, input, records, &mut next_chunk)?;
            if active_entry.is_some() {
                active_count += 1;
            }
        }
        if !made_progress {
            thread::yield_now();
        }
    }

    Ok(CompressionStats {
        input_bytes: expected_size,
        output_bytes: input.metadata().map_err(Error::Read)?.len(),
        chunks: records.len(),
        elapsed: started.elapsed(),
    })
}

#[cfg(feature = "qpl")]
fn submit_next_decompression_chunk(
    pool: &mut QplJobPool,
    slot: usize,
    input: &File,
    records: &[ChunkRecord],
    next_chunk: &mut usize,
) -> Result<Option<usize>, Error> {
    while let Some(record) = records.get(*next_chunk) {
        let record_index = *next_chunk;
        *next_chunk += 1;
        if record.zero {
            continue;
        }
        input
            .read_exact_at(
                pool.input_mut(slot, record.compressed_length as usize),
                record.compressed_offset,
            )
            .map_err(Error::Read)?;
        pool.submit_decompress(slot, record.uncompressed_length as usize)?;
        return Ok(Some(record_index));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::os::unix::fs::FileExt;

    use super::*;

    fn sample() -> Vec<u8> {
        (0..256 * 1024).map(|index| (index % 251) as u8).collect()
    }

    #[test]
    fn codec_names_round_trip() {
        for codec in [
            Codec::Lz4,
            Codec::Zstd,
            Codec::QplHardware,
            Codec::QplHardwareStatic,
            Codec::QplHardwareDynamic,
            Codec::QplHardwareStaticAsync,
            Codec::QplHardwareDynamicAsync,
            Codec::QplAuto,
        ] {
            assert_eq!(codec.to_string().parse::<Codec>().unwrap(), codec);
        }
    }

    #[test]
    fn lz4_round_trip() {
        let input = sample();
        let compressed = compress_chunk(Codec::Lz4, &input, 1).unwrap();
        assert_eq!(
            decompress_chunk(Codec::Lz4, &compressed, input.len()).unwrap(),
            input
        );
    }

    #[test]
    fn zstd_round_trip() {
        let input = sample();
        let compressed = compress_chunk(Codec::Zstd, &input, 1).unwrap();
        assert_eq!(
            decompress_chunk(Codec::Zstd, &compressed, input.len()).unwrap(),
            input
        );
    }

    #[test]
    #[cfg(not(feature = "qpl"))]
    fn qpl_fails_explicitly_when_unavailable() {
        assert!(matches!(
            compress_chunk(Codec::QplHardware, b"data", 1),
            Err(Error::QplUnavailable)
        ));
    }

    #[test]
    #[cfg(feature = "qpl")]
    fn qpl_hardware_huffman_modes_round_trip() {
        let input = sample();
        for codec in [Codec::QplHardwareStatic, Codec::QplHardwareDynamic] {
            let compressed = compress_chunk(codec, &input, 1).unwrap();
            assert_eq!(
                decompress_chunk(codec, &compressed, input.len()).unwrap(),
                input
            );
        }
    }

    #[test]
    #[cfg(feature = "qpl")]
    fn qpl_hardware_async_file_round_trip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let source_path = temp_dir.path().join("source");
        let data_path = temp_dir.path().join("compressed");
        let manifest_path = temp_dir.path().join("manifest.json");
        let destination_path = temp_dir.path().join("destination");
        let input = sample();
        fs::write(&source_path, &input).unwrap();
        let source = File::open(source_path).unwrap();
        let destination = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(destination_path)
            .unwrap();
        destination.set_len(input.len() as u64).unwrap();

        for codec in [
            Codec::QplHardwareStaticAsync,
            Codec::QplHardwareDynamicAsync,
        ] {
            compress_file(
                &source,
                0,
                input.len() as u64,
                &data_path,
                &manifest_path,
                codec,
                64 * 1024,
                4,
                1,
            )
            .unwrap();
            decompress_file(
                &data_path,
                &manifest_path,
                &destination,
                0,
                input.len() as u64,
                4,
            )
            .unwrap();

            let mut actual = vec![0_u8; input.len()];
            destination.read_exact_at(&mut actual, 0).unwrap();
            assert_eq!(actual, input);
        }
    }

    #[test]
    fn stats_report_ratio_and_throughput() {
        let stats = CompressionStats {
            input_bytes: 2 << 30,
            output_bytes: 1 << 30,
            chunks: 2,
            elapsed: Duration::from_secs(2),
        };
        assert_eq!(stats.ratio(), 0.5);
        assert_eq!(stats.throughput_gib_per_second(), 1.0);
    }

    #[test]
    fn parallel_file_round_trip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let source_path = temp_dir.path().join("source");
        let data_path = temp_dir.path().join("compressed");
        let manifest_path = temp_dir.path().join("index.json");
        let restored_path = temp_dir.path().join("restored");
        let input: Vec<u8> = (0..3 * 1024 * 1024 + 17)
            .map(|index| ((index * 17) % 251) as u8)
            .collect();
        fs::write(&source_path, &input).unwrap();
        let source = File::open(source_path).unwrap();

        let compressed = compress_file(
            &source,
            0,
            input.len() as u64,
            &data_path,
            &manifest_path,
            Codec::Lz4,
            256 * 1024,
            4,
            1,
        )
        .unwrap();
        assert_eq!(compressed.chunks, 13);

        let restored = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(restored_path)
            .unwrap();
        restored.set_len(input.len() as u64).unwrap();
        let decompressed = decompress_file(
            &data_path,
            &manifest_path,
            &restored,
            0,
            input.len() as u64,
            3,
        )
        .unwrap();
        assert_eq!(decompressed.chunks, 13);
        let mut actual = vec![0_u8; input.len()];
        restored.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, input);
    }

    #[test]
    fn zero_chunks_are_elided_and_restored() {
        let temp_dir = tempfile::tempdir().unwrap();
        let source_path = temp_dir.path().join("source");
        let data_path = temp_dir.path().join("compressed");
        let manifest_path = temp_dir.path().join("index.json");
        let restored_path = temp_dir.path().join("restored");
        let mut input = vec![0_u8; 3 * 64 * 1024];
        input[64 * 1024..2 * 64 * 1024].fill(0x5a);
        fs::write(&source_path, &input).unwrap();

        compress_file(
            &File::open(source_path).unwrap(),
            0,
            input.len() as u64,
            &data_path,
            &manifest_path,
            Codec::Lz4,
            64 * 1024,
            2,
            1,
        )
        .unwrap();
        let manifest: SlotManifest =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        assert_eq!(manifest.chunks.iter().filter(|chunk| chunk.zero).count(), 2);
        assert!(
            manifest
                .chunks
                .iter()
                .filter(|chunk| chunk.zero)
                .all(|chunk| chunk.compressed_length == 0)
        );

        let restored = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(restored_path)
            .unwrap();
        restored.set_len(input.len() as u64).unwrap();
        decompress_file(
            &data_path,
            &manifest_path,
            &restored,
            0,
            input.len() as u64,
            2,
        )
        .unwrap();
        let mut actual = vec![0_u8; input.len()];
        restored.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, input);
    }
}
