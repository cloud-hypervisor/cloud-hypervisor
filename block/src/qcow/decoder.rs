// Copyright 2025 The Cloud Hypervisor Authors. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Zlib decompress error")]
    ZlibDecompress(#[source] flate2::DecompressError),
    #[error("Zlib unexpected status: {0:?}")]
    ZlibUnexpectedStatus(flate2::Status),
    #[error("Zstd decompress error")]
    ZstdDecompress(#[source] std::io::Error),
    #[error("Zstd: failed to fill buffer")]
    ZstdFillBuffer(#[source] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Generic trait for decoding zlib/zstd formats
pub trait Decoder {
    fn decode(&self, input: &[u8], output: &mut [u8]) -> Result<usize>;
}

#[derive(Default)]
pub struct ZlibDecoder {}

impl Decoder for ZlibDecoder {
    fn decode(&self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        use flate2::{Decompress, FlushDecompress, Status};

        let mut decompressor = Decompress::new(false);
        let status = decompressor
            .decompress(input, output, FlushDecompress::Finish)
            .map_err(Error::ZlibDecompress)?;
        if status == Status::StreamEnd {
            Ok(decompressor.total_out() as usize)
        } else {
            Err(Error::ZlibUnexpectedStatus(status))
        }
    }
}

#[derive(Default)]
pub struct ZstdDecoder {}

impl Decoder for ZstdDecoder {
    fn decode(&self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        use std::io::Read;

        let mut decoder = zstd::stream::read::Decoder::new(input).map_err(Error::ZstdDecompress)?;
        let decoded_size = decoder.read(output).map_err(Error::ZstdFillBuffer)?;
        Ok(decoded_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zlib_decode() {
        let d = ZlibDecoder::default();
        let valid_input = vec![99, 96, 100, 98, 6, 0];
        let mut output1 = vec![0; 4];
        d.decode(&valid_input, &mut output1).unwrap();
        assert_eq!(&output1, b"\x00\x01\x02\x03");

        let invalid_input = vec![1, 2, 3, 4];
        let mut output2 = vec![0; 1024];
        d.decode(&invalid_input, &mut output2).unwrap_err();
    }

    #[test]
    fn test_zstd_decode() {
        let d = ZstdDecoder::default();
        let valid_input = vec![40, 181, 47, 253, 32, 2, 17, 0, 0, 1, 254];
        let mut output1 = vec![0; 2];
        d.decode(&valid_input, &mut output1).unwrap();
        assert_eq!(&output1, b"\x01\xfe");

        let invalid_input = vec![1, 2, 3, 4];
        let mut output2 = vec![0; 1024];
        d.decode(&invalid_input, &mut output2).unwrap_err();
    }
}
