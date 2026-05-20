// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! A barrier to distinguish between the active and deserialized state for structs/enums.
//!
//! Some resources, most notably file descriptors, cannot be de-/serialized.
//! The barrier allows a type-safe handling and transition of states while guaranteeing that any active struct does not contain invalid remnants from deserialization.

mod activation;
mod extraction;
mod fd;
pub mod fd_ident;

use std::collections::HashMap;

pub use activation::{FdUpdateError, IngestScmRights, IngestScmRightsError, UpdateFds};
pub use extraction::{ExportScmRights, ExtractFdMap, ExtractFdMapError};
pub use fd::{Fd, FdMarker, FromRawError};
pub use fd_ident::FdIdent;
use serde::Serialize;

pub type FdMap = HashMap<FdIdent, Vec<Fd<Active>>>;

trait Sealed {}

/// Marker to indicate a struct has been deserialized and not yet activated.
///
/// See the [module description][crate::deserialization_barrier] for more information.
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash, Serialize)]
pub struct Deserialized;
/// Marker for active structs.
///
/// See the [module description][crate::deserialization_barrier] for more information.
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash, Serialize)]
pub struct Active;

impl Sealed for Deserialized {}
impl Sealed for Active {}
