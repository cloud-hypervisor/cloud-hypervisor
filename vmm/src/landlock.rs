// Copyright © 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::io::Error as IoError;
use std::path::PathBuf;

#[cfg(test)]
use landlock::make_bitflags;
use landlock::{
    path_beneath_rules, Access, AccessFs, BitFlags, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetError, ABI,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LandlockError {
    /// All RulesetErrors from Landlock library are wrapped in this error
    #[error("Error creating/adding/restricting ruleset: {0}")]
    ManageRuleset(#[source] RulesetError),

    /// Error opening path
    #[error("Error opening path: {0}")]
    OpenPath(#[source] IoError),

    /// Invalid Landlock access
    #[error("Invalid Landlock access: {0}")]
    InvalidLandlockAccess(String),

    /// Invalid Path
    #[error("Invalid path")]
    InvalidPath,
}

// https://docs.rs/landlock/latest/landlock/enum.ABI.html for more info on ABI
static ABI: ABI = ABI::V3;

#[derive(Debug)]
pub(crate) struct LandlockAccess {
    access: BitFlags<AccessFs>,
}

impl TryFrom<&str> for LandlockAccess {
    type Error = LandlockError;

    fn try_from(s: &str) -> Result<LandlockAccess, LandlockError> {
        if s.is_empty() {
            return Err(LandlockError::InvalidLandlockAccess(
                "Access cannot be empty".to_string(),
            ));
        }

        let mut access = BitFlags::<AccessFs>::empty();
        for c in s.chars() {
            match c {
                'r' => access |= AccessFs::from_read(ABI),
                'w' => access |= AccessFs::from_write(ABI),
                _ => {
                    return Err(LandlockError::InvalidLandlockAccess(
                        format!("Invalid access: {c}").to_string(),
                    ))
                }
            };
        }
        Ok(LandlockAccess { access })
    }
}
pub struct Landlock {
    ruleset: RulesetCreated,
}

impl Landlock {
    pub fn new() -> Result<Landlock, LandlockError> {
        let file_access = AccessFs::from_all(ABI);

        let def_ruleset = Ruleset::default()
            .handle_access(file_access)
            .map_err(LandlockError::ManageRuleset)?;

        // By default, rulesets are created in `BestEffort` mode. This lets Landlock
        // to enable all the supported rules and silently ignore the unsupported ones.
        let ruleset = def_ruleset.create().map_err(LandlockError::ManageRuleset)?;

        Ok(Landlock { ruleset })
    }

    pub(crate) fn add_rule(
        &mut self,
        path: PathBuf,
        access: BitFlags<AccessFs>,
    ) -> Result<(), LandlockError> {
        // path_beneath_rules in landlock crate handles file and directory access rules.
        // Incoming path/s are passed to path_beneath_rules, so that we don't
        // have to worry about the type of the path.
        let paths = vec![path.clone()];
        let path_beneath_rules = path_beneath_rules(paths, access);
        self.ruleset
            .as_mut()
            .add_rules(path_beneath_rules)
            .map_err(LandlockError::ManageRuleset)?;
        Ok(())
    }

    pub(crate) fn add_rule_with_access(
        &mut self,
        path: PathBuf,
        access: &str,
    ) -> Result<(), LandlockError> {
        self.add_rule(path, LandlockAccess::try_from(access)?.access)?;
        Ok(())
    }

    pub fn restrict_self(self) -> Result<(), LandlockError> {
        self.ruleset
            .restrict_self()
            .map_err(LandlockError::ManageRuleset)?;
        Ok(())
    }
}

#[test]
fn test_try_from_access() {
    // These access rights could change in future versions of Landlock. Listing
    // them here explicitly to raise their visibility during code reviews.
    let read_access = make_bitflags!(AccessFs::{
        Execute
        | ReadFile
        | ReadDir
    });
    let write_access = make_bitflags!(AccessFs::{
        WriteFile
        | RemoveDir
        | RemoveFile
        | MakeChar
        | MakeDir
        | MakeReg
        | MakeSock
        | MakeFifo
        | MakeBlock
        | MakeSym
        | Refer
        | Truncate
    });
    let landlock_access = LandlockAccess::try_from("rw").unwrap();
    assert!(landlock_access.access == read_access | write_access);

    let landlock_access = LandlockAccess::try_from("r").unwrap();
    assert!(landlock_access.access == read_access);

    let landlock_access = LandlockAccess::try_from("w").unwrap();
    assert!(landlock_access.access == write_access);

    LandlockAccess::try_from("").unwrap_err();
}
