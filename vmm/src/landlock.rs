// Copyright © 2024 Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0
use crate::{Deserialize, Serialize};
use bitflags::bitflags;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq,  Serialize, Deserialize)]
    pub struct Perms: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
        const EXECUTE = 0b00000100;
    }
}
use landlock::{
    path_beneath_rules, Access, AccessFs, BitFlags, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetError, ABI,
};
use std::path::PathBuf;

use crate::vm_config::LandlockConfig;

static ABI: ABI = ABI::V3;
pub struct Landlock {
    ruleset: RulesetCreated,
}

impl Landlock {
    pub fn new() -> Result<Landlock, RulesetError> {
        let file_access = AccessFs::from_all(ABI);
        let def_ruleset = Ruleset::default().handle_access(file_access)?;

        let ruleset = def_ruleset.create()?;

        Ok(Landlock { ruleset })
    }

    pub fn add_rule(
        self,
        path: PathBuf,
        access: BitFlags<AccessFs>,
    ) -> Result<Landlock, RulesetError> {
        // path_beneath_rules in landlock crate handles file and directory access rules.
        // Incoming path/s are passed to path_beneath_rules, so that we don't
        // have to worry about the type of the path.
        let paths = vec![path.clone()];
        let path_beneath_rules = path_beneath_rules(paths, access);
        let ruleset = self.ruleset.add_rules(path_beneath_rules)?;
        Ok(Landlock { ruleset })
    }

    fn flags_to_access(&self, flags: Perms) -> BitFlags<AccessFs> {
        let mut perms = BitFlags::<AccessFs>::empty();
        if flags & Perms::READ != Perms::empty() {
            perms |= AccessFs::from_read(ABI);
        }
        if flags & Perms::READ != Perms::empty() {
            perms |= AccessFs::from_write(ABI);
        }
        perms
    }

    pub fn add_rule_with_flags(
        self,
        path: PathBuf,
        flags: Perms,
    ) -> Result<Landlock, RulesetError> {
        let perms = self.flags_to_access(flags);
        let landlock = self.add_rule(path.to_path_buf(), perms)?;
        Ok(landlock)
    }

    pub fn apply_config(
        self,
        landlock_config: Vec<LandlockConfig>,
    ) -> Result<Landlock, RulesetError> {
        let mut landlock = self;
        for config in landlock_config {
            let perms = landlock.flags_to_access(config.flags);
            landlock = landlock.add_rule(config.path, perms)?;
        }
        Ok(landlock)
    }

    pub fn restrict_self(self) -> Result<(), RulesetError> {
        self.ruleset.restrict_self()?;
        Ok(())
    }
}
