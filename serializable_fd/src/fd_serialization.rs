use std::fs::File;

use crate::FdMap;

//TODO(fd): add/improve documentation
pub trait FdSerialization {
    /// Creates an `FdMap` for `Self`.
    fn create_fd_map(&self) -> FdMap;

    /// Applies `fd_map` to `Self`, updating all fds in `Self`.
    fn apply_fd_map(&mut self, fd_map: &mut FdMap);

    /// Update all fds with the supplied `fds`.
    fn update_fds(&mut self, fds: Vec<File>) {
        let mut fd_map = self.create_fd_map();
        fd_map.update_fds(fds);
        self.apply_fd_map(&mut fd_map);
        if !fd_map.is_empty() {
            // TODO(fd): error handling
            panic!("superfluous fds");
        }
    }

    /// Checks whether `other` can update `Self`.
    fn can_update(&self, other: &FdMap) -> bool {
        let reference_fd_map = self.create_fd_map();
        other.can_update(&reference_fd_map)
    }
}
