use std::collections::BTreeMap;
use std::fs::File;
use std::os::fd::RawFd;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::fd::SerializableFd;
use crate::fd_device::FdDevice;

#[derive(Clone, Debug, PartialEq, Eq)]
enum FdMapInner {
    Serialized(Vec<(FdDevice, Vec<SerializableFd>)>),
    Active(BTreeMap<FdDevice, Vec<SerializableFd>>),
}

impl Serialize for FdMapInner {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            FdMapInner::Serialized(inner) => inner.serialize(serializer),
            FdMapInner::Active(inner) => {
                let vec: Vec<(FdDevice, Vec<SerializableFd>)> = inner.clone().into_iter().collect();
                vec.serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for FdMapInner {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = Vec::<(FdDevice, Vec<SerializableFd>)>::deserialize(deserializer)?;
        Ok(Self::Serialized(inner))
    }
}

impl FromIterator<(FdDevice, Vec<u64>)> for FdMapInner {
    fn from_iter<T: IntoIterator<Item = (FdDevice, Vec<u64>)>>(iter: T) -> Self {
        let vec = iter
            .into_iter()
            .map(|(fd_device, fds)| {
                let vec = fds
                    .iter()
                    .map(|fd| SerializableFd::new_serialized(*fd as RawFd))
                    .collect();
                (fd_device, vec)
            })
            .collect();
        Self::Serialized(vec)
    }
}

impl FromIterator<(FdDevice, Vec<u64>)> for FdMap {
    fn from_iter<T: IntoIterator<Item = (FdDevice, Vec<u64>)>>(iter: T) -> Self {
        Self {
            fd_map: FdMapInner::from_iter(iter),
        }
    }
}

impl FdMapInner {
    fn new() -> Self {
        Self::default()
    }

    fn new_with_entry(key: FdDevice, value: Vec<SerializableFd>) -> Self {
        if value.iter().all(|fd| fd.is_active()) {
            Self::Active(BTreeMap::from_iter(vec![(key, value)]))
        } else {
            Self::Serialized(vec![(key, value)])
        }
    }

    unsafe fn new_from_iter_active<T: IntoIterator<Item = (FdDevice, Vec<u64>)>>(iter: T) -> Self {
        let result = iter
            .into_iter()
            .map(|(fd_device, fds)| {
                let vec = fds
                    .iter()
                    .map(|fd| {
                        //SAFETY: TODO(fd)
                        unsafe { SerializableFd::new_active_from_raw(*fd as RawFd) }
                    })
                    .collect();
                (fd_device, vec)
            })
            .collect();
        Self::Active(result)
    }

    fn is_active(&self) -> bool {
        match self {
            FdMapInner::Serialized(_) => false,
            FdMapInner::Active(_) => true,
        }
    }

    fn merge(&mut self, other: Self) {
        match (self, other) {
            (Self::Serialized(this), Self::Serialized(other)) => {
                other.into_iter().for_each(|(device, fds)| {
                    this.push((device, fds));
                });
            }
            (Self::Active(this), Self::Active(other)) => {
                other.into_iter().for_each(|(device, mut fds)| {
                    this.entry(device)
                        .and_modify(|entry| entry.append(&mut fds))
                        .or_insert(fds);
                });
            }
            _ => {
                //TODO(fd)
                panic!("Can only merge both active or both serialized")
            }
        }
    }

    fn create_btree(
        vec: &[(FdDevice, Vec<SerializableFd>)],
    ) -> BTreeMap<FdDevice, Vec<SerializableFd>> {
        let mut btree = BTreeMap::new();
        vec.iter().for_each(|(fd_device, fds)| {
            btree
                .entry(fd_device.clone())
                .and_modify(|btree_fds: &mut Vec<SerializableFd>| {
                    btree_fds.append(&mut fds.clone());
                })
                .or_insert(fds.clone());
        });
        btree
    }

    fn can_update(&self, other: &Self) -> bool {
        if let Self::Active(this) = self
            && let Self::Serialized(other) = other
        {
            let self_btree = Self::create_btree(other);
            self_btree.iter().all(|(key, values)| {
                if let Some(this_values) = this.get(key) {
                    values.len() == this_values.len()
                } else {
                    false
                }
            })
        } else {
            false
        }
    }

    //TODO(fd): check for duplicates in serialized variant

    fn update_fds(&mut self, mut fds: Vec<File>) {
        let Self::Serialized(this) = self else {
            panic!("cannot update active");
        };
        let mut btree = BTreeMap::new();
        this.iter().for_each(|(fd_device, this_fds)| {
            btree.insert(
                fd_device.clone(),
                fds.drain(..this_fds.len())
                    .map(|fd| SerializableFd::new_active(fd.into()))
                    .collect(),
            );
        });
        *self = Self::Active(btree);
    }

    fn is_empty(&self) -> bool {
        match self {
            FdMapInner::Serialized(serialized) => serialized.is_empty(),
            FdMapInner::Active(active) => active.is_empty(),
        }
    }

    fn remove(&mut self, fd_device: &FdDevice) -> Option<Vec<SerializableFd>> {
        //TODO(fd): proper error handling
        let Self::Active(btree) = self else {
            panic!("failed to remove")
        };
        btree.remove(fd_device)
    }

    pub fn extract_fds(&mut self) -> Vec<SerializableFd> {
        //TODO(fd):
        match self {
            FdMapInner::Serialized(_) => {
                panic!("cannot extract serialized FDs")
            }
            FdMapInner::Active(inner) => inner.clone().into_values().flatten().collect(),
        }
    }
}

impl Default for FdMapInner {
    fn default() -> Self {
        Self::Serialized(Vec::new())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(transparent)]
pub struct FdMap {
    fd_map: FdMapInner,
}

impl FdMap {
    pub fn new() -> Self {
        Self {
            fd_map: FdMapInner::new(),
        }
    }

    /// # Safety
    ///
    /// TODO(fd)
    pub unsafe fn new_from_iter_active<T: IntoIterator<Item = (FdDevice, Vec<u64>)>>(
        iter: T,
    ) -> Self {
        // SAFETY: TODO(fd)
        let fd_map = unsafe { FdMapInner::new_from_iter_active(iter) };

        Self { fd_map }
    }

    pub fn new_with_entry(key: FdDevice, value: Vec<SerializableFd>) -> Self {
        Self {
            fd_map: FdMapInner::new_with_entry(key, value),
        }
    }

    pub fn merge(&mut self, other: FdMap) {
        self.fd_map.merge(other.fd_map);
    }

    pub fn can_update(&self, other: &FdMap) -> bool {
        self.fd_map.can_update(&other.fd_map)
    }

    pub fn remove(&mut self, device: &FdDevice) -> Option<Vec<SerializableFd>> {
        self.fd_map.remove(device)
    }

    pub fn is_empty(&self) -> bool {
        self.fd_map.is_empty()
    }

    pub fn is_active(&self) -> bool {
        self.fd_map.is_active()
    }

    pub fn update_fds(&mut self, fds: Vec<File>) {
        // TODO(fd): proper error handling
        self.fd_map.update_fds(fds);
    }

    pub fn extract_fds(&mut self) -> Vec<SerializableFd> {
        self.fd_map.extract_fds()
    }
}

#[cfg(test)]
mod unit_tests {
    use crate::{FdDevice, FdMap, SerializableFd};

    #[test]
    fn test() {
        let fd_map = FdMap::new_with_entry(
            FdDevice::Net {
                id: "10".to_owned(),
            },
            vec![SerializableFd::new_serialized(1)],
        );
        let fd_map_json = serde_json::to_string(&fd_map).unwrap();

        assert_eq!(fd_map_json, r#"[["net(10)",[1]]]"#);
    }
}
