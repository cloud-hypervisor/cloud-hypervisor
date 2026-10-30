// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, hash_map};
use std::sync::{Arc, Mutex};

use pci::PciBdf;
use serde::{Deserialize, Serialize};
use vm_device::Resource;
use vm_migration::Migratable;

use crate::device_manager::PciDeviceHandle;

#[serde_with::skip_serializing_none]
#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceNode {
    pub id: String,
    pub resources: Vec<Resource>,
    pub parent: Option<String>,
    pub children: Vec<String>,
    #[serde(skip)]
    pub migratable: Option<Arc<Mutex<dyn Migratable>>>,
    pub pci_bdf: Option<PciBdf>,
    #[serde(skip)]
    pub pci_device_handle: Option<PciDeviceHandle>,
}

impl DeviceNode {
    pub fn new(id: String, migratable: Option<Arc<Mutex<dyn Migratable>>>) -> Self {
        DeviceNode {
            id,
            resources: Vec::new(),
            parent: None,
            children: Vec::new(),
            migratable,
            pci_bdf: None,
            pci_device_handle: None,
        }
    }
}

#[macro_export]
macro_rules! device_node {
    ($id:ident) => {
        DeviceNode::new($id.clone(), None)
    };
    ($id:ident, $device:ident) => {
        DeviceNode::new(
            $id.clone(),
            Some(Arc::clone(&$device) as Arc<Mutex<dyn Migratable>>),
        )
    };
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DeviceTree(HashMap<String, DeviceNode>);

impl DeviceTree {
    pub fn new() -> Self {
        DeviceTree(HashMap::new())
    }
    pub fn contains_key(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }
    pub fn get(&self, k: &str) -> Option<&DeviceNode> {
        self.0.get(k)
    }
    pub fn get_mut(&mut self, k: &str) -> Option<&mut DeviceNode> {
        self.0.get_mut(k)
    }
    pub fn insert(&mut self, k: String, v: DeviceNode) -> Option<DeviceNode> {
        self.0.insert(k, v)
    }
    pub fn remove(&mut self, k: &str) -> Option<DeviceNode> {
        self.0.remove(k)
    }
    pub fn iter(&self) -> hash_map::Iter<'_, String, DeviceNode> {
        self.0.iter()
    }
    pub fn pci_devices(&self) -> Vec<&DeviceNode> {
        self.0
            .values()
            .filter(|v| v.pci_bdf.is_some() && v.pci_device_handle.is_some())
            .collect()
    }

    pub fn remove_node_by_pci_bdf(&mut self, pci_bdf: PciBdf) -> Option<DeviceNode> {
        let mut id = None;
        for (k, v) in self.0.iter() {
            if v.pci_bdf == Some(pci_bdf) {
                id = Some(k.clone());
                break;
            }
        }

        if let Some(id) = &id {
            self.0.remove(id)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceNode, DeviceTree};

    #[test]
    fn test_device_tree() {
        // Check new()
        let mut device_tree = DeviceTree::new();
        assert_eq!(device_tree.0.len(), 0);

        // Check insert()
        let id = String::from("id1");
        device_tree.insert(id.clone(), DeviceNode::new(id.clone(), None));
        assert_eq!(device_tree.0.len(), 1);
        let node = device_tree.0.get(&id);
        assert!(node.is_some());
        let node = node.unwrap();
        assert_eq!(node.id, id);

        // Check get()
        let id2 = String::from("id2");
        assert!(device_tree.get(&id).is_some());
        assert!(device_tree.get(&id2).is_none());

        // Check get_mut()
        let node = device_tree.get_mut(&id).unwrap();
        node.id.clone_from(&id2);
        let node = device_tree.0.get(&id).unwrap();
        assert_eq!(node.id, id2);

        // Check remove()
        let node = device_tree.remove(&id).unwrap();
        assert_eq!(node.id, id2);
        assert_eq!(device_tree.0.len(), 0);

        // Check iter()
        let disk_id = String::from("disk0");
        let net_id = String::from("net0");
        let rng_id = String::from("rng0");
        let device_list = vec![
            (disk_id.clone(), device_node!(disk_id)),
            (net_id.clone(), device_node!(net_id)),
            (rng_id.clone(), device_node!(rng_id)),
        ];
        device_tree.0.extend(device_list);
        for (id, node) in device_tree.iter() {
            if id == &disk_id {
                assert_eq!(node.id, disk_id);
            } else if id == &net_id {
                assert_eq!(node.id, net_id);
            } else if id == &rng_id {
                assert_eq!(node.id, rng_id);
            } else {
                unreachable!()
            }
        }
    }
}
