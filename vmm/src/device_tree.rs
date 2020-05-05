// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use vm_device::Resource;
use vm_migration::Migratable;

#[derive(Clone, Serialize, Deserialize)]
pub struct DeviceNode {
    pub id: String,
    pub resources: Vec<Resource>,
    pub parent: Option<String>,
    pub children: Vec<String>,
    #[serde(skip)]
    pub migratable: Option<Arc<Mutex<dyn Migratable>>>,
}

impl DeviceNode {
    pub fn new(id: String, migratable: Option<Arc<Mutex<dyn Migratable>>>) -> Self {
        DeviceNode {
            id,
            resources: Vec::new(),
            parent: None,
            children: Vec::new(),
            migratable,
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
    pub fn get(&self, k: &str) -> Option<&DeviceNode> {
        self.0.get(k)
    }
    pub fn get_mut(&mut self, k: &str) -> Option<&mut DeviceNode> {
        self.0.get_mut(k)
    }
    pub fn insert(&mut self, k: String, v: DeviceNode) -> Option<DeviceNode> {
        self.0.insert(k, v)
    }
    #[cfg(feature = "pci_support")]
    pub fn remove(&mut self, k: &str) -> Option<DeviceNode> {
        self.0.remove(k)
    }
    pub fn iter(&self) -> std::collections::hash_map::Iter<String, DeviceNode> {
        self.0.iter()
    }
    pub fn breadth_first_traversal(&self) -> BftIter {
        BftIter::new(&self.0)
    }
}

// Breadth first traversal iterator.
pub struct BftIter<'a> {
    nodes: Vec<&'a DeviceNode>,
}

impl<'a> BftIter<'a> {
    fn new(hash_map: &'a HashMap<String, DeviceNode>) -> Self {
        let mut nodes = Vec::new();

        for (_, node) in hash_map.iter() {
            if node.parent.is_none() {
                nodes.push(node);
            }
        }

        let mut node_layer = nodes.as_slice();
        loop {
            let mut next_node_layer = Vec::new();

            for node in node_layer.iter() {
                for child_node_id in node.children.iter() {
                    if let Some(child_node) = hash_map.get(child_node_id) {
                        next_node_layer.push(child_node);
                    }
                }
            }

            if next_node_layer.is_empty() {
                break;
            }

            let pos = nodes.len();
            nodes.extend(next_node_layer);

            node_layer = &nodes[pos..];
        }

        BftIter { nodes }
    }
}

impl<'a> Iterator for BftIter<'a> {
    type Item = &'a DeviceNode;

    fn next(&mut self) -> Option<Self::Item> {
        if self.nodes.is_empty() {
            None
        } else {
            Some(self.nodes.remove(0))
        }
    }
}

impl<'a> DoubleEndedIterator for BftIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.nodes.pop()
    }
}
