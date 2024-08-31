use std::ops::Deref;

use virtio_queue::{DescriptorChain, Error, Queue, QueueT};
use vm_memory::GuestMemory;

pub trait QueueExt {
    fn pop_desc_chain_with_notification<M>(
        &mut self,
        mem: M,
    ) -> Result<Option<DescriptorChain<M>>, Error>
    where
        // TODO: remove Sized bound once `Queue::enable_notification<M>` add `?Sized` for `M`.
        M: Clone + Deref<Target: GuestMemory + Sized>;
}

impl QueueExt for Queue {
    fn pop_desc_chain_with_notification<M>(
        &mut self,
        mem: M,
    ) -> Result<Option<DescriptorChain<M>>, Error>
    where
        M: Clone + Deref<Target: GuestMemory + Sized>,
    {
        if let Some(dc) = self.pop_descriptor_chain(mem.clone()) {
            return Ok(Some(dc));
        }
        if self.enable_notification(mem.deref())? {
            return Ok(self.pop_descriptor_chain(mem));
        }
        Ok(None)
    }
}
