use crate::{VmmService, VmInstanceConfig, VmmError};
use form_types::VmmEvent;

#[allow(unused)]
pub async fn handle_vmm_event(service: &mut VmmService, event: &VmmEvent) -> Result<(), VmmError> {
    match event {
        VmmEvent::Create { 
            owner,
            recovery_id,
            requestor,
            distro,
            version,
            user_data,
            meta_data,
            memory_mb,
            vcpu_count,
            name, 
            custom_cmdline, 
            rng_source, 
            console_type 
        } => {
            let service_config = service.config.clone();
            let instance_config: VmInstanceConfig = (event, &service_config).try_into().map_err(|e: VmmError| {
                VmmError::Config(e.to_string())
            })?;
            // TODO: return Future, and stash future in a `FuturesUnordered`
            // to be awaited asynchronously.
            service.create_vm(instance_config).await?;
            Ok(())
        }, 
        VmmEvent::Start { owner, recovery_id, id, requestor } => todo!(), 
        VmmEvent::Stop { owner, recovery_id, id, requestor } => todo!(),
        VmmEvent::Delete { owner, recovery_id, id, requestor } => todo!(),
        VmmEvent::Copy => todo!(),
        VmmEvent::Migrate => todo!(),
        VmmEvent::Snapshot => todo!(),
    }
}
