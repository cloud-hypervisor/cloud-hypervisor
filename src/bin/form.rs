use clap::{Parser, Subcommand, Args, ArgGroup};
use vmm_service::{api::CreateVmRequest, Distro};

#[derive(Debug, Parser)]
#[command(name = "form", about = "Formation Developer Client")]
/// Welcome to the form developer CLI
/// from this CLI you can create & manage Linux VPS instances 
/// in the formation network.
pub struct Cli {
    #[command(subcommand)]
    command: FormCommand
}

#[derive(Debug, Subcommand)]
pub enum FormCommand {
    #[command(group = ArgGroup::new("required_group")
        .args(["mnemonic", "private_key", "keyfile"])
        .required(true))]
    Create(CreateVm),
    Start,
    Stop,
    Delete,
    Commit,
    Get,
    Ssh
}

#[derive(Clone, Debug, Args)]
/// Options to create a linux Virtual Private Server instance in the 
/// formation network.
pub struct CreateVm {
    /// The endpoint to send the request to (e.g. "http://127.0.0.1:3002")
    #[clap(long, short)]
    endpoint: String,
    /// The distro being requested, currently only Ubuntu is supported
    #[clap(long, short, default_value_t=Distro::Ubuntu)]
    distro: Distro,
    /// The version of the distro being requested, currently only Ubuntu 22.04 is supported
    #[clap(long, short)]
    version: Option<String>,
    /// The amount of memory in MB being requested
    #[clap(long, short)]
    memory: u64,
    /// The number of vCPUs being requested
    #[clap(long, short='c')]
    vcpu_count: u8,
    /// The name of the VM instance, aka hostname, must be unique
    #[clap(long, short)]
    name: Option<String>,
    /// The path to the cloud-init user-data, must be a properly formatted
    /// yaml file, will be encoded into base64 format.
    #[clap(long, short)]
    user_data: Option<String>,
    /// The path to the cloud-init meta-data file, must be a properly formatted
    /// yaml file, will be encoded into base64 format.
    #[clap(long, short='t')]
    meta_data: Option<String>,
    /// A 12 or 24 word BIP39 compatible Mnemonic Phrase to derive a keypair
    /// from for signing.
    #[clap(long)]
    mnemonic: Option<String>,
    /// An Ethereum compatible ECDSA private key used for signing
    #[clap(long, short)]
    private_key: Option<String>,
    /// The path to an Ethereum compatible keyfile used for signing 
    #[clap(long, short)]
    keyfile: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let opts = Cli::parse();

    match opts.command {
        FormCommand::Create(create_vm) => {
            let vmm_request: CreateVmRequest = create_vm.clone().try_into()?;
            let client = reqwest::Client::new();
            client.post(&format!("{}/vm", create_vm.endpoint))
                .json(&vmm_request).send().await?;
        }
        _ => {}
    }
    
    Ok(())
}

impl TryFrom<&CreateVm> for CreateVmRequest {
    type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

    fn try_from(value: &CreateVm) -> Result<Self, Self::Error> {
        let _sk = if let Some(_phrase) = &value.mnemonic {
            // Convert mnemonic to SigningKey
        } else if let Some(_pk) = &value.private_key {
            // Convert string to SigningKey
        } else {
            // Get the keyfile
        };

        let name = if let Some(n) = &value.name {
            n.to_string()
        } else {
            format!(
                "{}_{}",
                random_word::gen(random_word::Lang::En),
                random_word::gen(random_word::Lang::En)
            ) 
        };

        Ok(CreateVmRequest {
            distro: value.distro.to_string(),
            version: value.version.clone().unwrap_or_else(|| "22.04".to_string()),
            memory_mb: value.memory,
            vcpu_count: value.vcpu_count,
            name,
            user_data: value.user_data.clone(),
            meta_data: value.meta_data.clone(),
            signature: None,
            recovery_id: 0
        })
    }
}

impl TryFrom<CreateVm> for CreateVmRequest {
    type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

    fn try_from(value: CreateVm) -> Result<Self, Self::Error> {
        let _sk = if let Some(_phrase) = &value.mnemonic {
            // Convert mnemonic to SigningKey
        } else if let Some(_pk) = &value.private_key {
            // Convert string to SigningKey
        } else {
            // Get the keyfile
        };

        let name = if let Some(n) = &value.name {
            n.to_string()
        } else {
            format!(
                "{}_{}",
                random_word::gen(random_word::Lang::En),
                random_word::gen(random_word::Lang::En)
            ) 
        };

        Ok(CreateVmRequest {
            distro: value.distro.to_string(),
            version: value.version.clone().unwrap_or_else(|| "22.04".to_string()),
            memory_mb: value.memory,
            vcpu_count: value.vcpu_count,
            name,
            user_data: value.user_data.clone(),
            meta_data: value.meta_data.clone(),
            signature: None,
            recovery_id: 0
        })
    }
}
