pub fn generate_default_runcmds() -> Vec<String> {
    let mut cmds = vec![];
    cmds.push("sudo netplan apply".to_string());
    cmds.push("sudo innernet install /etc/formnet/invite.toml".to_string());
    cmds
}
