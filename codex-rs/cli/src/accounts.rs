use clap::Parser;
use codex_common::CliConfigOverrides;
use codex_core::auth::AuthCredentialsStoreMode;
use codex_core::auth::CLIENT_ID;
use codex_core::auth::login_with_api_key;
use codex_core::auth::pool::AccountPool;
use codex_core::auth::pool::RotateReason;
use codex_core::config::Config;
use codex_login::ServerOptions;
use codex_login::run_device_code_login;
use codex_login::run_login_server;
use codex_protocol::config_types::ForcedLoginMethod;
use owo_colors::OwoColorize;
use std::io::IsTerminal;
use std::io::Read;
use std::path::PathBuf;

#[derive(Debug, Parser)]
pub(crate) struct AccountsCli {
    #[clap(skip)]
    pub(crate) config_overrides: CliConfigOverrides,

    #[command(subcommand)]
    cmd: AccountsSubcommand,
}

#[derive(Debug, clap::Subcommand)]
enum AccountsSubcommand {
    /// List all configured profiles in the local account pool.
    List,

    /// Add or update a profile (stores credentials under CODEX_HOME/account-pool/profiles/<name>/auth.json).
    Add(AddArgs),

    /// Set the active profile (copies credentials into the primary auth store for this CODEX_HOME).
    Use(UseArgs),

    /// Rotate to the next enabled profile in pool order.
    Rotate,

    /// Remove a profile from the pool (optionally deleting stored credentials).
    Remove(RemoveArgs),

    /// Clear usage-limit disabled flags (for one profile or all).
    ClearDisabled(ClearDisabledArgs),
}

#[derive(Debug, Parser)]
struct AddArgs {
    /// Profile name (A-Z, a-z, 0-9, '-', '_').
    name: String,

    /// Use the device code login flow (helpful on remote/headless machines).
    #[arg(long = "device-auth", conflicts_with = "with_api_key")]
    device_auth: bool,

    /// Store an API key profile (read key from stdin).
    #[arg(long = "with-api-key", conflicts_with = "device_auth")]
    with_api_key: bool,

    /// Do not switch the active account after adding/updating this profile.
    #[arg(long = "no-set-active")]
    no_set_active: bool,

    /// Overwrite existing stored credentials for this profile.
    #[arg(long = "overwrite")]
    overwrite: bool,
}

#[derive(Debug, Parser)]
struct UseArgs {
    /// Profile name to activate.
    name: String,
}

#[derive(Debug, Parser)]
struct RemoveArgs {
    /// Profile name to remove.
    name: String,

    /// Keep stored credentials on disk (only removes from pool.json).
    #[arg(long = "keep-files")]
    keep_files: bool,
}

#[derive(Debug, Parser)]
struct ClearDisabledArgs {
    /// Profile name to clear. If omitted, clears all profiles.
    name: Option<String>,
}

impl AccountsCli {
    pub(crate) async fn run(self) -> anyhow::Result<()> {
        let config = load_config(self.config_overrides).await?;
        let pool = AccountPool::new(config.codex_home.clone());

        match self.cmd {
            AccountsSubcommand::List => {
                let (active, profiles) = pool.list_profiles()?;
                if profiles.is_empty() {
                    println!("No profiles in the account pool.");
                    return Ok(());
                }
                println!("Active: {}", active.as_deref().unwrap_or("<none>").cyan());
                for p in profiles {
                    let mut line = format!("- {}", p.name);
                    if active.as_deref() == Some(p.name.as_str()) {
                        line.push_str(" (active)");
                    }
                    if let Some(until) = p.disabled_until {
                        line.push_str(&format!(" (disabled until {})", until.to_rfc3339()));
                    }
                    if let Some(mode) = p.mode {
                        line.push_str(&format!(" [{mode:?}]"));
                    }
                    if let Some(account_id) = p.account_id {
                        line.push_str(&format!(" account_id={account_id}"));
                    }
                    println!("{line}");
                }
                Ok(())
            }
            AccountsSubcommand::Add(args) => {
                if matches!(config.forced_login_method, Some(ForcedLoginMethod::Api))
                    && !args.with_api_key
                {
                    anyhow::bail!(
                        "ChatGPT login is disabled in this workspace; add an API key profile instead."
                    );
                }
                if matches!(config.forced_login_method, Some(ForcedLoginMethod::Chatgpt))
                    && args.with_api_key
                {
                    anyhow::bail!(
                        "API key login is disabled in this workspace; add a ChatGPT profile instead."
                    );
                }

                let profile_home = pool.profile_codex_home(&args.name)?;
                if !args.overwrite && has_stored_credentials(&profile_home)? {
                    anyhow::bail!(
                        "Profile '{}' already has stored credentials. Re-run with --overwrite to replace them.",
                        args.name
                    );
                }

                if args.with_api_key {
                    let api_key = read_api_key_from_stdin()?;
                    login_with_api_key(&profile_home, &api_key, AuthCredentialsStoreMode::File)?;
                } else if args.device_auth {
                    let mut opts = ServerOptions::new(
                        profile_home.clone(),
                        CLIENT_ID.to_string(),
                        config.forced_chatgpt_workspace_id.clone(),
                        AuthCredentialsStoreMode::File,
                    );
                    opts.open_browser = false;
                    run_device_code_login(opts).await?;
                } else {
                    let opts = ServerOptions::new(
                        profile_home.clone(),
                        CLIENT_ID.to_string(),
                        config.forced_chatgpt_workspace_id.clone(),
                        AuthCredentialsStoreMode::File,
                    );
                    let server = run_login_server(opts)?;
                    eprintln!(
                        "Starting local login server on http://localhost:{}.\nIf your browser did not open, navigate to this URL to authenticate:\n\n{}",
                        server.actual_port, server.auth_url
                    );
                    server.block_until_done().await?;
                }

                pool.upsert_profile(&args.name, !args.no_set_active)?;
                if !args.no_set_active {
                    pool.set_active_profile(&args.name, config.cli_auth_credentials_store_mode)?;
                }

                eprintln!("Saved profile '{}'.", args.name);
                Ok(())
            }
            AccountsSubcommand::Use(args) => {
                pool.set_active_profile(&args.name, config.cli_auth_credentials_store_mode)?;
                eprintln!("Active profile set to '{}'.", args.name);
                Ok(())
            }
            AccountsSubcommand::Rotate => {
                let rotated = pool.rotate_next(
                    config.cli_auth_credentials_store_mode,
                    RotateReason::Manual,
                    None,
                )?;
                if let Some(rotation) = rotated {
                    eprintln!("Rotated account {} → {}.", rotation.from, rotation.to);
                } else {
                    eprintln!(
                        "No rotation performed (pool not configured, only one profile, or all profiles are disabled)."
                    );
                }
                Ok(())
            }
            AccountsSubcommand::Remove(args) => {
                pool.remove_profile(&args.name, !args.keep_files)?;
                eprintln!("Removed profile '{}'.", args.name);
                Ok(())
            }
            AccountsSubcommand::ClearDisabled(args) => {
                pool.clear_disabled(args.name.as_deref())?;
                eprintln!("Cleared disabled flags.");
                Ok(())
            }
        }
    }
}

async fn load_config(cli_config_overrides: CliConfigOverrides) -> anyhow::Result<Config> {
    let cli_overrides = cli_config_overrides
        .parse_overrides()
        .map_err(anyhow::Error::msg)?;
    Ok(Config::load_with_cli_overrides(cli_overrides).await?)
}

fn has_stored_credentials(profile_home: &PathBuf) -> std::io::Result<bool> {
    Ok(profile_home.join("auth.json").is_file())
}

fn read_api_key_from_stdin() -> anyhow::Result<String> {
    let mut stdin = std::io::stdin();

    if stdin.is_terminal() {
        anyhow::bail!(
            "--with-api-key expects the API key on stdin. Try piping it, e.g. `printenv OPENAI_API_KEY | codex accounts add mykey --with-api-key`."
        );
    }

    eprintln!("Reading API key from stdin...");

    let mut buffer = String::new();
    stdin.read_to_string(&mut buffer)?;

    let api_key = buffer.trim().to_string();
    if api_key.is_empty() {
        anyhow::bail!("No API key provided via stdin.");
    }

    Ok(api_key)
}
