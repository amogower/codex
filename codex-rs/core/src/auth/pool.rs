use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::path_utils::write_atomically;
use crate::token_data::TokenData;

use super::AuthCredentialsStoreMode;
use super::storage::create_auth_storage;

const POOL_DIR: &str = "account-pool";
const POOL_FILE: &str = "pool.json";
const PROFILES_DIR: &str = "profiles";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotateReason {
    Manual,
    UsageLimitReached,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    pub from: String,
    pub to: String,
    pub reason: RotateReason,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProfileStatus {
    pub name: String,
    pub disabled_until: Option<DateTime<Utc>>,
    pub mode: Option<codex_app_server_protocol::AuthMode>,
    pub account_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AccountPool {
    codex_home: PathBuf,
}

impl AccountPool {
    pub fn new(codex_home: PathBuf) -> Self {
        Self { codex_home }
    }

    pub fn is_configured(&self) -> bool {
        self.pool_file().is_file()
    }

    pub fn profile_codex_home(&self, name: &str) -> std::io::Result<PathBuf> {
        validate_profile_name(name)?;
        Ok(self.pool_dir().join(PROFILES_DIR).join(name))
    }

    pub fn list_profiles(&self) -> std::io::Result<(Option<String>, Vec<ProfileStatus>)> {
        let Some(mut pool) = self.load_pool()? else {
            return Ok((None, Vec::new()));
        };
        pool.normalize();

        let mut statuses = Vec::new();
        for name in &pool.order {
            let meta = pool.profiles.get(name).cloned().unwrap_or_default();
            let (mode, account_id) = self.profile_mode_and_account_id(name)?;
            statuses.push(ProfileStatus {
                name: name.clone(),
                disabled_until: meta.disabled_until,
                mode,
                account_id,
            });
        }

        Ok((pool.active.clone(), statuses))
    }

    pub fn upsert_profile(&self, name: &str, make_active: bool) -> std::io::Result<()> {
        validate_profile_name(name)?;

        let mut pool = self.load_pool()?.unwrap_or_default();
        pool.normalize();

        pool.profiles.entry(name.to_string()).or_default();
        if !pool.order.iter().any(|n| n == name) {
            pool.order.push(name.to_string());
        }
        if make_active || pool.active.is_none() {
            pool.active = Some(name.to_string());
        }

        self.save_pool(&pool)
    }

    pub fn remove_profile(&self, name: &str, delete_files: bool) -> std::io::Result<()> {
        validate_profile_name(name)?;

        let Some(mut pool) = self.load_pool()? else {
            return Ok(());
        };
        pool.normalize();

        pool.profiles.remove(name);
        pool.order.retain(|n| n != name);
        if pool.active.as_deref() == Some(name) {
            pool.active = pool.order.first().cloned();
        }
        self.save_pool(&pool)?;

        if delete_files {
            let dir = self.profile_codex_home(name)?;
            let _ = std::fs::remove_dir_all(dir);
        }

        Ok(())
    }

    pub fn clear_disabled(&self, name: Option<&str>) -> std::io::Result<()> {
        let Some(mut pool) = self.load_pool()? else {
            return Ok(());
        };
        pool.normalize();

        match name {
            Some(name) => {
                validate_profile_name(name)?;
                if let Some(meta) = pool.profiles.get_mut(name) {
                    meta.disabled_until = None;
                }
            }
            None => {
                for meta in pool.profiles.values_mut() {
                    meta.disabled_until = None;
                }
            }
        }

        self.save_pool(&pool)
    }

    pub fn set_active_profile(
        &self,
        name: &str,
        active_store_mode: AuthCredentialsStoreMode,
    ) -> std::io::Result<()> {
        validate_profile_name(name)?;

        let Some(mut pool) = self.load_pool()? else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Account pool is not configured (no pool.json found).",
            ));
        };
        pool.normalize();

        if !pool.profiles.contains_key(name) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Unknown profile '{name}'."),
            ));
        }

        self.copy_profile_auth_to_active_store(name, active_store_mode)?;

        pool.active = Some(name.to_string());
        if let Some(meta) = pool.profiles.get_mut(name) {
            meta.disabled_until = None;
        }
        self.save_pool(&pool)
    }

    pub fn rotate_next(
        &self,
        active_store_mode: AuthCredentialsStoreMode,
        reason: RotateReason,
        usage_limit_resets_at: Option<DateTime<Utc>>,
    ) -> std::io::Result<Option<Rotation>> {
        let Some(mut pool) = self.load_pool()? else {
            return Ok(None);
        };
        pool.normalize();

        let Some(current) = pool.active.clone() else {
            return Ok(None);
        };
        if pool.order.len() < 2 {
            return Ok(None);
        }

        let now = Utc::now();
        if reason == RotateReason::UsageLimitReached {
            let disabled_until = usage_limit_resets_at
                .filter(|t| *t > now)
                .unwrap_or_else(|| now + Duration::minutes(15));
            if let Some(meta) = pool.profiles.get_mut(&current) {
                meta.disabled_until = Some(disabled_until);
            }
        }

        let Some(next) = next_enabled_profile(&pool, &current, now) else {
            self.save_pool(&pool)?;
            return Ok(None);
        };

        self.copy_profile_auth_to_active_store(&next, active_store_mode)?;

        pool.active = Some(next.clone());
        self.save_pool(&pool)?;

        Ok(Some(Rotation {
            from: current,
            to: next,
            reason,
        }))
    }

    pub fn profile_count(&self) -> std::io::Result<usize> {
        let Some(mut pool) = self.load_pool()? else {
            return Ok(0);
        };
        pool.normalize();
        Ok(pool.order.len())
    }

    pub fn sync_active_profile_from_active_store(
        &self,
        active_store_mode: AuthCredentialsStoreMode,
    ) -> std::io::Result<()> {
        let Some(mut pool) = self.load_pool()? else {
            return Ok(());
        };
        pool.normalize();
        let Some(active_profile) = pool.active.clone() else {
            return Ok(());
        };

        let active_storage = create_auth_storage(self.codex_home.clone(), active_store_mode);
        let Some(active_auth) = active_storage.load()? else {
            return Ok(());
        };
        let Some(active_tokens) = active_auth.tokens.as_ref() else {
            return Ok(());
        };

        let profile_home = self.profile_codex_home(&active_profile)?;
        let profile_storage = create_auth_storage(profile_home, AuthCredentialsStoreMode::File);
        let Some(profile_auth) = profile_storage.load()? else {
            return Ok(());
        };
        let Some(profile_tokens) = profile_auth.tokens.as_ref() else {
            return Ok(());
        };
        if !tokens_appear_to_match(active_tokens, profile_tokens) {
            return Ok(());
        }

        profile_storage.save(&active_auth)?;
        Ok(())
    }

    fn profile_mode_and_account_id(
        &self,
        name: &str,
    ) -> std::io::Result<(Option<codex_app_server_protocol::AuthMode>, Option<String>)> {
        let profile_home = self.profile_codex_home(name)?;
        let storage = create_auth_storage(profile_home, AuthCredentialsStoreMode::File);
        let auth = storage.load()?;
        let Some(auth) = auth else {
            return Ok((None, None));
        };

        let mode = if auth.tokens.is_some() {
            Some(codex_app_server_protocol::AuthMode::ChatGPT)
        } else if auth.openai_api_key.is_some() {
            Some(codex_app_server_protocol::AuthMode::ApiKey)
        } else {
            None
        };
        let account_id = auth.tokens.and_then(|t| t.account_id);
        Ok((mode, account_id))
    }

    fn copy_profile_auth_to_active_store(
        &self,
        name: &str,
        active_store_mode: AuthCredentialsStoreMode,
    ) -> std::io::Result<()> {
        let profile_home = self.profile_codex_home(name)?;
        let profile_storage = create_auth_storage(profile_home, AuthCredentialsStoreMode::File);
        let auth_dot_json = profile_storage.load()?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Profile '{name}' has no stored credentials."),
            )
        })?;

        let active_storage = create_auth_storage(self.codex_home.clone(), active_store_mode);
        active_storage.save(&auth_dot_json)?;
        Ok(())
    }

    fn load_pool(&self) -> std::io::Result<Option<PoolFileV1>> {
        let path = self.pool_file();
        let contents = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let mut pool: PoolFileV1 = serde_json::from_str(&contents)?;
        pool.normalize();
        Ok(Some(pool))
    }

    fn save_pool(&self, pool: &PoolFileV1) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(pool)?;
        write_atomically(&self.pool_file(), &json)
    }

    fn pool_dir(&self) -> PathBuf {
        self.codex_home.join(POOL_DIR)
    }

    fn pool_file(&self) -> PathBuf {
        self.pool_dir().join(POOL_FILE)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PoolFileV1 {
    #[serde(default = "pool_version")]
    version: u32,
    #[serde(default)]
    active: Option<String>,
    #[serde(default)]
    order: Vec<String>,
    #[serde(default)]
    profiles: HashMap<String, ProfileMetaV1>,
}

fn pool_version() -> u32 {
    1
}

impl PoolFileV1 {
    fn normalize(&mut self) {
        if self.version == 0 {
            self.version = pool_version();
        }

        // Ensure order lists every known profile at least once.
        let mut seen = std::collections::HashSet::new();
        let mut normalized = Vec::new();
        for n in self.order.iter().cloned() {
            if seen.insert(n.clone()) && self.profiles.contains_key(&n) {
                normalized.push(n);
            }
        }
        for n in self.profiles.keys() {
            if seen.insert(n.clone()) {
                normalized.push(n.clone());
            }
        }
        self.order = normalized;

        // Ensure active is valid.
        if let Some(active) = &self.active {
            if !self.profiles.contains_key(active) {
                self.active = self.order.first().cloned();
            }
        } else {
            self.active = self.order.first().cloned();
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ProfileMetaV1 {
    #[serde(default)]
    disabled_until: Option<DateTime<Utc>>,
}

fn next_enabled_profile(pool: &PoolFileV1, current: &str, now: DateTime<Utc>) -> Option<String> {
    let idx = pool.order.iter().position(|n| n == current)?;
    if pool.order.len() < 2 {
        return None;
    }

    for offset in 1..pool.order.len() {
        let name = pool.order[(idx + offset) % pool.order.len()].clone();
        let disabled_until = pool.profiles.get(&name).and_then(|m| m.disabled_until);
        if disabled_until.is_some_and(|t| t > now) {
            continue;
        }
        return Some(name);
    }
    None
}

fn tokens_appear_to_match(active: &TokenData, profile: &TokenData) -> bool {
    if let (Some(active), Some(profile)) =
        (active.account_id.as_deref(), profile.account_id.as_deref())
    {
        return active == profile;
    }

    if let (Some(active), Some(profile)) = (
        active.id_token.chatgpt_user_id.as_deref(),
        profile.id_token.chatgpt_user_id.as_deref(),
    ) {
        return active == profile;
    }

    if let (Some(active), Some(profile)) = (
        active.id_token.chatgpt_account_id.as_deref(),
        profile.id_token.chatgpt_account_id.as_deref(),
    ) {
        return active == profile;
    }

    if let (Some(active), Some(profile)) = (
        active.id_token.email.as_deref(),
        profile.id_token.email.as_deref(),
    ) {
        return active == profile;
    }

    false
}

fn validate_profile_name(name: &str) -> std::io::Result<()> {
    if name.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Profile name must not be empty.",
        ));
    }

    let ok = name.chars().all(|c| match c {
        'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => true,
        _ => false,
    });
    if ok {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid profile name '{name}'. Allowed characters: A-Z, a-z, 0-9, '-', '_'."),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthDotJson;
    use crate::auth::storage::get_auth_file;
    use crate::token_data::IdTokenInfo;
    use crate::token_data::TokenData;
    use base64::Engine;
    use pretty_assertions::assert_eq;
    use tempfile::tempdir;

    fn dummy_jwt() -> String {
        let header = serde_json::json!({"alg": "none", "typ": "JWT"}).to_string();
        let payload = serde_json::json!({"email": "user@example.com"}).to_string();
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        format!("{header_b64}.{payload_b64}.sig")
    }

    fn write_profile_auth(profile_home: &PathBuf, auth: &AuthDotJson) {
        std::fs::create_dir_all(profile_home).expect("mkdir");
        let json = serde_json::to_string_pretty(auth).expect("serialize");
        write_atomically(&get_auth_file(profile_home), &json).expect("write auth");
    }

    #[test]
    fn upsert_creates_pool_and_sets_active() {
        let dir = tempdir().unwrap();
        let pool = AccountPool::new(dir.path().to_path_buf());

        pool.upsert_profile("a", true).unwrap();
        let (active, profiles) = pool.list_profiles().unwrap();
        assert_eq!(active.as_deref(), Some("a"));
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "a");
    }

    #[test]
    fn rotate_skips_disabled_profiles() {
        let dir = tempdir().unwrap();
        let pool = AccountPool::new(dir.path().to_path_buf());

        pool.upsert_profile("a", true).unwrap();
        pool.upsert_profile("b", false).unwrap();
        pool.upsert_profile("c", false).unwrap();

        let auth = AuthDotJson {
            openai_api_key: Some("sk-test".to_string()),
            tokens: None,
            last_refresh: None,
        };
        write_profile_auth(&pool.profile_codex_home("a").unwrap(), &auth);
        write_profile_auth(&pool.profile_codex_home("b").unwrap(), &auth);
        write_profile_auth(&pool.profile_codex_home("c").unwrap(), &auth);

        // Disable b far in the future, rotate from a should go to c.
        let mut raw = pool.load_pool().unwrap().unwrap();
        raw.profiles.get_mut("b").unwrap().disabled_until = Some(Utc::now() + Duration::days(2));
        pool.save_pool(&raw).unwrap();

        let rotated = pool
            .rotate_next(AuthCredentialsStoreMode::File, RotateReason::Manual, None)
            .unwrap()
            .unwrap();
        assert_eq!(rotated.from, "a");
        assert_eq!(rotated.to, "c");
    }

    #[test]
    fn usage_limit_marks_current_disabled() {
        let dir = tempdir().unwrap();
        let pool = AccountPool::new(dir.path().to_path_buf());

        pool.upsert_profile("a", true).unwrap();
        pool.upsert_profile("b", false).unwrap();

        let auth = AuthDotJson {
            openai_api_key: None,
            tokens: Some(TokenData {
                id_token: IdTokenInfo {
                    raw_jwt: dummy_jwt(),
                    ..Default::default()
                },
                access_token: "at".to_string(),
                refresh_token: "rt".to_string(),
                account_id: Some("acct".to_string()),
            }),
            last_refresh: Some(Utc::now()),
        };
        write_profile_auth(&pool.profile_codex_home("a").unwrap(), &auth);
        write_profile_auth(&pool.profile_codex_home("b").unwrap(), &auth);

        let resets_at = Utc::now() + Duration::hours(6);
        pool.rotate_next(
            AuthCredentialsStoreMode::File,
            RotateReason::UsageLimitReached,
            Some(resets_at),
        )
        .unwrap();

        let raw = pool.load_pool().unwrap().unwrap();
        let until = raw.profiles.get("a").unwrap().disabled_until.unwrap();
        assert_eq!(until, resets_at);
    }

    #[test]
    fn manual_rotate_does_not_return_current_when_all_others_disabled() {
        let dir = tempdir().unwrap();
        let pool = AccountPool::new(dir.path().to_path_buf());

        pool.upsert_profile("a", true).unwrap();
        pool.upsert_profile("b", false).unwrap();

        let auth = AuthDotJson {
            openai_api_key: Some("sk-test".to_string()),
            tokens: None,
            last_refresh: None,
        };
        write_profile_auth(&pool.profile_codex_home("a").unwrap(), &auth);
        write_profile_auth(&pool.profile_codex_home("b").unwrap(), &auth);

        let mut raw = pool.load_pool().unwrap().unwrap();
        raw.profiles.get_mut("b").unwrap().disabled_until = Some(Utc::now() + Duration::days(2));
        pool.save_pool(&raw).unwrap();

        let rotated = pool
            .rotate_next(AuthCredentialsStoreMode::File, RotateReason::Manual, None)
            .unwrap();
        assert_eq!(rotated, None);

        let (active, _) = pool.list_profiles().unwrap();
        assert_eq!(active.as_deref(), Some("a"));
    }

    #[test]
    fn sync_active_profile_writes_back_refresh_even_without_account_id() {
        let dir = tempdir().unwrap();
        let pool = AccountPool::new(dir.path().to_path_buf());

        pool.upsert_profile("a", true).unwrap();

        let initial = AuthDotJson {
            openai_api_key: None,
            tokens: Some(TokenData {
                id_token: IdTokenInfo {
                    raw_jwt: dummy_jwt(),
                    ..Default::default()
                },
                access_token: "at-1".to_string(),
                refresh_token: "rt-1".to_string(),
                account_id: None,
            }),
            last_refresh: Some(Utc::now()),
        };
        write_profile_auth(&pool.profile_codex_home("a").unwrap(), &initial);

        let refreshed = AuthDotJson {
            openai_api_key: None,
            tokens: Some(TokenData {
                id_token: IdTokenInfo {
                    raw_jwt: dummy_jwt(),
                    ..Default::default()
                },
                access_token: "at-2".to_string(),
                refresh_token: "rt-2".to_string(),
                account_id: None,
            }),
            last_refresh: Some(Utc::now()),
        };
        write_profile_auth(&dir.path().to_path_buf(), &refreshed);

        pool.sync_active_profile_from_active_store(AuthCredentialsStoreMode::File)
            .unwrap();

        let profile_home = pool.profile_codex_home("a").unwrap();
        let storage = create_auth_storage(profile_home, AuthCredentialsStoreMode::File);
        let on_disk = storage.load().unwrap().unwrap();
        let active_storage =
            create_auth_storage(dir.path().to_path_buf(), AuthCredentialsStoreMode::File);
        let active_loaded = active_storage.load().unwrap().unwrap();
        assert_eq!(on_disk, active_loaded);
    }
}
