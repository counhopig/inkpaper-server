//! Password hashing for console accounts. Argon2id with default params is
//! memory-hard and resistant to GPU cracking - appropriate for the
//! personal-scale credential store here.

use anyhow::Result;
use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("password hashing failed: {e}"))?;
    Ok(hash.to_string())
}

/// Runs the memory-hard password hash outside the async executor.
pub async fn hash_password_async(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || hash_password(&password)).await?
}

/// Returns `true` when `password` matches the stored PHC hash. Always
/// performs a real verification (against the supplied hash) so username
/// probing can't be distinguished from a wrong password by timing alone.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Runs the memory-hard password verification outside the async executor.
/// A worker failure is treated like a failed verification.
pub async fn verify_password_async(password: String, stored_hash: String) -> bool {
    tokio::task::spawn_blocking(move || verify_password(&password, &stored_hash))
        .await
        .unwrap_or(false)
}

/// Username rules: 3..=32 chars, `[A-Za-z0-9_-]` only.
pub fn validate_username(username: &str) -> Result<(), &'static str> {
    let len = username.chars().count();
    if !(3..=32).contains(&len) {
        return Err("username must be 3..32 characters");
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("username may only contain letters, digits, '_' and '-'");
    }
    Ok(())
}

/// Password rules: 8..=128 characters.
pub fn validate_password(password: &str) -> Result<(), &'static str> {
    let len = password.chars().count();
    if !(8..=128).contains(&len) {
        return Err("password must be 8..128 characters");
    }
    Ok(())
}
