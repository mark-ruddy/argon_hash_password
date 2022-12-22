//! Functions for creating hashed passwords with salt using argon2
//! ### Create a hashed password with salt
//! ```
//! let (hash, salt) = argon_hash_password::create_hash_and_salt("PlaintextPassword").unwrap();
//! ```
//! The hash and salt can then be stored
//!
//! ### Check a Hash
//! ```ignore
//! let check = argon_hash_password::check_password_matches_hash("PlaintextPassword", hash, salt).unwrap();
//! match check {
//!     true => println!("Correct plaintext password provided"),
//!     false => println!("Incorrect plaintext password provided"),
//! }
//! ```

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::{distributions::Alphanumeric, Rng};
use std::error::Error;

/// Given a plaintext password return a password hash and a generated salt
pub fn create_hash_and_salt(password: &str) -> Result<(String, String), Box<dyn Error>> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = match hash_and_verify(password, salt.clone()) {
        Ok(hash) => hash,
        Err(e) => return Err(e),
    };
    Ok((hash, salt.to_string()))
}

/// Check that password and salt matches generated hash
pub fn check_password_matches_hash(
    password: &str,
    expected_hash: &str,
    salt: &str,
) -> Result<bool, Box<dyn Error>> {
    let parsed_salt = match SaltString::new(salt) {
        Ok(parsed_salt) => parsed_salt,
        Err(e) => return Err(format!("Failed to parse provided salt: {}", e).into()),
    };
    let hash = match hash_and_verify(password, parsed_salt) {
        Ok(hash) => hash,
        Err(e) => return Err(e),
    };
    if hash != expected_hash {
        return Ok(false);
    }
    Ok(true)
}

/// Verify that the password matches a certain length and the confirmation password provided
pub fn verify_password_len(password: &str) -> bool {
    if password.len() < 8 {
        return false;
    }
    if password.len() > 128 {
        return false;
    }
    true
}

/// Generate a secure 128-bit session ID of alphanumeric characters
pub fn gen_session_id() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(128)
        .map(char::from)
        .collect()
}

/// Given a plaintext password and a SaltString, return the hash of the password
fn hash_and_verify(password: &str, salt: SaltString) -> Result<String, Box<dyn Error>> {
    let argon2 = Argon2::default();
    let hash = match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => return Err(format!("Failed to hash password: {}", e).into()),
    };

    let parsed_hash = match PasswordHash::new(&hash) {
        Ok(parsed_hash) => parsed_hash,
        Err(e) => return Err(format!("Failed parse hash: {}", e).into()),
    };
    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => (),
        Err(e) => {
            return Err(format!("Failed to verify hashed password: {}", e).into());
        }
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "samplePass123";

    #[test]
    fn argon_same_password_not_matching_due_to_salt() {
        let (first_hash, first_salt) =
            create_hash_and_salt(PASSWORD).expect("Failed to create hashed password first time");
        let (second_hash, second_salt) =
            create_hash_and_salt(PASSWORD).expect("Failed to create hashed password second time");
        assert_ne!(first_hash, second_hash);
        assert_ne!(first_salt, second_salt);
    }

    #[test]
    fn argon_same_password_does_match() {
        let (hash, salt) =
            create_hash_and_salt(PASSWORD).expect("Failed to create hashed password");
        let check_hash = check_password_matches_hash(PASSWORD, &hash, &salt)
            .expect("Failed to check password hash");
        assert!(check_hash);
    }

    #[test]
    fn argon_different_password_does_not_match() {
        let (hash, salt) =
            create_hash_and_salt(PASSWORD).expect("Failed to create hashed password");
        let check_hash = check_password_matches_hash("aDifferentPassword123", &hash, &salt)
            .expect("Failed to check password hash");
        assert!(!check_hash);
    }
}
