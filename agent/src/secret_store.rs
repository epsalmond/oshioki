//! Key material that must not sit in the identity file.
//!
//! On macOS the box secret lives in the login keychain under the
//! `dev.oshioki.agent` service and the identity file keeps only the account
//! name that finds it. Anywhere else the file keeps carrying the secret
//! itself: a second 0600 file next to the first buys nothing.

use std::{collections::HashMap, sync::Mutex};

use anyhow::{Context as _, Result, bail};

/// Storage for fixed-size secrets, keyed by account name.
///
/// The box secret is the only entry: one per identity file, so callers pass
/// the file's `box_secret_ref` as the account.
pub trait SecretStore {
    /// Creates or replaces the entry.
    fn put(&self, account: &str, secret: &[u8; 32]) -> Result<()>;

    /// Returns the entry, or `None` when no entry exists under the account.
    /// A present entry that is not 32 bytes is corruption, not absence.
    fn get(&self, account: &str) -> Result<Option<[u8; 32]>>;

    /// Removes the entry. Missing entries are not an error.
    fn remove(&self, account: &str) -> Result<()>;
}

/// In-memory store. Tests use it so no test run touches a real keychain.
#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: Mutex<HashMap<String, [u8; 32]>>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for MemoryStore {
    fn put(&self, account: &str, secret: &[u8; 32]) -> Result<()> {
        self.inner
            .lock()
            .map_err(|_| anyhow::anyhow!("memory store lock poisoned"))?
            .insert(account.to_owned(), *secret);
        Ok(())
    }

    fn get(&self, account: &str) -> Result<Option<[u8; 32]>> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("memory store lock poisoned"))?
            .get(account)
            .copied())
    }

    fn remove(&self, account: &str) -> Result<()> {
        self.inner
            .lock()
            .map_err(|_| anyhow::anyhow!("memory store lock poisoned"))?
            .remove(account);
        Ok(())
    }
}

/// The login-keychain store. Only built on macOS.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct KeychainStore {
    service: &'static str,
}

#[cfg(target_os = "macos")]
impl KeychainStore {
    /// The store the shipped agent uses.
    pub fn oshioki() -> Self {
        Self {
            service: KEYCHAIN_SERVICE,
        }
    }

    /// A store under another service, for the opt-in live-keychain test.
    pub fn under(service: &'static str) -> Self {
        Self { service }
    }

    fn missing(error: security_framework::base::Error) -> bool {
        // errSecItemNotFound. Compared by value so the crate does not need
        // the -sys bindings as a direct dependency.
        error.code() == ERR_SEC_ITEM_NOT_FOUND
    }
}

#[cfg(target_os = "macos")]
impl SecretStore for KeychainStore {
    fn put(&self, account: &str, secret: &[u8; 32]) -> Result<()> {
        security_framework::passwords::set_generic_password(self.service, account, secret)
            .with_context(|| format!("store secret {account} in the login keychain"))
    }

    fn get(&self, account: &str) -> Result<Option<[u8; 32]>> {
        match security_framework::passwords::get_generic_password(self.service, account) {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    bail!(
                        "keychain entry {account} holds {} bytes, not a 32-byte secret",
                        bytes.len()
                    );
                }
                let mut secret = [0_u8; 32];
                secret.copy_from_slice(&bytes);
                Ok(Some(secret))
            }
            Err(error) if Self::missing(error) => Ok(None),
            Err(error) => {
                Err(error).with_context(|| format!("read secret {account} from the login keychain"))
            }
        }
    }

    fn remove(&self, account: &str) -> Result<()> {
        match security_framework::passwords::delete_generic_password(self.service, account) {
            Ok(()) => Ok(()),
            Err(error) if Self::missing(error) => Ok(()),
            Err(error) => Err(error)
                .with_context(|| format!("remove secret {account} from the login keychain")),
        }
    }
}

/// Service name for the shipped agent's keychain entries.
#[cfg(target_os = "macos")]
pub const KEYCHAIN_SERVICE: &str = "dev.oshioki.agent";

/// Apple Security result code for a search that matched nothing.
#[cfg(target_os = "macos")]
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_memory_store_round_trips_and_forgets() {
        let store = MemoryStore::new();
        assert_eq!(store.get("box").unwrap(), None);
        store.remove("box").unwrap();
        store.put("box", &[11; 32]).unwrap();
        assert_eq!(store.get("box").unwrap(), Some([11; 32]));
        store.put("box", &[12; 32]).unwrap();
        assert_eq!(store.get("box").unwrap(), Some([12; 32]));
        store.remove("box").unwrap();
        assert_eq!(store.get("box").unwrap(), None);
    }

    /// Touches the real login keychain, so it stays off unless asked: run
    /// with `OSHIOKI_TEST_KEYCHAIN=1`. Uses a random account under a test
    /// service and deletes it afterwards.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_keychain_store_round_trips() {
        if std::env::var_os("OSHIOKI_TEST_KEYCHAIN").is_none() {
            return;
        }
        let store = KeychainStore::under("dev.oshioki.agent-test");
        let account = format!("test-{}", uuidish());
        assert_eq!(store.get(&account).unwrap(), None);
        store.put(&account, &[21; 32]).unwrap();
        assert_eq!(store.get(&account).unwrap(), Some([21; 32]));
        store.remove(&account).unwrap();
        assert_eq!(store.get(&account).unwrap(), None);
    }

    #[cfg(target_os = "macos")]
    fn uuidish() -> String {
        use rand::RngCore as _;
        let mut bytes = [0_u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        oshioki_protocol::encode_base64url(&bytes)
    }
}
