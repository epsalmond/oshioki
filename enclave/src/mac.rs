//! `Security.framework` and `LocalAuthentication` bindings.
//!
//! The workspace denies `unsafe_code`; this module is the one place that lifts
//! it, because every call here is a raw framework call. Each `unsafe` block
//! names the invariant it relies on.
//!
//! The design comes from the issue #9 spike:
//!
//! * The key is created ephemeral (no `kSecAttrIsPermanent`), so no keychain
//!   and no provisioned entitlement are involved. A bare CLI cannot reach the
//!   Data Protection keychain.
//! * Persistence is the enclave-encrypted key blob, the `"toid"` attribute of
//!   the created key. It is what `CryptoKit` calls `dataRepresentation`. Only the
//!   enclave that minted it can use it, and the access control is baked in.
//! * Reconstruction passes the blob twice: as the key data, and under the
//!   undocumented `"toid"` attribute. Without the attribute
//!   `SecKeyCreateWithData` silently mints a fresh, ungated key instead of
//!   failing, so every reconstruction is checked against the known public key.

#![allow(unsafe_code)]

use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result, anyhow, bail};
use core_foundation::base::{CFType, TCFType as _};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::CFError;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::error::CFErrorRef;
use objc2::rc::Retained;
use objc2_foundation::NSString;
use objc2_local_authentication::LAContext;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
};
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecUseAuthenticationContext,
};
use security_framework_sys::key::SecKeyCreateWithData;

/// The attribute holding the enclave-encrypted key blob, `kSecAttrTokenOID`.
/// Undocumented, and load-bearing in both directions: it is where the blob is
/// read from, and where it must be supplied again to reattach the key.
const TOKEN_OID: &str = "toid";

/// The label the enclave key carries. Cosmetic; the key is never in a keychain.
const LABEL: &str = "oshioki agent approval key";

/// `CGSSessionCopyCurrentDictionary` reports the screen lock under this key.
const SCREEN_IS_LOCKED: &str = "CGSSessionScreenIsLocked";

/// `errSecUserCanceled`, the status the Security framework reports when the
/// Touch ID sheet is dismissed.
const ERR_SEC_USER_CANCELED: isize = -128;

/// Why a signature did not happen.
#[derive(Debug)]
pub enum SignError {
    /// The sheet was dismissed, or nobody answered it. The enclave reports the
    /// same error either way, so the caller decides which of the two it was
    /// from its own deadline and lock state.
    Canceled,
    /// Anything else: a re-enrolled fingerprint invalidates the key, and a
    /// reconstruction that does not match the known public key is refused.
    Failed(anyhow::Error),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canceled => write!(formatter, "the Touch ID sheet was dismissed"),
            Self::Failed(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for SignError {}

/// A P-256 key living in this Mac's Secure Enclave, behind Touch ID.
///
/// The struct itself holds no key material: the blob is enclave-encrypted and
/// useless on any other machine, and the public key is public. Cloning the
/// canceller is how another task dismisses an in-flight sheet.
pub struct EnclaveSigner {
    blob: Vec<u8>,
    public_key_sec1: Vec<u8>,
    canceller: PromptCanceller,
}

impl EnclaveSigner {
    /// Creates a key in the enclave. No Touch ID sheet appears: the access
    /// control is checked when the key is used, not when it is made.
    pub fn create() -> Result<Self> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
            // Biometry as enrolled right now, and only for signing. Adding or
            // removing a fingerprint invalidates the key permanently.
            kSecAccessControlBiometryCurrentSet | kSecAccessControlPrivateKeyUsage,
        )
        .map_err(|error| anyhow!("SecAccessControlCreateWithFlags failed: {error}"))?;
        let mut options = GenerateKeyOptions::default();
        // No `set_location`: the key stays ephemeral, so no keychain write and
        // no entitlement. The blob below is the only copy that survives.
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_label(LABEL)
            .set_access_control(access);
        let key = SecKey::new(&options)
            .map_err(|error| anyhow!("SecKeyCreateRandomKey failed: {error}"))?;
        let blob = key_blob(&key)?;
        let public_key_sec1 = public_key_sec1(&key)?;
        Ok(Self {
            blob,
            public_key_sec1,
            canceller: PromptCanceller::default(),
        })
    }

    /// Reattaches a stored blob and reads back its public key. No sheet: only
    /// signing needs biometry.
    pub fn from_blob(blob: Vec<u8>) -> Result<Self> {
        let (key, _context) = key_from_blob(&blob, "use the oshioki approval key")?;
        let public_key_sec1 = public_key_sec1(&key)?;
        Ok(Self {
            blob,
            public_key_sec1,
            canceller: PromptCanceller::default(),
        })
    }

    /// The blob to persist. Enclave-encrypted, bound to this Mac.
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// The 65-byte SEC1 uncompressed public point.
    pub fn public_key_sec1(&self) -> &[u8] {
        &self.public_key_sec1
    }

    /// A handle another task uses to dismiss the sheet this signer is showing.
    pub fn canceller(&self) -> PromptCanceller {
        self.canceller.clone()
    }

    /// Signs `message` after Touch ID, and returns a DER ECDSA signature.
    ///
    /// The sheet reads "Oshioki is trying to `<reason>`. Touch ID to allow
    /// this." This blocks for the whole interaction, so callers run it off the
    /// async runtime.
    pub fn sign_der(&self, message: &[u8], reason: &str) -> Result<Vec<u8>, SignError> {
        let (key, context) = key_from_blob(&self.blob, reason).map_err(SignError::Failed)?;
        // A reconstruction that ignored the blob would be a fresh, ungated key
        // whose signatures verify against nothing the host pinned. Refuse.
        let public_key_sec1 = public_key_sec1(&key).map_err(SignError::Failed)?;
        if public_key_sec1 != self.public_key_sec1 {
            return Err(SignError::Failed(anyhow!(
                "the reconstructed enclave key is not the paired one"
            )));
        }
        self.canceller.arm(context);
        let signed = key.create_signature(Algorithm::ECDSASignatureMessageX962SHA256, message);
        self.canceller.disarm();
        signed.map_err(|error| {
            if is_cancellation(&error) {
                SignError::Canceled
            } else {
                SignError::Failed(anyhow!("SecKeyCreateSignature failed: {error}"))
            }
        })
    }

    /// Whether the enclave refuses to hand out the private key, which it always
    /// should. Exists so a test can assert it on real hardware.
    pub fn export_is_refused(&self) -> Result<bool> {
        let (key, _context) = key_from_blob(&self.blob, "use the oshioki approval key")?;
        Ok(key.external_representation().is_none())
    }
}

/// Dismisses whatever Touch ID sheet the signer is showing.
///
/// The deadline lives on the async side and the sheet on a blocking thread, so
/// the timer needs a way in. A cancellation that arrives before the sheet is up
/// is remembered and applied as soon as it is.
///
/// Every cancellation names the attempt it belongs to. A deadline timer cannot
/// be stopped once it has entered its last few instructions, so a timer for a
/// request that was just answered can still fire. Without the number that
/// cancellation would land on the next request and tear down a sheet nobody
/// had seen yet, which the agent would then publish as a denial.
#[derive(Clone, Default)]
pub struct PromptCanceller(Arc<Mutex<CancelState>>);

#[derive(Default)]
struct CancelState {
    attempt: u64,
    context: Option<ContextHandle>,
    cancelled: bool,
}

/// An `LAContext` that may be invalidated from another thread.
struct ContextHandle(Retained<LAContext>);

// SAFETY: LAContext is a plain Objective-C object with no main-thread
// requirement, and the only message sent from another thread is `invalidate`,
// which Apple documents as the way to stop an evaluation already in flight.
// The handle is kept behind a mutex, so no two threads touch it at once.
unsafe impl Send for ContextHandle {}

impl PromptCanceller {
    /// Starts an attempt and returns its number, which is what a later
    /// [`Self::cancel`] has to name. Whatever an earlier attempt left behind
    /// is dropped here.
    pub fn begin(&self) -> u64 {
        let mut state = self.lock();
        state.attempt = state.attempt.wrapping_add(1);
        state.context = None;
        state.cancelled = false;
        state.attempt
    }

    /// Dismisses `attempt`'s sheet now, or as soon as it appears. A number
    /// that is not the current attempt is a timer that fired too late, and it
    /// does nothing.
    pub fn cancel(&self, attempt: u64) {
        let mut state = self.lock();
        if state.attempt != attempt {
            return;
        }
        state.cancelled = true;
        if let Some(handle) = state.context.as_ref() {
            // SAFETY: the handle owns a live retained LAContext.
            unsafe { handle.0.invalidate() };
        }
    }

    fn arm(&self, context: Retained<LAContext>) {
        let mut state = self.lock();
        if state.cancelled {
            // SAFETY: the context was just created and is still retained here.
            unsafe { context.invalidate() };
        }
        state.context = Some(ContextHandle(context));
    }

    fn disarm(&self) {
        self.lock().context = None;
    }

    /// A poisoned lock would mean a panic while holding it; the state is three
    /// fields and none is left half-written, so recovering is correct.
    fn lock(&self) -> std::sync::MutexGuard<'_, CancelState> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Whether the login session's screen is locked.
///
/// Returns true when there is no window session at all, since nothing could
/// show a sheet then either.
pub fn screen_is_locked() -> bool {
    // SAFETY: CGSessionCopyCurrentDictionary takes no arguments and returns a
    // dictionary the caller owns, or NULL outside a window session.
    let session = unsafe { CGSessionCopyCurrentDictionary() };
    if session.is_null() {
        return true;
    }
    // SAFETY: the "Copy" in the name is the create rule; the reference is ours.
    let session: CFDictionary = unsafe { CFDictionary::wrap_under_create_rule(session) };
    let (keys, values) = session.get_keys_and_values();
    for (key, value) in keys.iter().zip(values.iter()) {
        // SAFETY: session dictionary keys are CFStrings, borrowed not owned.
        let name = unsafe { CFString::wrap_under_get_rule((*key).cast()) };
        if name == CFString::from_static_string(SCREEN_IS_LOCKED) {
            // SAFETY: the value is borrowed from the dictionary we still hold.
            let value = unsafe { CFType::wrap_under_get_rule((*value).cast()) };
            return is_true(&value);
        }
    }
    false
}

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
}

/// Reads a session dictionary flag, which macOS has spelled both ways.
fn is_true(value: &CFType) -> bool {
    if let Some(boolean) = value.downcast::<CFBoolean>() {
        return bool::from(boolean);
    }
    value
        .downcast::<CFNumber>()
        .and_then(|number| number.to_i64())
        .is_some_and(|number| number != 0)
}

/// The enclave-encrypted key blob from a live key's attributes.
fn key_blob(key: &SecKey) -> Result<Vec<u8>> {
    let attributes = key.attributes();
    let (keys, values) = attributes.get_keys_and_values();
    for (name, value) in keys.iter().zip(values.iter()) {
        // SAFETY: key attribute names are CFStrings owned by the dictionary.
        let name = unsafe { CFString::wrap_under_get_rule((*name).cast()) };
        if name == CFString::from_static_string(TOKEN_OID) {
            // SAFETY: the "toid" value is CFData owned by the same dictionary.
            let data = unsafe { CFData::wrap_under_get_rule((*value).cast()) };
            return Ok(data.to_vec());
        }
    }
    bail!("the new key has no '{TOKEN_OID}' blob, so nothing could be persisted")
}

/// The 65-byte SEC1 uncompressed public point of an enclave key.
fn public_key_sec1(key: &SecKey) -> Result<Vec<u8>> {
    let public = key
        .public_key()
        .context("SecKeyCopyPublicKey returned no public key")?;
    let sec1 = public
        .external_representation()
        .context("the public key has no external representation")?;
    Ok(sec1.to_vec())
}

/// Rebuilds a usable `SecKey` from a stored blob, with an `LAContext` carrying
/// the reason the sheet will show. The context is returned so the caller can
/// invalidate it at a deadline.
fn key_from_blob(blob: &[u8], reason: &str) -> Result<(SecKey, Retained<LAContext>)> {
    // SAFETY: -[LAContext new] and -setLocalizedReason: take no unusual
    // arguments and have no thread affinity.
    let context = unsafe {
        let context = LAContext::new();
        context.setLocalizedReason(&NSString::from_str(reason));
        context
    };
    let context_pointer: *const LAContext = &raw const *context;

    // SAFETY: every constant here is a framework CFString the process does not
    // own, so the get rule applies. The LAContext pointer is an Objective-C
    // object, which CFDictionary retains like any other CFType, and the
    // `context` binding keeps it alive for the whole call.
    let pairs: Vec<(CFString, CFType)> = unsafe {
        vec![
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFType::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom.cast()),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyClass),
                CFType::wrap_under_get_rule(kSecAttrKeyClassPrivate.cast()),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrTokenID),
                CFType::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave.cast()),
            ),
            (
                CFString::wrap_under_get_rule(kSecUseAuthenticationContext),
                CFType::wrap_under_get_rule(context_pointer.cast()),
            ),
            (
                CFString::from_static_string(TOKEN_OID),
                CFData::from_buffer(blob).into_CFType(),
            ),
        ]
    };
    let attributes = CFDictionary::from_CFType_pairs(&pairs);
    let data = CFData::from_buffer(blob);
    let mut error: CFErrorRef = std::ptr::null_mut();
    // SAFETY: both dictionary and data outlive the call, and `error` is only
    // read when the call returns NULL, which is when it is written.
    let key = unsafe {
        SecKeyCreateWithData(
            data.as_concrete_TypeRef(),
            attributes.as_concrete_TypeRef(),
            &raw mut error,
        )
    };
    if key.is_null() {
        // SAFETY: a NULL return means the framework wrote an error we own.
        let error = unsafe { CFError::wrap_under_create_rule(error) };
        bail!("SecKeyCreateWithData failed: {error}");
    }
    // SAFETY: SecKeyCreateWithData follows the create rule.
    Ok((unsafe { SecKey::wrap_under_create_rule(key) }, context))
}

/// Whether a signing error is a dismissed sheet rather than a broken key.
///
/// The enclave reports the same condition for a sheet the user dismissed, a
/// sheet nobody was there to answer, and a context invalidated from another
/// thread. Telling those apart is the caller's job.
fn is_cancellation(error: &CFError) -> bool {
    error.code() == ERR_SEC_USER_CANCELED
        || error
            .description()
            .to_string()
            .to_ascii_lowercase()
            .contains("cancel")
}

#[cfg(test)]
mod tests {
    use super::{EnclaveSigner, screen_is_locked};

    /// Creation, blob round-trip, and export refusal, none of which shows a
    /// sheet. Skipped where there is no enclave to talk to.
    #[test]
    fn a_blob_reattaches_to_the_same_non_exportable_key() {
        let Ok(signer) = EnclaveSigner::create() else {
            eprintln!("skipping: this machine has no usable Secure Enclave");
            return;
        };
        assert!(!signer.blob().is_empty());
        assert_eq!(signer.public_key_sec1().len(), 65);
        assert_eq!(signer.public_key_sec1()[0], 0x04);
        let reloaded = EnclaveSigner::from_blob(signer.blob().to_vec()).unwrap();
        assert_eq!(reloaded.public_key_sec1(), signer.public_key_sec1());
        assert!(signer.export_is_refused().unwrap());
        assert!(reloaded.export_is_refused().unwrap());
    }

    /// A blob that is not one of ours must not turn into a working key.
    #[test]
    fn a_corrupt_blob_is_refused() {
        assert!(EnclaveSigner::from_blob(vec![0; 569]).is_err());
    }

    /// A timer that fires just after its own attempt ended must not reach the
    /// next one. This needs no enclave, only the bookkeeping.
    #[test]
    fn a_late_cancellation_does_not_carry_into_the_next_attempt() {
        let canceller = super::PromptCanceller::default();
        let first = canceller.begin();
        canceller.cancel(first);
        assert!(canceller.0.lock().unwrap().cancelled);
        let second = canceller.begin();
        assert_ne!(first, second);
        assert!(!canceller.0.lock().unwrap().cancelled);
        canceller.cancel(first);
        assert!(
            !canceller.0.lock().unwrap().cancelled,
            "a cancellation named the attempt that is already over"
        );
        canceller.cancel(second);
        assert!(canceller.0.lock().unwrap().cancelled);
    }

    /// Reading the lock state must not panic or hang, whatever the session is.
    #[test]
    fn the_lock_state_is_readable() {
        let _ = screen_is_locked();
    }
}
