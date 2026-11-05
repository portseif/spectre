//! Password security auditing, kept separate from discovery.
//!
//! * [`pwned_passwords`] — Workflow A: check a password the user voluntarily
//!   supplies, using the Pwned Passwords k-anonymity range API. Only the first
//!   five hex characters of the SHA-1 hash leave the device.
//! * [`hash_inventory`] — Workflow B (initial scope): inventory the storage
//!   schemes of password hashes an authorized administrator supplies and flag
//!   legacy or unsalted storage. No cracking, no plaintext recovery.
//! * [`offline`] — the isolated interface reserved for a future, separately
//!   authorized offline auditing backend. No implementation ships.

pub mod hash_inventory;
pub mod offline;
pub mod pwned_passwords;

pub use hash_inventory::{HashInventory, HashScheme, HashStrength, SchemeSummary, inventory};
pub use pwned_passwords::{PWNED_PASSWORDS_HOST, PasswordCheckResult, PwnedPasswordsClient};
