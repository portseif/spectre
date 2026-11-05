//! Password-hash storage inventory for authorized administrators.
//!
//! Classifies each supplied hash by storage scheme and parameters, flags
//! legacy, fast, or unsalted schemes, and produces remediation advice. It
//! never attempts to recover plaintext and keeps no hash values: the result
//! contains aggregate counts only.
//!
//! Accepted line formats: a bare hash, `identifier:hash`, `identifier<TAB>hash`,
//! `/etc/shadow` entries, and pwdump (`user:rid:LM:NT:::`).

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashScheme {
    Argon2id,
    Argon2i,
    Argon2d,
    Yescrypt,
    Scrypt,
    Bcrypt,
    Pbkdf2Sha512,
    Pbkdf2Sha256,
    Pbkdf2Sha1,
    Sha512Crypt,
    Sha256Crypt,
    DrupalSha512,
    Phpass,
    SaltedSha,
    DjangoSaltedSha1,
    Md5Crypt,
    DesCrypt,
    MySql41,
    Ntlm,
    LanManager,
    UnsaltedSha512,
    UnsaltedSha384,
    UnsaltedSha256,
    UnsaltedSha224,
    UnsaltedSha1,
    UnsaltedMd5OrNtlm,
    LdapUnsalted,
    Unrecognized,
}

impl HashScheme {
    pub fn label(self) -> &'static str {
        match self {
            Self::Argon2id => "Argon2id",
            Self::Argon2i => "Argon2i",
            Self::Argon2d => "Argon2d",
            Self::Yescrypt => "yescrypt",
            Self::Scrypt => "scrypt",
            Self::Bcrypt => "bcrypt",
            Self::Pbkdf2Sha512 => "PBKDF2-HMAC-SHA512",
            Self::Pbkdf2Sha256 => "PBKDF2-HMAC-SHA256",
            Self::Pbkdf2Sha1 => "PBKDF2-HMAC-SHA1",
            Self::Sha512Crypt => "sha512crypt ($6$)",
            Self::Sha256Crypt => "sha256crypt ($5$)",
            Self::DrupalSha512 => "Drupal 7 ($S$)",
            Self::Phpass => "phpass ($P$/$H$)",
            Self::SaltedSha => "Salted SHA (LDAP {SSHA})",
            Self::DjangoSaltedSha1 => "Django salted SHA-1/MD5",
            Self::Md5Crypt => "md5crypt ($1$/$apr1$)",
            Self::DesCrypt => "Traditional DES crypt",
            Self::MySql41 => "MySQL 4.1+ (double SHA-1)",
            Self::Ntlm => "NTLM",
            Self::LanManager => "LAN Manager (LM)",
            Self::UnsaltedSha512 => "Unsalted SHA-512",
            Self::UnsaltedSha384 => "Unsalted SHA-384",
            Self::UnsaltedSha256 => "Unsalted SHA-256",
            Self::UnsaltedSha224 => "Unsalted SHA-224",
            Self::UnsaltedSha1 => "Unsalted SHA-1",
            Self::UnsaltedMd5OrNtlm => "Unsalted MD5 or NTLM (32 hex)",
            Self::LdapUnsalted => "Unsalted LDAP {SHA}/{MD5}",
            Self::Unrecognized => "Unrecognized",
        }
    }

    pub fn salted(self) -> Option<bool> {
        match self {
            Self::MySql41
            | Self::Ntlm
            | Self::LanManager
            | Self::UnsaltedSha512
            | Self::UnsaltedSha384
            | Self::UnsaltedSha256
            | Self::UnsaltedSha224
            | Self::UnsaltedSha1
            | Self::UnsaltedMd5OrNtlm
            | Self::LdapUnsalted => Some(false),
            Self::Unrecognized => None,
            _ => Some(true),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashStrength {
    Critical,
    Weak,
    Acceptable,
    Strong,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Classification {
    scheme: HashScheme,
    strength: HashStrength,
    parameter: Option<String>,
}

fn classified(scheme: HashScheme, strength: HashStrength, parameter: Option<String>) -> Classification {
    Classification { scheme, strength, parameter }
}

fn is_hex(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn crypt_alphabet(text: &str) -> bool {
    text.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'/')
}

fn argon2_parameters(hash: &str) -> (Option<u64>, Option<u64>) {
    let mut memory = None;
    let mut iterations = None;
    for part in hash.split('$').flat_map(|segment| segment.split(',')) {
        if let Some(value) = part.strip_prefix("m=") {
            memory = value.parse().ok();
        } else if let Some(value) = part.strip_prefix("t=") {
            iterations = value.parse().ok();
        }
    }
    (memory, iterations)
}

/// Classify a single hash string. Thresholds follow the OWASP Password
/// Storage Cheat Sheet (Argon2id m >= 19 MiB and t >= 2; bcrypt cost >= 10;
/// PBKDF2 at least 600k iterations for SHA-256, 210k for SHA-512, 1.3M for SHA-1).
fn classify(hash: &str) -> Classification {
    use HashScheme::*;
    use HashStrength::*;

    if let Some(rest) = hash.strip_prefix("{CRYPT}").or_else(|| hash.strip_prefix("{crypt}")) {
        return classify(rest);
    }
    if hash.starts_with("$argon2") {
        let scheme = if hash.starts_with("$argon2id$") {
            Argon2id
        } else if hash.starts_with("$argon2i$") {
            Argon2i
        } else {
            Argon2d
        };
        let (memory, iterations) = argon2_parameters(hash);
        let strength = match (scheme, memory, iterations) {
            (_, Some(memory), _) if memory < 15 * 1024 => Weak,
            (Argon2id, Some(memory), Some(iterations)) if memory >= 19 * 1024 && iterations >= 2 => Strong,
            (Argon2id, Some(memory), Some(_)) if memory >= 46 * 1024 => Strong,
            _ => Acceptable,
        };
        return classified(scheme, strength, memory.zip(iterations).map(|(memory, iterations)| format!("m={memory}KiB t={iterations}")));
    }
    if hash.starts_with("$y$") {
        return classified(Yescrypt, Strong, None);
    }
    if hash.starts_with("$scrypt$") || hash.starts_with("$7$") {
        return classified(Scrypt, Strong, None);
    }
    for prefix in ["$2a$", "$2b$", "$2y$", "$2x$"] {
        if let Some(rest) = hash.strip_prefix(prefix) {
            let cost: Option<u32> = rest.get(..2).and_then(|digits| digits.parse().ok());
            let strength = match cost {
                Some(cost) if cost >= 12 => Strong,
                Some(cost) if cost >= 10 => Acceptable,
                Some(_) => Weak,
                None => Unknown,
            };
            return classified(Bcrypt, strength, cost.map(|cost| format!("cost {cost}")));
        }
    }
    // PBKDF2: passlib ($pbkdf2-sha256$ITER$...) and Django (pbkdf2_sha256$ITER$...).
    for (prefixes, scheme, minimum) in [
        (["$pbkdf2-sha512$", "pbkdf2_sha512$"], Pbkdf2Sha512, 210_000u64),
        (["$pbkdf2-sha256$", "pbkdf2_sha256$"], Pbkdf2Sha256, 600_000),
        (["$pbkdf2$", "pbkdf2_sha1$"], Pbkdf2Sha1, 1_300_000),
    ] {
        if let Some(rest) = prefixes.iter().find_map(|prefix| hash.strip_prefix(prefix)) {
            let iterations: Option<u64> = rest.split('$').next().and_then(|value| value.parse().ok());
            let strength = match iterations {
                Some(count) if count >= minimum => Acceptable,
                Some(_) => Weak,
                None => Unknown,
            };
            return classified(scheme, strength, iterations.map(|count| format!("{count} iterations")));
        }
    }
    if hash.starts_with("$6$") {
        return classified(
            Sha512Crypt,
            Weak,
            hash.split('$').find_map(|part| part.strip_prefix("rounds=")).map(|rounds| format!("rounds={rounds}")),
        );
    }
    if hash.starts_with("$5$") {
        return classified(Sha256Crypt, Weak, None);
    }
    if hash.starts_with("$S$") {
        return classified(DrupalSha512, Weak, None);
    }
    if hash.starts_with("$P$") || hash.starts_with("$H$") {
        return classified(Phpass, Weak, None);
    }
    if hash.starts_with("$1$") || hash.starts_with("$apr1$") {
        return classified(Md5Crypt, Critical, None);
    }
    let upper_prefix = hash.get(..hash.find('}').map_or(0, |index| index + 1)).unwrap_or_default().to_ascii_uppercase();
    match upper_prefix.as_str() {
        "{SSHA}" | "{SSHA256}" | "{SSHA512}" | "{SMD5}" => return classified(SaltedSha, Weak, None),
        "{SHA}" | "{MD5}" | "{SHA256}" | "{SHA512}" => return classified(LdapUnsalted, Critical, None),
        _ => {}
    }
    if hash.starts_with("sha1$") || hash.starts_with("md5$") {
        return classified(DjangoSaltedSha1, Weak, None);
    }
    if let Some(rest) = hash.strip_prefix('*')
        && rest.len() == 40
        && is_hex(rest)
    {
        return classified(MySql41, Critical, None);
    }
    if is_hex(hash) {
        return match hash.len() {
            32 => classified(UnsaltedMd5OrNtlm, Critical, None),
            40 => classified(UnsaltedSha1, Critical, None),
            56 => classified(UnsaltedSha224, Critical, None),
            64 => classified(UnsaltedSha256, Critical, None),
            96 => classified(UnsaltedSha384, Critical, None),
            128 => classified(UnsaltedSha512, Critical, None),
            _ => classified(Unrecognized, Unknown, None),
        };
    }
    if hash.len() == 13 && crypt_alphabet(hash) {
        return classified(DesCrypt, Critical, None);
    }
    classified(Unrecognized, Unknown, None)
}

/// Placeholder LM hash for an empty password (LM disabled).
const EMPTY_LM: &str = "aad3b435b51404eeaad3b435b51404ee";

/// Split one input line into zero or more hash fields.
fn hashes_in_line(line: &str) -> Vec<(&str, Option<HashScheme>)> {
    let fields: Vec<&str> = line.split(':').collect();
    // pwdump: user:rid:LM:NT:::
    if fields.len() >= 4
        && fields[1].bytes().all(|byte| byte.is_ascii_digit())
        && fields[2].len() == 32
        && fields[3].len() == 32
        && is_hex(fields[2])
        && is_hex(fields[3])
    {
        let mut hashes = vec![(fields[3], Some(HashScheme::Ntlm))];
        if !fields[2].eq_ignore_ascii_case(EMPTY_LM) {
            hashes.push((fields[2], Some(HashScheme::LanManager)));
        }
        return hashes;
    }
    // /etc/shadow: user:hash:lastchg:...
    if fields.len() >= 8 {
        return vec![(fields[1], None)];
    }
    if let Some((_, hash)) = line.split_once('\t') {
        return vec![(hash.trim(), None)];
    }
    // identifier:hash, unless the colon belongs to the hash itself.
    if fields.len() == 2 && !line.starts_with('$') && !line.starts_with('{') {
        return vec![(fields[1].trim(), None)];
    }
    vec![(line, None)]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemeSummary {
    pub scheme: HashScheme,
    pub label: String,
    pub count: u64,
    pub salted: Option<bool>,
    pub strength: HashStrength,
    /// Parameter distribution, e.g. `{"cost 10": 4}`.
    pub parameters: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashInventory {
    pub lines_read: u64,
    pub hashes_analyzed: u64,
    /// Locked or passwordless shadow entries (`!`, `*`, empty).
    pub accounts_without_password: u64,
    pub schemes: Vec<SchemeSummary>,
    /// Hashes whose exact value appears more than once. For unsalted schemes
    /// this reveals accounts sharing a password; for salted ones, salt reuse.
    pub duplicate_values: u64,
    pub unsalted_count: u64,
    pub overall: HashStrength,
    pub recommendations: Vec<String>,
}

/// Inventory hash storage schemes in administrator-supplied text.
pub fn inventory(input: &str) -> HashInventory {
    let mut lines_read = 0;
    let mut without_password = 0;
    let mut summaries: BTreeMap<(HashScheme, HashStrength), SchemeSummary> = BTreeMap::new();
    let mut occurrences: HashMap<&str, u32> = HashMap::new();

    for line in input.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')) {
        lines_read += 1;
        for (hash, forced_scheme) in hashes_in_line(line) {
            if hash.is_empty() || hash.starts_with('!') || hash == "*" || hash == "x" {
                without_password += 1;
                continue;
            }
            let classification = match forced_scheme {
                Some(HashScheme::LanManager) => classified(HashScheme::LanManager, HashStrength::Critical, None),
                Some(scheme) => classified(scheme, HashStrength::Critical, None),
                None => classify(hash),
            };
            *occurrences.entry(hash).or_insert(0) += 1;
            let summary = summaries.entry((classification.scheme, classification.strength)).or_insert_with(|| SchemeSummary {
                scheme: classification.scheme,
                label: classification.scheme.label().to_string(),
                count: 0,
                salted: classification.scheme.salted(),
                strength: classification.strength,
                parameters: BTreeMap::new(),
            });
            summary.count += 1;
            if let Some(parameter) = classification.parameter {
                *summary.parameters.entry(parameter).or_insert(0) += 1;
            }
        }
    }

    let schemes: Vec<SchemeSummary> = summaries.into_values().collect();
    let hashes_analyzed = schemes.iter().map(|summary| summary.count).sum();
    let duplicate_values = occurrences.values().filter(|count| **count > 1).count() as u64;
    let unsalted_count = schemes.iter().filter(|summary| summary.salted == Some(false)).map(|summary| summary.count).sum();
    let overall = schemes
        .iter()
        .filter(|summary| summary.strength != HashStrength::Unknown)
        .map(|summary| summary.strength)
        .min()
        .unwrap_or(HashStrength::Unknown);

    let mut recommendations = Vec::new();
    let present = |predicate: &dyn Fn(&SchemeSummary) -> bool| schemes.iter().any(predicate);
    if present(&|summary| summary.salted == Some(false)) {
        recommendations.push("Unsalted hashes found: identical passwords produce identical hashes and precomputed tables apply. Migrate to Argon2id (or scrypt/bcrypt) by rehashing at next login, wrapping legacy hashes in the new KDF until then.".to_string());
    }
    if present(&|summary| matches!(summary.scheme, HashScheme::LanManager)) {
        recommendations
            .push("LAN Manager hashes are present: disable LM hash storage (NoLMHash policy) and force password changes.".to_string());
    }
    if present(&|summary| matches!(summary.scheme, HashScheme::Ntlm)) {
        recommendations
            .push("NTLM hashes are unsalted MD4: enforce long passphrases, restrict NTLM, and monitor for pass-the-hash.".to_string());
    }
    if present(&|summary| summary.strength == HashStrength::Critical && summary.salted == Some(true)) {
        recommendations
            .push("Obsolete crypt schemes (DES crypt, md5crypt) are trivially fast to attack; rehash with a modern KDF.".to_string());
    }
    if present(&|summary| summary.strength == HashStrength::Weak) {
        recommendations.push("Fast or under-parameterized salted schemes found (SHA-crypt, phpass, salted SHA, low-cost bcrypt/PBKDF2). Increase work factors to OWASP minimums or migrate to Argon2id.".to_string());
    }
    if duplicate_values > 0 {
        recommendations.push(format!("{duplicate_values} hash value(s) occur more than once: shared passwords (unsalted schemes) or reused salts. Investigate and force resets for affected accounts."));
    }
    if schemes.len() > 1 {
        recommendations
            .push("Multiple storage schemes are in use; track migration progress until a single modern scheme remains.".to_string());
    }
    if recommendations.is_empty() && hashes_analyzed > 0 {
        recommendations
            .push("Storage schemes meet current OWASP guidance. Re-evaluate parameters periodically as hardware improves.".to_string());
    }

    HashInventory {
        lines_read,
        hashes_analyzed,
        accounts_without_password: without_password,
        schemes,
        duplicate_values,
        unsalted_count,
        overall,
        recommendations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_schemes() {
        let cases = [
            ("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g", HashScheme::Argon2id, HashStrength::Strong),
            ("$argon2id$v=19$m=4096,t=3,p=1$c2FsdA$aGFzaA", HashScheme::Argon2id, HashStrength::Weak),
            ("$2b$12$KIXQJm0p0yQxQ1Lw7VbKQe2z0Yp0u5vD9n9H1l3uQ1mJ1qJ1qJ1qG", HashScheme::Bcrypt, HashStrength::Strong),
            ("$2y$08$KIXQJm0p0yQxQ1Lw7VbKQe2z0Yp0u5vD9n9H1l3uQ1mJ1qJ1qJ1qG", HashScheme::Bcrypt, HashStrength::Weak),
            ("pbkdf2_sha256$870000$c2FsdA$aGFzaA==", HashScheme::Pbkdf2Sha256, HashStrength::Acceptable),
            ("pbkdf2_sha256$36000$c2FsdA$aGFzaA==", HashScheme::Pbkdf2Sha256, HashStrength::Weak),
            ("$6$rounds=5000$saltsalt$hash", HashScheme::Sha512Crypt, HashStrength::Weak),
            ("$1$saltsalt$hashhashhashhashhash", HashScheme::Md5Crypt, HashStrength::Critical),
            ("$P$B12345678abcdefghijklmnopqrstu", HashScheme::Phpass, HashStrength::Weak),
            ("{SSHA}c2FsdGVkaGFzaA==", HashScheme::SaltedSha, HashStrength::Weak),
            ("{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", HashScheme::LdapUnsalted, HashStrength::Critical),
            ("*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19", HashScheme::MySql41, HashStrength::Critical),
            ("5f4dcc3b5aa765d61d8327deb882cf99", HashScheme::UnsaltedMd5OrNtlm, HashStrength::Critical),
            ("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", HashScheme::UnsaltedSha1, HashStrength::Critical),
            ("abJnggxhB/yWI", HashScheme::DesCrypt, HashStrength::Critical),
            ("$y$j9T$salt$hash", HashScheme::Yescrypt, HashStrength::Strong),
            ("not a hash at all", HashScheme::Unrecognized, HashStrength::Unknown),
        ];
        for (hash, scheme, strength) in cases {
            let result = classify(hash);
            assert_eq!((result.scheme, result.strength), (scheme, strength), "{hash}");
        }
    }

    #[test]
    fn parses_line_formats_and_aggregates() {
        let input = "\
# comment
alice:$2b$12$KIXQJm0p0yQxQ1Lw7VbKQe2z0Yp0u5vD9n9H1l3uQ1mJ1qJ1qJ1qG
bob\t5f4dcc3b5aa765d61d8327deb882cf99
carol:5f4dcc3b5aa765d61d8327deb882cf99
root:$6$rounds=5000$saltsalt$hash:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
legacy:501:e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c:::
";
        let report = inventory(input);
        assert_eq!(report.lines_read, 7);
        assert_eq!(report.accounts_without_password, 1);
        assert_eq!(report.hashes_analyzed, 7);
        assert_eq!(report.duplicate_values, 1, "bob and carol share an unsalted hash");
        assert_eq!(report.overall, HashStrength::Critical);
        assert!(report.schemes.iter().any(|summary| summary.scheme == HashScheme::LanManager && summary.count == 1));
        assert!(report.schemes.iter().any(|summary| summary.scheme == HashScheme::Ntlm && summary.count == 2));
        assert!(report.recommendations.iter().any(|text| text.contains("Unsalted")));
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("5f4dcc3b"), "reports must not contain hash values");
    }

    #[test]
    fn modern_only_inventory_is_strong() {
        let report = inventory("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA\n$argon2id$v=19$m=65536,t=3,p=4$c2FsdDI$aGFzaDI\n");
        assert_eq!(report.overall, HashStrength::Strong);
        assert_eq!(report.unsalted_count, 0);
        assert_eq!(report.schemes[0].parameters.get("m=65536KiB t=3"), Some(&2));
    }
}
