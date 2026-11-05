-- Domain ownership checks by DNS TXT challenge were removed. Addresses that
-- were only verified through their domain go back to unverified, and the
-- domains table, which existed only for those checks, is dropped.
UPDATE email_addresses
SET verification_status = 'unverified',
    verification_method = NULL,
    verified_at = NULL,
    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE verification_method IN ('verified_domain', 'dns_txt_challenge')
   OR verification_status = 'ownership_pending';

DROP TABLE domains;
