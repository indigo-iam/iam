-- Remove orphaned consent exemptions
DELETE FROM whitelisted_site
WHERE client_id NOT IN (
    SELECT client_id
    FROM client_details
);

-- Remove orphaned scopes
DELETE FROM whitelisted_site_scope
WHERE owner_id NOT IN (
    SELECT id
    FROM whitelisted_site
);

-- Add foreign key from consent exemption to client
ALTER TABLE whitelisted_site
    ADD CONSTRAINT fk_whitelisted_site_client
    FOREIGN KEY (client_id)
    REFERENCES client_details (client_id)
    ON DELETE CASCADE;

-- Add foreign key from scopes to consent exemption
ALTER TABLE whitelisted_site_scope
    ADD CONSTRAINT fk_whitelisted_site_scope_owner
    FOREIGN KEY (owner_id)
    REFERENCES whitelisted_site (id)
    ON DELETE CASCADE;