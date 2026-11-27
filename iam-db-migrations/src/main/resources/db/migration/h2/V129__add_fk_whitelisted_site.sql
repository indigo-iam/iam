-- Remove orphaned consent exemptions
DELETE FROM whitelisted_site
WHERE NOT EXISTS (
    SELECT 1
    FROM client_details
    WHERE client_details.client_id = whitelisted_site.client_id
);

-- Remove orphaned scopes
DELETE FROM whitelisted_site_scope
WHERE NOT EXISTS (
    SELECT 1
    FROM whitelisted_site
    WHERE whitelisted_site.id = whitelisted_site_scope.owner_id
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