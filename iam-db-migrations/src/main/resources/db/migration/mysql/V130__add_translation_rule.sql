CREATE TABLE translation_rule (
    id BIGINT NOT NULL AUTO_INCREMENT,
    issuer VARCHAR(512),
    resource_server_id VARCHAR(250),
    operation VARCHAR(32) NOT NULL,
    rule_config TEXT NOT NULL,
    execution_order INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,

    PRIMARY KEY (id),

    INDEX idx_translation_rule_scope_order (
        issuer,
        resource_server_id,
        execution_order,
        id
    )
);