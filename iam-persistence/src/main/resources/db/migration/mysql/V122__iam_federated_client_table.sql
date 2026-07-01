CREATE TABLE IF NOT EXISTS iam_federated_client (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	
	client_id VARCHAR(256) NOT NULL,
	client_secret TEXT,
	
	client_name VARCHAR(256) NOT NULL,
	token_endpoint_auth_method VARCHAR(256),

	jwks_uri TEXT,
	jwks TEXT,
	
	created_at TIMESTAMP NULL,
	active TINYINT(1),
	
	expiration TIMESTAMP NOT NULL,
    entity_id VARCHAR(512) NOT NULL,
	
	UNIQUE (entity_id)
);

CREATE TABLE IF NOT EXISTS iam_federated_client_redirect_uri (
    owner_id BIGINT NOT NULL,
    redirect_uri VARCHAR(2048) NOT NULL,
    CONSTRAINT pk_iam_federated_client_redirect_uri PRIMARY KEY (owner_id, redirect_uri),
    CONSTRAINT fk_iam_federated_client_redirect_uri FOREIGN KEY (owner_id) REFERENCES iam_federated_client (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS iam_federated_client_grant_type (
    owner_id BIGINT NOT NULL,
    grant_type VARCHAR(2000) NOT NULL,
    CONSTRAINT pk_iam_federated_client_grant_type PRIMARY KEY (owner_id, grant_type),
    CONSTRAINT fk_iam_federated_client_grant_type FOREIGN KEY (owner_id) REFERENCES iam_federated_client (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS iam_federated_client_response_type (
    owner_id BIGINT NOT NULL,
    response_type VARCHAR(2000) NOT NULL,
    CONSTRAINT pk_iam_federated_client_response_type PRIMARY KEY (owner_id, response_type),
    CONSTRAINT fk_iam_federated_client_response_type FOREIGN KEY (owner_id) REFERENCES iam_federated_client (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS iam_federated_client_scope (
    owner_id BIGINT NOT NULL,
    scope VARCHAR(2048) NOT NULL,
    CONSTRAINT pk_iam_federated_client_scope PRIMARY KEY (owner_id, scope),
    CONSTRAINT fk_iam_federated_client_scope FOREIGN KEY (owner_id) REFERENCES iam_federated_client (id) ON DELETE CASCADE
);