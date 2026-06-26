CREATE TABLE IF NOT EXISTS iam_federated_client (
	id BIGINT AUTO_INCREMENT PRIMARY KEY,
	
	client_id VARCHAR(256),
	client_secret TEXT,
	
	client_name VARCHAR(256),
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
    owner_id VARCHAR(256),
    redirect_uri VARCHAR(2048)
);

CREATE TABLE IF NOT EXISTS iam_federated_client_grant_type (
    owner_id VARCHAR(256),
    grant_type VARCHAR(2000)
);

CREATE TABLE IF NOT EXISTS iam_federated_client_response_type (
    owner_id VARCHAR(256),
    response_type VARCHAR(2000)
);

CREATE TABLE IF NOT EXISTS iam_federated_client_scope (
    owner_id VARCHAR(256),
    scope VARCHAR(2048)
);