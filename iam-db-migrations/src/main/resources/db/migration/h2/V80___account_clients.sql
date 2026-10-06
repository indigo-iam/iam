-- account clients table
CREATE TABLE iam_account_client (id IDENTITY NOT NULL, creation_time TIMESTAMP NOT NULL, account_id BIGINT NOT NULL, client_id BIGINT NOT NULL, PRIMARY KEY (id));
ALTER TABLE iam_account_client ADD CONSTRAINT UNQ_iam_account_client_0 UNIQUE (account_id, client_id);
ALTER TABLE iam_account_client ADD CONSTRAINT FK_iam_account_client_client_id FOREIGN KEY (client_id) REFERENCES client_details (id);
ALTER TABLE iam_account_client ADD CONSTRAINT FK_iam_account_client_account_id FOREIGN KEY (account_id) REFERENCES iam_account (ID);