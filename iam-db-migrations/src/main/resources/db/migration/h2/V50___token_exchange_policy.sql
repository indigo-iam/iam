CREATE TABLE iam_exchange_policy 
    (
        ID BIGINT IDENTITY NOT NULL, 
        creation_time TIMESTAMP NOT NULL, 
        description VARCHAR(512), 
        last_update_time TIMESTAMP NOT NULL, 
        rule VARCHAR(6) NOT NULL, 
        dest_m_param VARCHAR(256), 
        dest_m_type VARCHAR(8) NOT NULL, 
        origin_m_param VARCHAR(256), 
        origin_m_type VARCHAR(8) NOT NULL, 
        PRIMARY KEY (ID)
    );

   
CREATE TABLE iam_exchange_scope_policies (
    param VARCHAR(256), 
    rule VARCHAR(6) NOT NULL, 
    type VARCHAR(6) NOT NULL, 
    exchange_policy_id BIGINT
);

ALTER TABLE iam_exchange_scope_policies 
    ADD CONSTRAINT FK_iam_exchange_scope_policies_exchange_policy_id 
    FOREIGN KEY (exchange_policy_id) 
    REFERENCES iam_exchange_policy (ID);

INSERT INTO iam_exchange_policy(description, creation_time, last_update_time, rule, origin_m_type, dest_m_type)
    VALUES
    ('Allow all exchanges',
    CURRENT_TIMESTAMP(),
    CURRENT_TIMESTAMP(),
    'PERMIT',
    'ANY',
    'ANY');