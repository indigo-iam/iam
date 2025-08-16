CREATE TABLE IF NOT EXISTS iam_issued_at
(
    hvalue   CHAR(64)   NOT NULL,
    expiration   TIMESTAMP   NOT NULL,
    client_id   BIGINT   NOT NULL,
    CONSTRAINT iam_issued_at_PK PRIMARY KEY (hvalue),
    CONSTRAINT client_details_client_id_FK FOREIGN KEY (client_id) REFERENCES client_details (id) ON DELETE CASCADE

);