CREATE TABLE iam_reg_request_labels 
    (NAME VARCHAR(64) NOT NULL, PREFIX VARCHAR(256), val VARCHAR(64), request_id BIGINT);
    
CREATE INDEX INDEX_iam_reg_request_labels_prefix_name_val 
    ON iam_reg_request_labels (prefix, name, val);
    
CREATE INDEX INDEX_iam_reg_request_labels_prefix_name 
    ON iam_reg_request_labels (prefix, name);
    
ALTER TABLE iam_reg_request_labels 
    ADD CONSTRAINT FK_iam_reg_request_labels_request_id 
    FOREIGN KEY (request_id) REFERENCES iam_reg_request (ID);