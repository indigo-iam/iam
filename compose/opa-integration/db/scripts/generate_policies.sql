DELIMITER //

CREATE PROCEDURE generate_test_policies(
    IN p_count INT,
    IN p_account_id BIGINT
)
BEGIN
    DECLARE i INT DEFAULT 0;
    DECLARE v_policy_id BIGINT;
    DECLARE v_uuid VARCHAR(36);

    START TRANSACTION;

    WHILE i < p_count DO

        SET v_uuid = UUID();

        -- Insert policy
        INSERT INTO iam_scope_policy (
            creation_time,
            description,
            last_update_time,
            rule,
            account_id,
            group_id,
            matching_policy
        )
        VALUES (
            NOW(),
            'Test storage restriction',
            NOW(),
            'PERMIT',
            p_account_id,
            NULL,
            'PATH'
        );

        SET v_policy_id = LAST_INSERT_ID();

        -- Insert associated scopes
        INSERT INTO iam_scope_policy_scope (policy_id, scope)
        VALUES
            (v_policy_id, CONCAT('storage.read:/', v_uuid)),
            (v_policy_id, CONCAT('storage.write:/', v_uuid)),
            (v_policy_id, CONCAT('storage.modify:/', v_uuid));

        SET i = i + 1;

    END WHILE;

    COMMIT;
END //

DELIMITER ;