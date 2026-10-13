CREATE INDEX ia_ct_idx ON iam_account(creationtime);
CREATE INDEX ia_lut_idx ON iam_account(lastupdatetime);
CREATE INDEX ia_llt_idx ON iam_account(last_login_time);
CREATE INDEX iui_em_idx ON iam_user_info(email);
CREATE INDEX iui_gn_fn_idx ON iam_user_info(givenname, familyname);