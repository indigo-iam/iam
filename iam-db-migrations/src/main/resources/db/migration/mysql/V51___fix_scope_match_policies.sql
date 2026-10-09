-- Delete unused profile scopes
delete from system_scope where scope = 'urn:indigo-iam.github.io:jwt-profile#wlcg-1.0';
delete from system_scope where scope = 'urn:indigo-iam.github.io:jwt-profile#iam';