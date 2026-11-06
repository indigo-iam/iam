-- PostgreSQL string comparisons are already case sensitive: nothing to do here
-- (on MySQL this migration switches subject_dn and issuer_dn to a case sensitive collation)
SELECT 1;
