--
-- Flyway callback, run after each migration.
--
-- Unlike MySQL AUTO_INCREMENT, PostgreSQL identity sequences do not advance when rows are
-- inserted with explicit ids (as the initial and test data migrations do). Move each sequence
-- past the max id of its table, so that ids generated afterwards do not collide.
-- Sequences are only moved forward.
--
DO $$
DECLARE
  r RECORD;
  max_id BIGINT;
BEGIN
  FOR r IN
    SELECT c.table_name, c.column_name,
      pg_get_serial_sequence(format('%I.%I', c.table_schema, c.table_name), c.column_name) AS seq
    FROM information_schema.columns c
    WHERE c.table_schema = current_schema()
      AND (c.is_identity = 'YES' OR c.column_default LIKE 'nextval(%')
  LOOP
    EXECUTE format('SELECT MAX(%I) FROM %I', r.column_name, r.table_name) INTO max_id;
    IF max_id IS NOT NULL AND max_id > COALESCE(pg_sequence_last_value(r.seq::regclass), 0) THEN
      PERFORM setval(r.seq, max_id);
    END IF;
  END LOOP;
END $$;
