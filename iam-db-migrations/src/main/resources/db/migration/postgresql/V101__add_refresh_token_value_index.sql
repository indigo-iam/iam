-- Unique on the first 767 chars, as the MySQL prefix index
CREATE UNIQUE INDEX rt_tvh_idx ON refresh_token (left(token_value, 767));
-- hash index for lookups by token value
CREATE INDEX rt_tv_idx ON refresh_token USING hash (token_value);
