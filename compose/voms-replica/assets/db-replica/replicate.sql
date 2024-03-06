STOP REPLICA;
CHANGE REPLICATION SOURCE TO 
  SOURCE_HOST='db-primary.test.example',
  SOURCE_USER='replicator',
  SOURCE_PASSWORD='pwd',
  SOURCE_SSL=1,
  SOURCE_SSL_CA = '/certs/ca-cert.pem',
  SOURCE_SSL_CERT = '/certs/client-cert.pem',
  SOURCE_SSL_KEY = '/certs/client-key.pem',
  SOURCE_SSL_VERIFY_SERVER_CERT=1;
START REPLICA;