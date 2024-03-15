STOP REPLICA;
CHANGE REPLICATION SOURCE TO 
  SOURCE_HOST='db-primary.test.example',
  SOURCE_USER='replicator',
  SOURCE_PASSWORD='pwd',
  SOURCE_SSL=1,
  SOURCE_SSL_CA = '/etc/grid-security/certificates/igi-test-ca.pem',
  SOURCE_SSL_VERIFY_SERVER_CERT=1;
START REPLICA;