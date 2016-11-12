# Deployment and Administration guide

This is the INDIGO IAM deployment and administration guide.

## Requirements

### Docker

The IAM service is currently distributed as a docker image from Dockerhub, so in
order to run the service, you will need:

- Docker v. 1.11.1 or greater

If you want to use docker-compose to deploy the service, you will also need

- docker-compose v.1.7.0 or greater

### MariaDB/MySQL

The IAM service stores information in a mariadb/mysql database.

### NginX

The IAM service is designed to run as a backend Java application behind an
NGINX reverse proxy (it could run equally well behing apache, but we tested it
behind NGINX).

## Configuration

### Prerequisites

In order to run a production instance of the IAM, you will need:

- An X.509 certificate, used for SSL termination at the NGINX reverse proxy
- A JSON keystore holding the keys used to sign JSON Web Tokens. You can use
  [this handy tool][jwk-generator] to generate JSON web keys for your service

If you enable SAML login:

- SAML metadata for your SAML federation
- SAML metadata for the IAM service


#### MySQL configuration

Just create a database and a user that has read/write/schema change access to the database.

#### NGINX configuration
Configure NGINX to act as a reverse proxy for
the IAM backend application.

The example configuration below is taken from the docker file for the IAM development environment:

```nginx
server {
  listen        443 ssl;
  server_name   YOUR_HOSTNAME_HERE;
  access_log   /var/log/nginx/iam.access.log  combined;

  ssl on;
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  ssl_certificate      /path/to/your/ssl/cert.pem;
  ssl_certificate_key  /path/to/your/ssl/key.pem;

  location / {
    proxy_pass              YOUR_BE_HOSTNAME_HERE:8080;
    proxy_set_header        X-Real-IP $remote_addr;
    proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header        X-Forwarded-Proto https;
    proxy_set_header        Host $http_host;
  }
```

#### JSON web keys generation

Checkout the json-web-key-generator repository:

```bash
git clone https://github.com/mitreid-connect/json-web-key-generator
```

Build the code with:

```bash
mvn package
```

Generate a key with the following command:
```bash
java -jar target/json-web-key-generator-0.3-SNAPSHOT-jar-with-dependencies.jar \
  -t RSA -s 1024 -S -i rsa1
Full key:
{
  "keys": [
    {
      "p": "3oh7ex6zgdmJh5NBD0IplmBDDGC2ECu2A1vcp8e8DqE7OSSpAc1T9tTjJioCGqkNM51JK_MtgCJz1CiysVDOQQ",
      "kty": "RSA",
      "q": "nRmBm5tQ2wmOtd1XUYDRH2qWai6eElt-1cvO5tnTdWZkFaAeaHQ3_xf_PFOjyAv5Y5rNLgf_Xbu9UCo_mSrDMQ",
      "d": "BGHRhQP6ADqqSrM8_mI0YhjGStj1aW9rLi7wXQMJ122kegPxIT7dfP-5UScxykD_BrCCHQVPxdJl5wXy-giZnhaL9wtDkOXb8D8RCi1n02cs3Z1T23xONi_AG47QPBZjM5GcX-oOGCENByuEIdkU_Bn6vvqM3oyVlj5sio7tNAE",
      "e": "AQAB",
      "kid": "rsa1",
      "qi": "RarXtTFCE3hk5ZanLWEapDnn7SLSxAvDcBTmG5SpCI9Eix7cfTigaK6N7OQIN0uGO1GJ-KVWL2v8dyI1jMoU6g",
      "dp": "MtBtieavzMXUzr2ETKyp_GmMxeXLjRO-IzQ1xaYpPhn5AQprATtWofVozQ0on9fcaN3QmJWV3T2Av4BvlWfDQQ",
      "dq": "CWJ7rpsBooQYpV6al8DVPUY1xBQS10_l7MmnC31Zt3qtYelVx7GhoriBQ85PS2UDueKGfUh3BddwQLi1YeX_EQ",
      "n": "iI_fuJq4z_9VQY5EH41sQWOAYUsjtxAFjRnAc1P5-GPOx3Izg9V7yKNmudLUt-jIkv6D5h-AzrhEV6DOdBRoiN4el1mCZ95jiJkjU2kpVOmutDysZkrn667zPd43w7E6IqHnahmMrVUjUyx6pie1SqJHLUXghz8Gle-1yi08_XE"
    }
  ]
}
```
Save the output of the above command (minus the `Full key:` initial text) in a file.

### IAM docker image

The IAM service is provided on the following Dockerhub repositories:

- indigoiam/iam-login-service
- indigodatacloud/iam-login-service

We keep the images in sync, so the following instructions apply to images
fetched from any of the two repositories. 

### IAM configuration

The IAM service is configured via spring profiles and environment variables.

#### IAM profiles

IAM profiles are used to enable/disable group of IAM functionalities. Currently the
following profiles are defined:

|*Profile name*|*Active by default*|*Description*|
|--------------|-------------------|-------------|
| h2 | yes | Enables h2 in-memory database, useful for development and testing |
| mysql  | no | Enables MySQL database backend |
| google | no | Enables Google authentication |
| saml | no | Enables SAML authentication |
| dev | yes | Enables development debugging information |
| registration | yes | Enables user registration and reset password functionalities |

Profiles are enabled by setting the `spring.profiles.active` Java system
property when starting the IAM service. This can be done, using the official
IAM docker image, by setting the IAM_JAVA_OPTS environment variable as follows:

```
IAM_JAVA_OPTS="-Dspring.profiles.active=mysql,google,saml"
```

#### Service configuration

All configurable aspects of the IAM are configured via environment variables.

|*Env. variable*|*Default value*|*Meaning*|
|--------------|-------------|-------|
|IAM_PORT| 8080 | The IAM service will listen on this port|
|IAM_USE_FORWARDED_HEADERS| false | Use forward headers from reverse proxy. Set this to true when deploying the service behind a reverse proxy. |
|IAM_ISSUER | http://localhost:8080 | This is the endpoint on which the IAM will receive requests. |
|IAM_KEY_STORE_LOCATION | N/A | The path to the JSON key store that holds the keys used to sign the tokens |
|IAM_X509_TRUST_ANCHORS_DIR | /etc/grid-security/certificates | Where CA certificates will be searched |
|IAM_X509_TRUST_ANCHORS_REFRESH | 14400| How frequently (in seconds) should trust anchors be refreshed |

#### Database access options

|*Env. variable*|*Default value*|*Meaning*|
|--------------|-------------|-------|
|IAM_DB_HOST | N/A | The host where the MariaDB/MySQL daemon is running |
|IAM_DB_PORT | 3306 | The database port |
|IAM_DB_NAME | iam | The database name |
|IAM_DB_USERNAME | iam | The database username |
|IAM_DB_PASSWORD | pwd | The database password |

#### Google authentication options

|*Env. variable*|*Default value*|*Meaning*|
|--------------|-------------|-------|
|IAM_GOOGLE_CLIENT_ID | N/A | The google OpenID-connect client id |
|IAM_GOOGLE_CLIENT_SECRET | N/A | The Google OpenID-connect client secret |
|IAM_GOOGLE_REDIRECT_URIS | N/A | The Google OpenID-connect redirect URIs |

#### SAML authentication options

|*Env. variable*|*Default value*|*Meaning*|
|--------------|-------------|-------|
|IAM_SAML_ENTITY_ID | N/A | The SAML entity ID |
|IAM_SAML_KEYSTORE | N/A | The keystore holding SAML certificate and keys |
|IAM_SAML_KEYSTORE_PASSWORD | N/A | The keystore password |
|IAM_SAML_KEY_ID | N/A | The identifier of the key that should be used to sign requests/assertions |
|IAM_SAML_KEY_PASSWORD | N/A | The SAML key password |
|IAM_SAML_IDP_METADATA | N/A | The path to the SAML federation idp metadata |

#### Notification service options

IAM notification service use an external SMTP server for sending email notifications.
The table below contains the options for configure the SMTP server.

|*Env. variable*  |*Default value*|*Meaning*|
|-----------------|---------------|---------|
|IAM_MAIL_HOST    |localhost      |Hostname of the SMTP server to use for sending notification emails|
|IAM_MAIL_PORT    |25             |Port on which SMTP server to use is listening|
|IAM_MAIL_USERNAME|N/A            |Username to use for authentication on SMTP server, if required|
|IAM_MAIL_PASSWORD|N/A            |Password to use for authentication on SMTP server, if required|

Specific options:

|*Env. variable*               |*Default value*        |*Meaning*|
|------------------------------|-----------------------|---------|
|IAM_NOTIFICATION_DISABLE      |false                  |Turn on the notification service. If set to `true`, notifications aren't send to mail server, but logged into the log file|
|IAM_NOTIFICATION_FROM         |indigo@localhost       |Mail address used as mail sender| 
|IAM_NOTIFICATION_TASK_DELAY   |30000                  |Time interval, in milliseconds, between two consecutive runs of the job that send notifications|
|IAM_NOTIFICATION_CLEANUP_AGE  |30                     |Retention of delivered messages, in days|
|IAM_NOTIFICATION_ADMIN_ADDRESS|indigo-alerts@localhost|Mail address used as receiver for administrative notifications|


### Example configuration

The IAM service is run starting the docker container with the following command:

```bash
/usr/bin/docker run \
  --name iam-login-service --net=iam -p 8080:8080 \
  --env-file=/path/to//iam-login-service/env \
   -v /path/to//keystore.jks:/keystore.jks:ro \
  indigodatacloud/iam-login-service
```

The env file content is the following: 

```
IAM_JAVA_OPTS=-Dspring.profiles.active=google,mysql -Djava.security.egd=file:/dev/urandom
IAM_BASE_URL=https://iam-test.indigo-datacloud.eu
IAM_ISSUER=https://iam-test.indigo-datacloud.eu/
IAM_USE_FORWARDED_HEADERS=true
IAM_KEY_STORE_LOCATION=file:/keystore.jks
IAM_DB_HOST=the_db_host
IAM_DB_NAME=iam_login_service
IAM_DB_USERNAME=iam_test
IAM_DB_PASSWORD=some_super_secure_password
IAM_DB_VALIDATION_QUERY=SELECT 1
IAM_GOOGLE_CLIENT_ID=XXXXXXXXXXXXXXXXX.apps.googleusercontent.com
IAM_GOOGLE_CLIENT_SECRET=***********
IAM_GOOGLE_REDIRECT_URIS=https://iam-test.indigo-datacloud.eu/openid_connect_login
IAM_SAML_ENTITY_ID=https://iam-test.indigo-datacloud.eu
IAM_SAML_KEYSTORE=file:///saml-keystore.jks
IAM_SAML_KEYSTORE_PASSWORD=********
IAM_SAML_KEY_ID=iam-test
IAM_SAML_KEY_PASSWORD=********
IAM_SAML_IDP_METADATA=file:///idp-metadata.xml
IAM_NOTIFICATION_FROM=iam@iam-test.mydomain.eu
IAM_NOTIFICATION_TASK_DELAY=5000
IAM_NOTIFICATION_ADMIN_ADDRESS=iam-admins@mydomain.eu
IAM_MAIL_HOST=mailman.mydomain.eu
```

[jwk-generator]: https://github.com/mitreid-connect/json-web-key-generator
