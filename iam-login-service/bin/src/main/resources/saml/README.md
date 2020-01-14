Metadata and keystore for SAML testing.

The signed metadata is generated with the xmlsectool from shibboleth:

https://wiki.shibboleth.net/confluence/display/XSTJ2/xmlsectool+V2+Home

with the following arguments (and executed in the IAM source dir):

```bash
xmlsectool.sh --sign \
  --inFile iam-login-service/src/main/resources/saml/idp-metadata.xml \
  --outFile iam-login-service/src/main/resources/saml/idp-metadata.signed.xml \
  --referenceIdAttributeName ID \
  --keystore iam-login-service/src/main/resources/saml/samlKeystore.jks \
  --keystorePassword "password" \
  --key iam \
  --keyPassword password
```
