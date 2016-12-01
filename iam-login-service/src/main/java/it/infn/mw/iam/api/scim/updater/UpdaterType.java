package it.infn.mw.iam.api.scim.updater;

public enum UpdaterType {

  ACCOUNT_REPLACE_GIVEN_NAME("Replace given name of user"),
  ACCOUNT_REPLACE_FAMILY_NAME("Replace family name of user"),
  ACCOUNT_REPLACE_EMAIL("Replace email of user"),
  ACCOUNT_REPLACE_PASSWORD("Replace password of user"),
  ACCOUNT_REPLACE_PICTURE("Replace picture of user"),
  ACCOUNT_REPLACE_USERNAME("Replace username of user"),
  ACCOUNT_REPLACE_ACTIVE("Replace active status of user"),

  ACCOUNT_ADD_OIDC_ID("Add OpenID Connect account to user"),
  ACCOUNT_ADD_SAML_ID("Add SAML account to user"),
  ACCOUNT_ADD_SSH_KEY("Add ssh key to user"),
  ACCOUNT_ADD_X509_CERTIFICATE("Add x509 certificate to user"),

  ACCOUNT_REMOVE_OIDC_ID("Remove OpenID Connect account from user"),
  ACCOUNT_REMOVE_SAML_ID("Remove SAML account from user"),
  ACCOUNT_REMOVE_SSH_KEY("Remove ssh key from user"),
  ACCOUNT_REMOVE_X509_CERTIFICATE("Remove x509 certificate from user"),

  ACCOUNT_ADD_GROUP_MEMBERSHIP("Add group to user"),
  ACCOUNT_REMOVE_GROUP_MEMBERSHIP("Remove user from group"), 
  ACCOUNT_REMOVE_PICTURE("Remove picture from user");

  private String description;

  UpdaterType(String description) {
    this.description = description;
  }

  public String getDescription() {
    return description;
  }
}