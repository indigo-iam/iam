package it.infn.mw.iam.authn;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ExternalAuthenticationRegistrationInfo {

  public enum ExternalAuthenticationType {
    OIDC, SAML
  }

  @JsonProperty("type")
  private final ExternalAuthenticationType type;

  private String issuer;
  private String subject;

  private String email;

  private String givenName;
  private String familyName;

  public ExternalAuthenticationRegistrationInfo(ExternalAuthenticationType type) {
    this.type = type;
  }

  @JsonCreator
  public ExternalAuthenticationRegistrationInfo(@JsonProperty("type") String type,
      @JsonProperty("issuer") String issuer, @JsonProperty("subject") String subject,
      @JsonProperty("email") String email, @JsonProperty("given_name") String givenName,
      @JsonProperty("family_name") String familyName) {

    this.type = ExternalAuthenticationType.valueOf(type);
    this.issuer = issuer;
    this.subject = subject;
    this.email = email;
    this.givenName = givenName;
    this.familyName = familyName;
  }

  public ExternalAuthenticationType getType() {
    return type;
  }

  public String getIssuer() {
    return issuer;
  }

  public void setIssuer(String issuer) {
    this.issuer = issuer;
  }

  public String getSubject() {
    return subject;
  }

  public void setSubject(String subject) {
    this.subject = subject;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public String getGivenName() {
    return givenName;
  }

  @JsonProperty("given_name")
  public void setGivenName(String givenName) {
    this.givenName = givenName;
  }

  @JsonProperty("family_name")
  public String getFamilyName() {
    return familyName;
  }

  public void setFamilyName(String familyName) {
    this.familyName = familyName;
  }
}
