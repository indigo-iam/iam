package it.infn.mw.iam.authn.saml.util;

public enum Saml2Attribute {

  epuid("eduPersonUniqueId", "urn:oid:1.3.6.1.4.1.5923.1.1.1.13"),
  eppn("eduPersonPrincipalName", "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"),
  eduPersonOrcid("eduPersonOrcid", "urn:oid:1.3.6.1.4.1.5923.1.1.1.16"),
  mail("mail", "urn:oid:0.9.2342.19200300.100.1.3"),
  givenName("givenName", "urn:oid:2.5.4.42"),
  sn("sn", "urn:oid:2.5.4.4"),
  cn("cn", "urn:oid:2.5.4.3"),
  employeeNumber("employeeNumber", "urn:oid:2.16.840.1.113730.3.1.3"),
  spidCode("spidCode", "spidCode");

  private Saml2Attribute(String alias, String attributeName) {
    this.alias = alias;
    this.attributeName = attributeName;
  }

  private String alias;
  private String attributeName;

  public String getAlias() {
    return alias;
  }

  public String getAttributeName() {
    return attributeName;
  }
  
}
