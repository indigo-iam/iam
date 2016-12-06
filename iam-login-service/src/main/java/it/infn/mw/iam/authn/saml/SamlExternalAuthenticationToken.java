package it.infn.mw.iam.authn.saml;

import java.util.Collection;
import java.util.Date;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLCredential;

import com.google.common.base.Strings;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAccountLinker;
import it.infn.mw.iam.authn.ExternalAuthenticationInfoBuilder;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo.ExternalAuthenticationType;
import it.infn.mw.iam.persistence.model.IamAccount;

public class SamlExternalAuthenticationToken
    extends AbstractExternalAuthenticationToken<ExpiringUsernameAuthenticationToken> {

  private static final long serialVersionUID = -7854473523011856692L;

  public static final String OID_GIVEN_NAME = "urn:oid:2.5.4.42";
  public static final String OID_SN = "urn:oid:2.5.4.4";
  public static final String OID_CN = "urn:oid:2.5.4.3";
  public static final String OID_MAIL = "urn:oid:0.9.2342.19200300.100.1.3";

  public SamlExternalAuthenticationToken(ExpiringUsernameAuthenticationToken authn,
      Date tokenExpiration, Object principal, Object credentials,
      Collection<? extends GrantedAuthority> authorities) {
    super(authn, tokenExpiration, principal, credentials, authorities);
  }

  @Override
  public Map<String, String> buildAuthnInfoMap(ExternalAuthenticationInfoBuilder visitor) {

    return visitor.buildInfoMap(this);
  }

  @Override
  public ExternalAuthenticationRegistrationInfo toExernalAuthenticationInfo() {

    ExternalAuthenticationRegistrationInfo ri =
	new ExternalAuthenticationRegistrationInfo(ExternalAuthenticationType.SAML);

    SAMLCredential cred = (SAMLCredential) getExternalAuthentication().getCredentials();

    ri.setIssuer(cred.getRemoteEntityID());
    ri.setSubject(getName());

    if (!Strings.isNullOrEmpty(cred.getAttributeAsString(OID_GIVEN_NAME))) {
      ri.setGivenName(cred.getAttributeAsString(OID_GIVEN_NAME));
    }

    if (!Strings.isNullOrEmpty(cred.getAttributeAsString(OID_SN))) {
      ri.setFamilyName(cred.getAttributeAsString(OID_SN));
    }

    if (!Strings.isNullOrEmpty(cred.getAttributeAsString(OID_MAIL))) {
      ri.setEmail(cred.getAttributeAsString(OID_MAIL));
    }

    return ri;
  }

  @Override
  public void linkToIamAccount(ExternalAccountLinker visitor, IamAccount account) {
    visitor.linkToIamAccount(account, this);
  }

}
