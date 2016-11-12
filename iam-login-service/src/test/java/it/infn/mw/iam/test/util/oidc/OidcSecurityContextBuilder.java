package it.infn.mw.iam.test.util.oidc;

import static org.mockito.Mockito.when;

import java.util.Calendar;
import java.util.Date;

import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.mitre.openid.connect.model.UserInfo;
import org.mockito.Mockito;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import com.google.common.base.Strings;

import it.infn.mw.iam.authn.oidc.OidcExternalAuthenticationToken;
import it.infn.mw.iam.test.util.SecurityContextBuilderSupport;

public class OidcSecurityContextBuilder extends SecurityContextBuilderSupport {

  UserInfo userInfo = null;

  public OidcSecurityContextBuilder() {

    issuer = "test-oidc-issuer";

    subject = "test-oidc-subject";

    username = "test-oidc-subject";

    userInfo = Mockito.mock(UserInfo.class);
  }


  public SecurityContextBuilderSupport name(String givenName, String familyName) {

    if (!Strings.isNullOrEmpty(givenName) && !Strings.isNullOrEmpty(familyName)) {
      when(userInfo.getGivenName()).thenReturn(givenName);
      when(userInfo.getFamilyName()).thenReturn(familyName);
      when(userInfo.getName()).thenReturn(givenName + " " + familyName);
    }
    return this;
  }

  public OidcSecurityContextBuilder email(String email) {

    if (!Strings.isNullOrEmpty(email)) {

      if (userInfo == null) {
	userInfo = Mockito.mock(UserInfo.class);
      }

      when(userInfo.getEmail()).thenReturn(email);
    }
    return this;

  }

  public OidcSecurityContextBuilder expirationTime(long unixTime) {
    if (unixTime > 0) {
      this.expirationTime = new Date(unixTime);
    }
    return this;
  }


  @Override
  public SecurityContext buildSecurityContext() {
    SecurityContext context = SecurityContextHolder.createEmptyContext();
    OIDCAuthenticationToken oidcToken =
	new OIDCAuthenticationToken(subject, issuer, userInfo, authorities, null, null, null);

    if (expirationTime == null) {
      Calendar cal = Calendar.getInstance();
      cal.add(Calendar.HOUR, 1);
      expirationTime = cal.getTime();
    }

    OidcExternalAuthenticationToken token =
	new OidcExternalAuthenticationToken(oidcToken, expirationTime, username, null, authorities);

    context.setAuthentication(token);

    return context;
  }



}
