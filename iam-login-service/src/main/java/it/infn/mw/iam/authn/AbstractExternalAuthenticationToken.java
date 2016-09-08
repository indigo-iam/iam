package it.infn.mw.iam.authn;

import java.util.Collection;
import java.util.Date;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;

public abstract class AbstractExternalAuthenticationToken<T>
    extends ExpiringUsernameAuthenticationToken {


  /**
   * 
   */
  private static final long serialVersionUID = 3728054624371667370L;

  final T wrappedAuthentication;

  public AbstractExternalAuthenticationToken(T authn, Object principal, Object credentials) {
    super(principal, credentials);
    this.wrappedAuthentication = authn;

  }

  public AbstractExternalAuthenticationToken(T authn, Date tokenExpiration, Object principal,
      Object credentials, Collection<? extends GrantedAuthority> authorities) {
    super(tokenExpiration, principal, credentials, authorities);
    this.wrappedAuthentication = authn;
  }


  public T getExternalAuthentication() {
    return wrappedAuthentication;
  }

  public abstract Map<String, String> buildAuthnInfoMap(ExternalAuthenticationInfoBuilder visitor);

}
