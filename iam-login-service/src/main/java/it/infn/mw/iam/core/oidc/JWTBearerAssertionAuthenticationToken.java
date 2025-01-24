package it.infn.mw.iam.core.oidc;

import java.text.ParseException;
import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.nimbusds.jwt.JWT;

public class JWTBearerAssertionAuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = -3138213539914074617L;
  private String subject;
  private JWT jwt;

  /**
   * Create an unauthenticated token with the given subject and JWT
   */
  public JWTBearerAssertionAuthenticationToken(JWT jwt) {
    super(null);
    try {
      // save the subject of the JWT in case the credentials get erased later
      this.subject = jwt.getJWTClaimsSet().getSubject();
    } catch (ParseException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    this.jwt = jwt;
    setAuthenticated(false);
  }

  /**
   * Create an authenticated token with the given clientID, JWT, and authorities set
   */
  public JWTBearerAssertionAuthenticationToken(JWT jwt,
      Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    try {
      // save the subject of the JWT in case the credentials get erased later
      this.subject = jwt.getJWTClaimsSet().getSubject();
    } catch (ParseException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }
    this.jwt = jwt;
    setAuthenticated(true);
  }

  @Override
  public Object getCredentials() {
    return jwt;
  }

  @Override
  public Object getPrincipal() {
    return subject;
  }

  public JWT getJwt() {
    return jwt;
  }

  public void setJwt(JWT jwt) {
    this.jwt = jwt;
  }

  @Override
  public void eraseCredentials() {
    super.eraseCredentials();
    setJwt(null);
  }



}
