package it.infn.mw.iam.test.util;

import java.util.Date;
import java.util.List;

import org.joda.time.DateTime;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;

public abstract class SecurityContextBuilderSupport {

  protected String issuer;
  protected String subject;

  protected String username;

  protected Date expirationTime = DateTime.now().plusHours(1).toDate();

  protected List<GrantedAuthority> authorities;

  public SecurityContextBuilderSupport issuer(String issuer) {
    this.issuer = issuer;
    return this;
  }

  public SecurityContextBuilderSupport subject(String subject) {
    this.subject = subject;
    return this;
  }

  public SecurityContextBuilderSupport username(String username) {
    this.username = username;
    return this;
  }

  public SecurityContextBuilderSupport authorities(String... authorities) {
    this.authorities = AuthorityUtils.createAuthorityList(authorities);
    return this;
  }

  public SecurityContextBuilderSupport authorities(List<GrantedAuthority> authorities) {
    this.authorities = authorities;
    return this;
  }

  public SecurityContextBuilderSupport expirationTime(long expirationTimeMillis) {
    if (expirationTimeMillis > 0) {
      this.expirationTime = new Date(expirationTimeMillis);
    }
    return this;
  }

  public abstract SecurityContextBuilderSupport email(String email);

  public abstract SecurityContextBuilderSupport name(String givenName, String familyName);

  public abstract SecurityContext buildSecurityContext();
}
