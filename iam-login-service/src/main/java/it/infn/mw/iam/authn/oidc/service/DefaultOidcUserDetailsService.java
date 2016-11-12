package it.infn.mw.iam.authn.oidc.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import com.google.common.base.Strings;

import it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class DefaultOidcUserDetailsService implements OidcUserDetailsService {

  @Autowired
  IamAccountRepository repo;

  List<GrantedAuthority> convertAuthorities(IamAccount a) {

    List<GrantedAuthority> authorities = new ArrayList<>();

    for (IamAuthority auth : a.getAuthorities()) {

      authorities.add(new SimpleGrantedAuthority(auth.getAuthority()));

    }
    return authorities;
  }

  protected User buildUserFromIamAccount(IamAccount account) {
    return new User(account.getUsername(), account.getPassword(), convertAuthorities(account));
  }

  protected User buildUserFromOIDCAuthentication(OIDCAuthenticationToken token) {
    String username = token.getSub();

    if (token.getUserInfo() != null) {
      if (!Strings.isNullOrEmpty(token.getUserInfo().getName())) {
	username = token.getUserInfo().getName();
      }
    }

    return new User(username, "", Arrays
      .asList(ExternalAuthenticationHandlerSupport.EXT_AUTHN_UNREGISTERED_USER_AUTH));
  }

  @Override
  public Object loadUserByOIDC(OIDCAuthenticationToken token) {

    Optional<IamAccount> account = repo.findByOidcId(token.getIssuer(), token.getSub());

    if (account.isPresent()) {
      return buildUserFromIamAccount(account.get());
    }

    return buildUserFromOIDCAuthentication(token);
  }

}
