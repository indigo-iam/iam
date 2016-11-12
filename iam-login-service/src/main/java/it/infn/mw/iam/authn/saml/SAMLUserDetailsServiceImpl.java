package it.infn.mw.iam.authn.saml;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolver;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

  final SamlUserIdentifierResolver resolver;
  final IamAccountRepository repo;

  @Autowired
  public SAMLUserDetailsServiceImpl(SamlUserIdentifierResolver resolver,
      IamAccountRepository repo) {
    this.resolver = resolver;
    this.repo = repo;
  }


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

  protected User buildUserFromSamlCredential(String userSamlId, SAMLCredential credential) {
    return new User(userSamlId, "", Arrays
      .asList(ExternalAuthenticationHandlerSupport.EXT_AUTHN_UNREGISTERED_USER_AUTH));
  }

  @Override
  public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {

    String issuerId = credential.getRemoteEntityID();

    String userSamlId =
        resolver.getUserIdentifier(credential).orElseThrow(() -> new UsernameNotFoundException(
            "Could not extract a user identifier from the SAML assertion"));

    Optional<IamAccount> account = repo.findBySamlId(issuerId, userSamlId);

    if (account.isPresent()) {
      return buildUserFromIamAccount(account.get());
    }

    return buildUserFromSamlCredential(userSamlId, credential);
  }

}
