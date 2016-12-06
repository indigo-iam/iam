package it.infn.mw.iam.api.account.authority;

import java.util.Set;

public class AuthoritySetDTO {

  Set<String> authorities;

  public static AuthoritySetDTO fromAuthorities(Set<String> authorities) {
    return new AuthoritySetDTO(authorities);
  }


  private AuthoritySetDTO(Set<String> authorities) {
    this.authorities = authorities;
  }

  public Set<String> getAuthorities() {
    return authorities;
  }
}
