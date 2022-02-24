/**
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.infn.mw.iam.authn.multi_factor_authentication;

import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.PASSWORD;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class MultiFactorAuthenticationProvider implements AuthenticationProvider {

  private IamAccountRepository accountRepo;
  private PasswordEncoder passwordEncoder;

  public MultiFactorAuthenticationProvider(IamAccountRepository accountRepo,
      PasswordEncoder passwordEncoder) {
    this.accountRepo = accountRepo;
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    if (authentication.isAuthenticated()) {
      return authentication;
    }

    IamAccount account = accountRepo.findByUsername(authentication.getName())
      .orElseThrow(() -> new BadCredentialsException("Invalid login details"));
    String password = authentication.getCredentials().toString();
    if (!passwordEncoder.matches(password, account.getPassword())) {
      throw new BadCredentialsException("Invalid login details");
    }

    if (account.getTotpMfa() != null && account.getTotpMfa().isActive()) {
      List<GrantedAuthority> currentAuthorities = new ArrayList<>();
      for (GrantedAuthority authority : authentication.getAuthorities()) {
        currentAuthorities.add(new SimpleGrantedAuthority(authority.getAuthority()));
      }
      currentAuthorities.add(new SimpleGrantedAuthority("ROLE_PRE_AUTHENTICATED"));

      // Used multi-factor authentication, so add pwd and otp as methods of
      // authentication. This ensures the amr flag is properly set in an id_token, if OIDC used. otp
      // refers to one-time-password (this authentication provider is for authenticator apps, which
      // use OTPs)
      IamAuthenticationMethodReference pwd =
          new IamAuthenticationMethodReference(PASSWORD.getValue());
      Set<IamAuthenticationMethodReference> refs = new HashSet<>();
      refs.add(pwd);

      ExtendedAuthenticationToken token = new ExtendedAuthenticationToken(
          authentication.getPrincipal(), authentication.getCredentials(), currentAuthorities, refs);
      token.setAuthenticated(false);
      return token;
    }

    return null;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return authentication.equals(ExtendedAuthenticationToken.class);
  }
}
