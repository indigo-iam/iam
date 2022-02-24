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

import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.ONE_TIME_PASSWORD;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import dev.samstevens.totp.code.CodeVerifier;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class MultiFactorCodeCheckProvider implements AuthenticationProvider {

  private final IamAccountRepository accountRepo;
  private final CodeVerifier codeVerifier;

  public MultiFactorCodeCheckProvider(IamAccountRepository accountRepo, CodeVerifier codeVerifier) {
    this.accountRepo = accountRepo;
    this.codeVerifier = codeVerifier;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    if (authentication.isAuthenticated()) {
      return authentication;
    }

    ExtendedAuthenticationToken token = (ExtendedAuthenticationToken) authentication;
    String code = token.getCode();

    IamAccount account = accountRepo.findByUsername(authentication.getName())
      .orElseThrow(() -> new BadCredentialsException("Invalid login details"));

    IamTotpMfa totpMfa = account.getTotpMfa();

    if (code != null && totpMfa != null && totpMfa.isActive()) {
      if (codeVerifier.isValidCode(totpMfa.getSecret(), code)) {
        IamAuthenticationMethodReference otp =
            new IamAuthenticationMethodReference(ONE_TIME_PASSWORD.getValue());
        Set<IamAuthenticationMethodReference> refs = token.getAuthenticationMethodReferences();
        refs.add(otp);
        token.setAuthenticationMethodReferences(refs);
        token.setAuthenticated(true);

        List<GrantedAuthority> authorities = new ArrayList<>();
        for (GrantedAuthority authority : authentication.getAuthorities()) {
          authorities.add(new SimpleGrantedAuthority(authority.getAuthority()));
        }
        authorities.remove(new SimpleGrantedAuthority("ROLE_PRE_AUTHENTICATED"));

        account.getAuthorities()
          .stream()
          .forEach(
              authority -> authorities.add(new SimpleGrantedAuthority(authority.getAuthority())));

        ExtendedAuthenticationToken newToken = new ExtendedAuthenticationToken(token.getPrincipal(),
            token.getCredentials(), authorities, token.getAuthenticationMethodReferences());
        newToken.setAuthenticated(true);

        return newToken;
      }
    }

    return null;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return authentication.equals(ExtendedAuthenticationToken.class);
  }
}
