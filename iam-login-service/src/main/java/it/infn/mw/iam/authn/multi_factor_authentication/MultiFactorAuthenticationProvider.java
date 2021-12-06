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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.api.common.NoSuchAccountError;
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
    IamAccount account = accountRepo.findByUsername(authentication.getName())
      .orElseThrow(() -> NoSuchAccountError.forUsername(authentication.getName()));
    String password = authentication.getCredentials().toString();
    if (!passwordEncoder.matches(password, account.getPassword())) {
      throw new BadCredentialsException("Invalid login details");
    }

    if (account.getTotpMfa() != null && account.getTotpMfa().isActive()) {
      List<GrantedAuthority> updatedAuthorities =
          new ArrayList<>(Arrays.asList(new SimpleGrantedAuthority("ROLE_PRE_AUTHENTICATED")));

      return new UsernamePasswordAuthenticationToken(authentication.getPrincipal(),
          authentication.getCredentials(), updatedAuthorities);
    }

    return null;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return authentication.equals(UsernamePasswordAuthenticationToken.class);
  }
}
