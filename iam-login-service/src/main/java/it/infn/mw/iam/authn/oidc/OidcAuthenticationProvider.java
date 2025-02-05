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
package it.infn.mw.iam.authn.oidc;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.mitre.openid.connect.client.OIDCAuthenticationProvider;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.mitre.openid.connect.model.PendingOIDCAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import it.infn.mw.iam.authn.common.config.AuthenticationValidator;
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.authn.oidc.service.OidcUserDetailsService;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.authn.util.SessionTimeoutHelper;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

public class OidcAuthenticationProvider extends OIDCAuthenticationProvider {

  public static final Logger LOG = LoggerFactory.getLogger(OidcAuthenticationProvider.class);

  private final OidcUserDetailsService userDetailsService;
  private final AuthenticationValidator<OIDCAuthenticationToken> tokenValidatorService;
  private final IamAccountRepository accountRepo;
  private final IamTotpMfaRepository totpMfaRepository;
  private final SessionTimeoutHelper sessionTimeoutHelper;

  public OidcAuthenticationProvider(OidcUserDetailsService userDetailsService,
      AuthenticationValidator<OIDCAuthenticationToken> tokenValidatorService,
      SessionTimeoutHelper sessionTimeoutHelper, IamAccountRepository accountRepo,
      IamTotpMfaRepository totpMfaRepository) {

    this.userDetailsService = userDetailsService;
    this.tokenValidatorService = tokenValidatorService;
    this.sessionTimeoutHelper = sessionTimeoutHelper;
    this.accountRepo = accountRepo;
    this.totpMfaRepository = totpMfaRepository;
  }


  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    OIDCAuthenticationToken token = (OIDCAuthenticationToken) super.authenticate(authentication);

    if (token == null) {
      return null;
    }

    tokenValidatorService.validateAuthentication(token);

    User user = (User) userDetailsService.loadUserByOIDC(token);

    Optional<IamAccount> account = accountRepo.findByUsername(user.getUsername());
    if (account.isPresent()) {

      ExtendedAuthenticationToken extToken;

      IamAuthenticationMethodReference pwd = new IamAuthenticationMethodReference("oidc");
      Set<IamAuthenticationMethodReference> refs = new HashSet<>();
      refs.add(pwd);

      Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(account.get());

      // Checking to see if we can find an active MFA secret attached to the user's account. If so,
      // MFA is enabled on the account
      if (totpMfaOptional.isPresent() && totpMfaOptional.get().isActive()) {
        // Add PRE_AUTHENTICATED role to the user. This grants them access to the /iam/verify
        // endpoint
        List<GrantedAuthority> currentAuthorities = List.of(Authorities.ROLE_PRE_AUTHENTICATED);
        Set<GrantedAuthority> fullyAuthenticatedAuthorities = new HashSet<>(user.getAuthorities());

        // Construct a new authentication object for the PRE_AUTHENTICATED user
        extToken = new ExtendedAuthenticationToken(account.get().getUsername(),
            authentication.getCredentials(), currentAuthorities);
        extToken.setAuthenticationMethodReferences(refs);
        extToken.setAuthenticated(false);
        extToken.setFullyAuthenticatedAuthorities(fullyAuthenticatedAuthorities);
      } else {
        // MFA is not enabled on this account, construct a new authentication object for the FULLY
        // AUTHENTICATED user, granting their normal authorities
        extToken = new ExtendedAuthenticationToken(account.get().getUsername(),
            authentication.getCredentials(), user.getAuthorities());
        extToken.setAuthenticationMethodReferences(refs);
        extToken.setAuthenticated(true);
      }

      return extToken;
    } else {
      return new OidcExternalAuthenticationToken(token,
          Date.from(sessionTimeoutHelper.getDefaultSessionExpirationTime()), user.getUsername(),
          null, user.getAuthorities());
    }
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return (ExtendedAuthenticationToken.class.isAssignableFrom(authentication)
        || PendingOIDCAuthenticationToken.class.isAssignableFrom(authentication));
  }

}
