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

import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.ONE_TIME_PASSWORD;
import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.PASSWORD;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.mitre.openid.connect.client.OIDCAuthenticationProvider;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
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

    Optional<IamAccount> account = accountRepo.findByEmail(token.getUserInfo().getEmail());
    if (account.isPresent()) {

      OidcExternalAuthenticationToken extToken;

      Set<IamAuthenticationMethodReference> refs = new HashSet<>();

      // Extract the `amr` claim from the ID token, if available
      Object amrValues;
      try {
        amrValues = token.getIdToken().getJWTClaimsSet().getClaim("amr");
        if (amrValues != null) {
          // Check for each possible authentication method in the `amr` claim and add to refs
          if (amrValues.equals("pwd")) {
            refs.add(new IamAuthenticationMethodReference(PASSWORD.getValue()));
          }
          if (amrValues.equals("otp")) {
            refs.add(new IamAuthenticationMethodReference(ONE_TIME_PASSWORD.getValue()));
          }
          if (amrValues.equals("mfa")) {
            refs.add(new IamAuthenticationMethodReference("mfa"));
          }
        }
      } catch (ParseException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      }

      Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(account.get());

      // Checking to see if we can find an active MFA secret attached to the user's account. If so,
      // MFA is enabled on the account
      if (totpMfaOptional.isPresent() && totpMfaOptional.get().isActive()) {
        List<GrantedAuthority> currentAuthorities = new ArrayList<>();
        // Add PRE_AUTHENTICATED role to the user. This grants them access to the /iam/verify endpoint
        currentAuthorities.add(Authorities.ROLE_PRE_AUTHENTICATED);
        currentAuthorities.addAll(user.getAuthorities());

        // Construct a new authentication object for the PRE_AUTHENTICATED user
        extToken = new OidcExternalAuthenticationToken(token,
            Date.from(sessionTimeoutHelper.getDefaultSessionExpirationTime()),
            account.get().getUsername(), null, currentAuthorities);
        extToken.setAuthenticated(false);
        //extToken.setDetails(refs);
      } else {
        // MFA is not enabled on this account, construct a new authentication object for the FULLY
        // AUTHENTICATED user, granting their normal authorities
        extToken = new OidcExternalAuthenticationToken(token,
            Date.from(sessionTimeoutHelper.getDefaultSessionExpirationTime()),
            account.get().getUsername(), null, user.getAuthorities());
      }

      return extToken;
    } else {
      return new OidcExternalAuthenticationToken(token,
          Date.from(sessionTimeoutHelper.getDefaultSessionExpirationTime()), user.getUsername(),
          null, user.getAuthorities());
    }
  }

}
