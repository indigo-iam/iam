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

import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.EXT_OIDC_PROVIDER;
import static java.util.Objects.isNull;

import java.text.ParseException;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.mitre.openid.connect.client.OIDCAuthenticationProvider;
import org.mitre.openid.connect.model.OIDCAuthenticationToken;
import org.mitre.openid.connect.model.PendingOIDCAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import it.infn.mw.iam.authn.common.config.AuthenticationValidator;
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.authn.oidc.service.OidcUserDetailsService;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.authn.util.SessionTimeoutHelper;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

public class OidcAuthenticationProvider extends OIDCAuthenticationProvider {

  public static final Logger LOG = LoggerFactory.getLogger(OidcAuthenticationProvider.class);

  private static final String ACR_VALUE_MFA = "https://refeds.org/profile/mfa";

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

      OidcExternalAuthenticationToken extToken;

      IamAuthenticationMethodReference pwd =
          new IamAuthenticationMethodReference(EXT_OIDC_PROVIDER.getValue());
      Set<IamAuthenticationMethodReference> refs = new HashSet<>();
      refs.add(pwd);

      Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(account.get());

      String acrValue = null;
      try {
        Object acrClaim = token.getIdToken().getJWTClaimsSet().getClaim("acr");
        if (acrClaim != null) {
          acrValue = acrClaim.toString();
        }
      } catch (ParseException e) {
        LOG.error("Error parsing JWT claims: {}", e.getMessage());
      }

      // Checking to see if we can find an active MFA secret attached to the user's account. If so,
      // MFA is enabled on the account
      if (totpMfaOptional.isPresent() && totpMfaOptional.get().isActive()
          && (isNull(acrValue) || !ACR_VALUE_MFA.equals(acrValue))) {
        // Add PRE_AUTHENTICATED role to the user. This grants them access to the /iam/verify
        // endpoint
        List<GrantedAuthority> currentAuthorities = List.of(Authorities.ROLE_PRE_AUTHENTICATED);
        Set<GrantedAuthority> fullyAuthenticatedAuthorities = new HashSet<>(user.getAuthorities());

        // Construct a new authentication object for the PRE_AUTHENTICATED user
        extToken = new OidcExternalAuthenticationToken(token,
            Date.from(sessionTimeoutHelper.getDefaultSessionExpirationTime()),
            account.get().getUsername(), null, currentAuthorities);
        extToken.setAuthenticationMethodReferences(refs);
        extToken.setFullyAuthenticatedAuthorities(fullyAuthenticatedAuthorities);
        extToken.setDetails(Map.of("acr", ACR_VALUE_MFA));
      } else {
        // MFA is not enabled on this account, construct a new authentication object for the FULLY
        // AUTHENTICATED user, granting their normal authorities
        extToken = new OidcExternalAuthenticationToken(token,
            Date.from(sessionTimeoutHelper.getDefaultSessionExpirationTime()),
            account.get().getUsername(), null, convert(account.get().getAuthorities()));
        extToken.setAuthenticationMethodReferences(refs);
        if (!isNull(acrValue)) {
          extToken.setDetails(Map.of("acr", acrValue));
        }
      }
      return extToken;
    } else {
      return new OidcExternalAuthenticationToken(token,
          Date.from(sessionTimeoutHelper.getDefaultSessionExpirationTime()), user.getUsername(),
          null, user.getAuthorities());
    }
  }

  private List<GrantedAuthority> convert(Set<IamAuthority> authorities) {
    return authorities.stream()
      .map(auth -> new SimpleGrantedAuthority(auth.getAuthority()))
      .collect(Collectors.toList());
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return (PendingOIDCAuthenticationToken.class.isAssignableFrom(authentication)
        || OidcExternalAuthenticationToken.class.isAssignableFrom(authentication));
  }

}
