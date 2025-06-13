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

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTHN_UNREGISTERED_USER_AUTH;
import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.EXT_OIDC_PROVIDER;
import static java.util.Objects.isNull;

import java.text.ParseException;
import java.util.Arrays;
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

import com.google.common.base.Strings;
import com.google.common.collect.Sets;

import it.infn.mw.iam.authn.InactiveAccountAuthenticationHander;
import it.infn.mw.iam.authn.common.config.AuthenticationValidator;
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.authn.oidc.service.OidcAccountProvisioningService;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.authn.util.SessionTimeoutHelper;
import it.infn.mw.iam.config.oidc.IamOidcJITAccountProvisioningProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

public class OidcAuthenticationProvider extends OIDCAuthenticationProvider {

  public static final Logger LOG = LoggerFactory.getLogger(OidcAuthenticationProvider.class);

  private static final String ACR_VALUE_MFA = "https://refeds.org/profile/mfa";

  private final AuthenticationValidator<OIDCAuthenticationToken> tokenValidatorService;
  private final IamAccountRepository accountRepo;
  private final InactiveAccountAuthenticationHander inactiveAccountHandler;
  private final IamTotpMfaRepository totpMfaRepository;
  private final SessionTimeoutHelper sessionTimeoutHelper;
  private final IamOidcJITAccountProvisioningProperties jitProperties;
  private final OidcAccountProvisioningService oidcProvisioningService;

  public OidcAuthenticationProvider(
      AuthenticationValidator<OIDCAuthenticationToken> tokenValidatorService,
      SessionTimeoutHelper sessionTimeoutHelper, IamAccountRepository accountRepo,
      InactiveAccountAuthenticationHander inactiveAccountHandler,
      IamTotpMfaRepository totpMfaRepository, IamOidcJITAccountProvisioningProperties jitProperties,
      OidcAccountProvisioningService oidcProvisioningService) {

    this.tokenValidatorService = tokenValidatorService;
    this.sessionTimeoutHelper = sessionTimeoutHelper;
    this.accountRepo = accountRepo;
    this.inactiveAccountHandler = inactiveAccountHandler;
    this.totpMfaRepository = totpMfaRepository;
    this.jitProperties = jitProperties;
    this.oidcProvisioningService = oidcProvisioningService;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    OIDCAuthenticationToken token = (OIDCAuthenticationToken) super.authenticate(authentication);

    if (token == null) {
      return null;
    }

    tokenValidatorService.validateAuthentication(token);

    Optional<IamAccount> account = accountRepo.findByOidcId(token.getIssuer(), token.getSub());
    if (account.isEmpty()) {
      if (jitProperties.getEnabled()) {
        IamAccount newAccount = oidcProvisioningService.provisionAccount(token);
        return registeredOidcAuthentication(newAccount, token);
      } else {
        return unregisteredOidcAuthentication(token);
      }
    }
    inactiveAccountHandler.handleInactiveAccount(account.get());
    return registeredOidcAuthentication(account.get(), token);
  }

  private Authentication registeredOidcAuthentication(IamAccount account,
      OIDCAuthenticationToken token) {

    String acrValue = computeAcrValue(token);
    Optional<IamTotpMfa> mfaSettings = totpMfaRepository.findByAccount(account);

    if (mfaSettings.isPresent() && mfaSettings.get().isActive() && mfaNotDone(acrValue)) {
      return preAuthenticated(account, token);
    }
    return fullyAuthenticated(account, token, acrValue);
  }

  private Authentication fullyAuthenticated(IamAccount account, OIDCAuthenticationToken token,
      String acrValue) {

    Set<IamAuthenticationMethodReference> refs = new HashSet<>();
    refs.add(new IamAuthenticationMethodReference(EXT_OIDC_PROVIDER.getValue()));
    Date tokenExpiration = Date.from(sessionTimeoutHelper.getDefaultSessionExpirationTime());
    OidcExternalAuthenticationToken extToken = new OidcExternalAuthenticationToken(token,
        tokenExpiration, account.getUsername(), null, convert(account.getAuthorities()));
    extToken.setAuthenticationMethodReferences(refs);
    if (!isNull(acrValue)) {
      extToken.setDetails(Map.of("acr", acrValue));
    }
    return extToken;
  }

  private Authentication preAuthenticated(IamAccount account, OIDCAuthenticationToken token) {

    Set<IamAuthenticationMethodReference> refs = new HashSet<>();
    refs.add(new IamAuthenticationMethodReference(EXT_OIDC_PROVIDER.getValue()));
    Date tokenExpiration = Date.from(sessionTimeoutHelper.getDefaultSessionExpirationTime());
    List<GrantedAuthority> currentAuthorities = List.of(Authorities.ROLE_PRE_AUTHENTICATED);
    Set<GrantedAuthority> fullyAuthenticatedAuthorities =
        Sets.newHashSet(convert(account.getAuthorities()));
    OidcExternalAuthenticationToken extToken = new OidcExternalAuthenticationToken(token,
        tokenExpiration, account.getUsername(), null, currentAuthorities);
    extToken.setAuthenticationMethodReferences(refs);
    extToken.setFullyAuthenticatedAuthorities(fullyAuthenticatedAuthorities);
    extToken.setDetails(Map.of("acr", ACR_VALUE_MFA));
    return extToken;
  }

  private boolean mfaNotDone(String acrValue) {
    return isNull(acrValue) || !ACR_VALUE_MFA.equals(acrValue);
  }

  private String computeAcrValue(OIDCAuthenticationToken token) {
    try {
      Object acrClaim = token.getIdToken().getJWTClaimsSet().getClaim("acr");
      if (acrClaim != null) {
        return acrClaim.toString();
      }
    } catch (ParseException e) {
      LOG.error("Error parsing JWT claims: {}", e.getMessage());
    }
    return null;
  }

  private Authentication unregisteredOidcAuthentication(OIDCAuthenticationToken token) {
    String username = token.getSub();
    if (token.getUserInfo() != null && !Strings.isNullOrEmpty(token.getUserInfo().getName())) {
      username = token.getUserInfo().getName();
    }
    return new OidcExternalAuthenticationToken(token,
        Date.from(sessionTimeoutHelper.getDefaultSessionExpirationTime()), username, null,
        Arrays.asList(EXT_AUTHN_UNREGISTERED_USER_AUTH));
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
