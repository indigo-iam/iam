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
package it.infn.mw.iam.authn.saml;

import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.EXT_SAML_PROVIDER;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLCredential;

import com.google.common.base.Joiner;

import it.infn.mw.iam.authn.common.config.AuthenticationValidator;
import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolutionResult;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolver;
import it.infn.mw.iam.authn.util.Authorities;
import it.infn.mw.iam.authn.util.SessionTimeoutHelper;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

public class IamSamlAuthenticationProvider extends SAMLAuthenticationProvider {

  private final SamlUserIdentifierResolver userIdResolver;
  private final AuthenticationValidator<ExpiringUsernameAuthenticationToken> validator;
  private final Joiner joiner = Joiner.on(",").skipNulls();
  private final SessionTimeoutHelper sessionTimeoutHelper;
  private final IamAccountRepository accountRepo;
  private final IamTotpMfaRepository totpMfaRepository;

  public IamSamlAuthenticationProvider(SamlUserIdentifierResolver resolver,
      AuthenticationValidator<ExpiringUsernameAuthenticationToken> validator,
      SessionTimeoutHelper sessionTimeoutHelper, IamAccountRepository accountRepo,
      IamTotpMfaRepository totpMfaRepository) {
    this.userIdResolver = resolver;
    this.validator = validator;
    this.sessionTimeoutHelper = sessionTimeoutHelper;
    this.accountRepo = accountRepo;
    this.totpMfaRepository = totpMfaRepository;
  }

  private Supplier<AuthenticationServiceException> handleResolutionFailure(
      SamlUserIdentifierResolutionResult result) {

    List<String> errorMessages = result.getErrorMessages().orElse(Collections.emptyList());

    return () -> new AuthenticationServiceException(joiner.join(errorMessages));
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    ExpiringUsernameAuthenticationToken token =
        (ExpiringUsernameAuthenticationToken) super.authenticate(authentication);

    if (token == null) {
      return null;
    }

    User user = (User) token.getDetails();

    SAMLCredential samlCredentials = (SAMLCredential) token.getCredentials();

    SamlUserIdentifierResolutionResult result =
        userIdResolver.resolveSamlUserIdentifier(samlCredentials);

    IamSamlId samlId = result.getResolvedId().orElseThrow(handleResolutionFailure(result));

    validator.validateAuthentication(token);

    Optional<IamAccount> account = accountRepo.findByUsername(user.getUsername());

    if (account.isPresent()) {
      SamlExternalAuthenticationToken extToken;

      IamAuthenticationMethodReference pwd =
          new IamAuthenticationMethodReference(EXT_SAML_PROVIDER.getValue());
      Set<IamAuthenticationMethodReference> refs = new HashSet<>();
      refs.add(pwd);

      Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(account.get());

      // Check if SAML assertion coming from remote IdP contains mfa signal
      String authnContextClassRef = samlCredentials.getAuthenticationAssertion()
        .getAuthnStatements()
        .stream()
        .map(AuthnStatement::getAuthnContext)
        .filter(Objects::nonNull)
        .map(AuthnContext::getAuthnContextClassRef)
        .filter(Objects::nonNull)
        .map(AuthnContextClassRef::getAuthnContextClassRef)
        .filter(Objects::nonNull)
        .filter(acr -> acr.toLowerCase().contains("mfa"))
        .findFirst()
        .orElse(null);

      boolean isMfa = "https://refeds.org/profile/mfa".equals(authnContextClassRef);

      if (totpMfaOptional.isPresent() && totpMfaOptional.get().isActive() && !isMfa) {
        List<GrantedAuthority> currentAuthorities = List.of(Authorities.ROLE_PRE_AUTHENTICATED);
        Set<GrantedAuthority> fullyAuthenticatedAuthorities = new HashSet<>(user.getAuthorities());

        extToken = new SamlExternalAuthenticationToken(samlId, token,
            Date.from(sessionTimeoutHelper.getDefaultSessionExpirationTime()),
            account.get().getUsername(), token.getCredentials(), currentAuthorities);
        extToken.setAuthenticationMethodReferences(refs);
        extToken.setFullyAuthenticatedAuthorities(fullyAuthenticatedAuthorities);
      } else {
        extToken = new SamlExternalAuthenticationToken(samlId, token,
            Date.from(sessionTimeoutHelper.getDefaultSessionExpirationTime()),
            account.get().getUsername(), token.getCredentials(),
            convert(account.get().getAuthorities()));
        if (isMfa) {
          Map<String, String> authDetails = new HashMap<>();
          authDetails.put("acr", authnContextClassRef);
          extToken.setDetails(authDetails);
        }
      }
      return extToken;
    } else {

      return new SamlExternalAuthenticationToken(samlId, token,
          Date.from(sessionTimeoutHelper.getDefaultSessionExpirationTime()), user.getUsername(),
          token.getCredentials(), token.getAuthorities());
    }
  }

  private List<GrantedAuthority> convert(Set<IamAuthority> authorities) {
    return authorities.stream()
      .map(auth -> new SimpleGrantedAuthority(auth.getAuthority()))
      .collect(Collectors.toList());
  }
}
