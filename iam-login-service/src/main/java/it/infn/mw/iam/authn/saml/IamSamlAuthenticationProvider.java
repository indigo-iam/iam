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

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.function.Supplier;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLCredential;

import com.google.common.base.Joiner;

import it.infn.mw.iam.authn.common.config.AuthenticationValidator;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolutionResult;
import it.infn.mw.iam.authn.saml.util.SamlUserIdentifierResolver;
import it.infn.mw.iam.authn.util.SessionTimeoutHelper;
import it.infn.mw.iam.persistence.model.IamSamlId;

public class IamSamlAuthenticationProvider extends SAMLAuthenticationProvider {

  private final SamlUserIdentifierResolver userIdResolver;
  private final AuthenticationValidator<ExpiringUsernameAuthenticationToken> validator;
  private final Joiner joiner = Joiner.on(",").skipNulls();
  private final SessionTimeoutHelper sessionTimeoutHelper;

  public IamSamlAuthenticationProvider(SamlUserIdentifierResolver resolver,
      AuthenticationValidator<ExpiringUsernameAuthenticationToken> validator,
      SessionTimeoutHelper sessionTimeoutHelper) {
    this.userIdResolver = resolver;
    this.validator = validator;
    this.sessionTimeoutHelper = sessionTimeoutHelper;
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

    return new SamlExternalAuthenticationToken(samlId, token,
        Date.from(sessionTimeoutHelper.getDefaultSessionExpirationTime()), user.getUsername(),
        token.getCredentials(), token.getAuthorities());
  }

}
