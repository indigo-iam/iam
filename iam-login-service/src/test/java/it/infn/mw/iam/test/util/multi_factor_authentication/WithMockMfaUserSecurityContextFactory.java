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
package it.infn.mw.iam.test.util.multi_factor_authentication;

import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.PASSWORD;
import static it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference.AuthenticationMethodReferenceValues.ONE_TIME_PASSWORD;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import it.infn.mw.iam.authn.multi_factor_authentication.IamAuthenticationMethodReference;
import it.infn.mw.iam.core.ExtendedAuthenticationToken;
import it.infn.mw.iam.test.util.WithMockMfaUser;

public class WithMockMfaUserSecurityContextFactory
    implements WithSecurityContextFactory<WithMockMfaUser> {

  @Override
  public SecurityContext createSecurityContext(WithMockMfaUser annotation) {
    SecurityContext context = SecurityContextHolder.createEmptyContext();

    IamAuthenticationMethodReference pwd =
        new IamAuthenticationMethodReference(PASSWORD.getValue());
    IamAuthenticationMethodReference otp =
        new IamAuthenticationMethodReference(ONE_TIME_PASSWORD.getValue());
    Set<IamAuthenticationMethodReference> refs =
        new HashSet<IamAuthenticationMethodReference>(Arrays.asList(pwd, otp));

    ExtendedAuthenticationToken token = new ExtendedAuthenticationToken(annotation.username(), "",
        AuthorityUtils.createAuthorityList(annotation.authorities()));
    token.setAuthenticated(true);
    token.setAuthenticationMethodReferences(refs);
    context.setAuthentication(token);
    return context;
  }
}
