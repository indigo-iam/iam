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

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import it.infn.mw.iam.test.util.WithMockPreAuthenticatedUser;

public class WithMockPreAuthenticatedUserSecurityContextFactory
    implements WithSecurityContextFactory<WithMockPreAuthenticatedUser> {

  @Override
  public SecurityContext createSecurityContext(WithMockPreAuthenticatedUser annotation) {
    SecurityContext context = SecurityContextHolder.createEmptyContext();

    Authentication authentication = new UsernamePasswordAuthenticationToken(annotation.username(),
        "", AuthorityUtils.createAuthorityList(annotation.authorities()));
    context.setAuthentication(authentication);
    return context;
  }
}
