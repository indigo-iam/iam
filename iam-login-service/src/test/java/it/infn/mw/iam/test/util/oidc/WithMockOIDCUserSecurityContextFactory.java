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
package it.infn.mw.iam.test.util.oidc;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import it.infn.mw.iam.test.util.WithMockOIDCUser;
import it.infn.mw.iam.util.test.OidcSecurityContextBuilder;

public class WithMockOIDCUserSecurityContextFactory
    implements WithSecurityContextFactory<WithMockOIDCUser> {


  @Override
  public SecurityContext createSecurityContext(WithMockOIDCUser annotation) {

    OidcSecurityContextBuilder builder = new OidcSecurityContextBuilder();

    builder.issuer(annotation.issuer())
      .subject(annotation.subject())
      .email(annotation.email())
      .name(annotation.givenName(), annotation.familyName())
      .username(annotation.username())
      .authorities(annotation.authorities())
      .expirationTime(annotation.expirationTime());

    if (annotation.claims().length >= 2) {
      if (annotation.claims().length % 2 != 0) {
        throw new IllegalArgumentException(
            "claims must be a string array with an even number of elements");
      }

      for (int i = 0; i < annotation.claims().length; i += 2) {
        builder.claim(annotation.claims()[i], annotation.claims()[i + 1]);
      }
    }

    return builder.buildSecurityContext();
  }


}
