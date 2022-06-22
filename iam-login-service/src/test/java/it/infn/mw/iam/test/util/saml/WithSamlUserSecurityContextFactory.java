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
package it.infn.mw.iam.test.util.saml;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import it.infn.mw.iam.test.util.WithMockSAMLUser;
import it.infn.mw.iam.util.test.saml.SamlSecurityContextBuilder;

public class WithSamlUserSecurityContextFactory
    implements WithSecurityContextFactory<WithMockSAMLUser> {

  @Override
  public SecurityContext createSecurityContext(WithMockSAMLUser annotation) {

    SamlSecurityContextBuilder builder = new SamlSecurityContextBuilder();

    builder.subject(annotation.subject())
      .issuer(annotation.issuer())
      .authorities(annotation.authorities())
      .email(annotation.email())
      .username(annotation.username())
      .name(annotation.givenName(), annotation.familyName())
      .expirationTime(annotation.expirationTime());
    
    // CERN registration details
    builder.cernPersonId(annotation.cernPersonId())
      .cernFirstName(annotation.cernFirstName())
      .cernLastName(annotation.cerLastName())
      .cernEmail(annotation.cernEmail())
      .cernHomeInstitute(annotation.cernHomeInstitute());
     
    return builder.buildSecurityContext();
  }

}
