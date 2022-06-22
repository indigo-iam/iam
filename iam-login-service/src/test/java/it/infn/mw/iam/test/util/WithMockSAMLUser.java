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
package it.infn.mw.iam.test.util;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTHN_UNREGISTERED_USER_ROLE;
import static it.infn.mw.iam.test.ext_authn.saml.SamlAuthenticationTestSupport.DEFAULT_IDP_ID;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import org.springframework.security.test.context.support.WithSecurityContext;

import it.infn.mw.iam.authn.saml.util.SamlAttributeNames;
import it.infn.mw.iam.test.util.saml.WithSamlUserSecurityContextFactory;

@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithSamlUserSecurityContextFactory.class)
public @interface WithMockSAMLUser {
  String username() default "test-saml-user";

  String givenName() default "";

  String familyName() default "";

  String email() default "";

  String subject() default "test-saml-user";

  String subjectAttribute() default SamlAttributeNames.eduPersonUniqueId;

  String issuer() default DEFAULT_IDP_ID;

  String eppn() default "test-saml-user@" + DEFAULT_IDP_ID;

  String[] authorities() default {EXT_AUTHN_UNREGISTERED_USER_ROLE};
  
  String cernPersonId() default "";
  String cernEmail() default "";
  String cernFirstName() default "";
  String cerLastName() default "";
  String cernHomeInstitute() default "";

  long expirationTime() default -1;
}
