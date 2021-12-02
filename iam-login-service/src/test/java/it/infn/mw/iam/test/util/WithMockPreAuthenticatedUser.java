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

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import org.springframework.security.test.context.support.WithSecurityContext;

import it.infn.mw.iam.test.util.multi_factor_authentication.WithMockPreAuthenticatedUserSecurityContextFactory;

@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithMockPreAuthenticatedUserSecurityContextFactory.class)
public @interface WithMockPreAuthenticatedUser {

  String username() default "test-pre-authenticated-user";

  String[] authorities() default {"ROLE_PRE_AUTHENTICATED"};
}
