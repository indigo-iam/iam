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
package it.infn.mw.iam.api.authn_info;

import static it.infn.mw.iam.authn.ExternalAuthenticationHandlerSupport.EXT_AUTHN_UNREGISTERED_USER_ROLE;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.authn.AbstractExternalAuthenticationToken;
import it.infn.mw.iam.authn.ExternalAuthenticationRegistrationInfo;

@RestController
public class AuthnInfoController {

  public static final String BASE_RESOURCE = "/iam/authn-info";

  @RequestMapping(value=BASE_RESOURCE, method=RequestMethod.GET)
  @PreAuthorize("hasRole('" + EXT_AUTHN_UNREGISTERED_USER_ROLE + "')")
  public ExternalAuthenticationRegistrationInfo getAuthenticationInfo() {

    AbstractExternalAuthenticationToken<?> extAuthnToken =
	(AbstractExternalAuthenticationToken<?>) SecurityContextHolder.getContext()
	  .getAuthentication();

    return extAuthnToken.toExernalAuthenticationRegistrationInfo();

  }
}
