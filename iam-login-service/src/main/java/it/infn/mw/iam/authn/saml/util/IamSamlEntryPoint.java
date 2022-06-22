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
package it.infn.mw.iam.authn.saml.util;

import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

import it.infn.mw.iam.authn.saml.profile.SSOProfileOptionsResolver;

public class IamSamlEntryPoint extends SAMLEntryPoint {

  private final SSOProfileOptionsResolver optionsResolver;
  
  public IamSamlEntryPoint(SSOProfileOptionsResolver resolver) {
    this.optionsResolver = resolver;
  }
  
  
  @Override
  protected WebSSOProfileOptions getProfileOptions(SAMLMessageContext context,
      AuthenticationException exception) throws MetadataProviderException {
    return optionsResolver.resolveProfileOptions(context.getPeerEntityId());
  }
  
}
