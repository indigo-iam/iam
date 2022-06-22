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
package it.infn.mw.iam.authn;

import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.google.common.base.Strings;

import it.infn.mw.iam.authn.error.InvalidExternalAuthenticationHintError;

@Service
public class DefaultExternalAuthenticationHintService implements ExternalAuthenticationHintService {

  private static final String SAML_COLON="saml:";
  
  private String baseUrl;
  
  @Autowired
  public DefaultExternalAuthenticationHintService(@Value("${iam.baseUrl}") String url) {
    this.baseUrl = url;
  }
  
  protected void hintSanityChecks(String hint) {
    if (Objects.isNull(hint)) {
      throw new InvalidExternalAuthenticationHintError("null hint");
    }

    if (Strings.isNullOrEmpty(hint.trim())) {
      throw new InvalidExternalAuthenticationHintError("empty hint");
    }
  }

  @Override
  public String resolve(String externalAuthnHint) {
    hintSanityChecks(externalAuthnHint);
    if (externalAuthnHint.startsWith(SAML_COLON)) {
      if (SAML_COLON.equals(externalAuthnHint)) {
        return String.format("%s/saml/login", baseUrl); 
      }
      return String.format("%s/saml/login?idp=%s", baseUrl, externalAuthnHint.substring(5));
    }
    throw new InvalidExternalAuthenticationHintError(
        String.format("unsupported hint: %s", externalAuthnHint));
  }

}
