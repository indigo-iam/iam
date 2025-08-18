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

import it.infn.mw.iam.authn.error.InvalidAARCHintError;

@Service
public class DefaultAARCHintService implements AARCHintService {

  private static final String SAML_COLON = "saml:";


  private String baseUrl;


  // right, now I need to modify this, so it doesn't just accept SAML

  @Autowired
  public DefaultAARCHintService(@Value("${iam.baseUrl}") String url) {
    this.baseUrl = url;
  }

  protected void hintSanityChecks(String hint) {
    if (Objects.isNull(hint)) {
      throw new InvalidAARCHintError("null hint");
    }

    if (Strings.isNullOrEmpty(hint.trim())) {
      throw new InvalidAARCHintError("empty hint");
    }
  }

  @Override
  public String resolve(String aarcHint) {
    hintSanityChecks(aarcHint);

    // Okay, this works, but I need to check for OIDC providers and SAML providers
    // fuck yes, this seems to be working!! 
    // Now I just need to gather the whitelisted providers so I can check with them



    // OIDC redirect
    //return String.format("%s/openid_connect_login?iss=%s", baseUrl, aarcHint);

    // SAML redirect 
    return String.format("%s/saml/login?idp=%s", baseUrl, aarcHint);


    // It shouldn't be if the hint starts with it. 
    // It should be if it is within the oidc list 
    // and otherwise it should check if it is in the saml list
/*     if (aarcHint.startsWith(SAML_COLON)) {
      if (SAML_COLON.equals(aarcHint)) {
        return String.format("%s/saml/login", baseUrl);
      }
      return String.format("%s/saml/login?idp=%s", baseUrl, aarcHint.substring(5));
    }
    throw new InvalidAARCHintError(String.format("unsupported hint: %s", aarcHint));
 */
    
  }

}

