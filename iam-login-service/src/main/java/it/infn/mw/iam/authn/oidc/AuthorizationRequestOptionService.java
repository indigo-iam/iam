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
package it.infn.mw.iam.authn.oidc;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import it.infn.mw.iam.authn.oidc.OIDCProviderMetadataService.OIDCProviderMetadata;
import it.infn.mw.iam.config.oidc.OidcProvider;

public class AuthorizationRequestOptionService {

  private Map<String, String> options = new HashMap<>();
  private Map<String, String> tokenOptions = new HashMap<>();

  public Map<String, String> getOptions() {
    return options;
  }

  public void setOptions(Map<String, String> options) {
    this.options = options;
  }

  public Map<String, String> getTokenOptions() {
    return tokenOptions;
  }

  public void setTokenOptions(Map<String, String> tokenOptions) {
    this.tokenOptions = tokenOptions;
  }

}
