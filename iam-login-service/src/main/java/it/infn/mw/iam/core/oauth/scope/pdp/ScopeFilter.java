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
package it.infn.mw.iam.core.oauth.scope.pdp;

import java.util.Set;

import org.mitre.oauth2.model.AuthenticationHolderEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
public interface ScopeFilter {

  public Set<String> filterScopes(Set<String> scopes, Authentication authn);

  public Set<String> filterScopes(Set<String> scopes, IamAccount account);

  public AuthenticationHolderEntity filterScopes(AuthenticationHolderEntity authHolder);

  public OAuth2Authentication filterScopes(OAuth2Authentication authHolder);

}
