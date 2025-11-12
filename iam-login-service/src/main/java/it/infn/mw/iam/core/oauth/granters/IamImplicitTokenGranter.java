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
package it.infn.mw.iam.core.oauth.granters;

import java.util.Collection;

import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

@SuppressWarnings("deprecation")
public class IamImplicitTokenGranter extends ImplicitTokenGranter {

  public IamImplicitTokenGranter(AuthorizationServerTokenServices tokenServices,
      ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory) {
    super(tokenServices, clientDetailsService, requestFactory);
  }

  @Override
  protected void validateGrantType(String grantType, ClientDetails clientDetails) {
    Collection<String> authorizedGrantTypes = clientDetails.getAuthorizedGrantTypes();
    if (authorizedGrantTypes == null || authorizedGrantTypes.isEmpty()
        || !authorizedGrantTypes.contains(grantType)) {
      throw new InvalidClientException("Unauthorized grant type");
    }
  }
}
