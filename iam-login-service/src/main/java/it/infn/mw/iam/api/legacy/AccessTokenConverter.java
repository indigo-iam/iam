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
package it.infn.mw.iam.api.legacy;

import org.springframework.stereotype.Component;

import it.infn.mw.iam.persistence.model.OAuth2AccessTokenEntity;

@Component
public class AccessTokenConverter {

  AccessTokenDTO fromEntityToDTO(OAuth2AccessTokenEntity entity) {

    AccessTokenDTO.Builder builder = AccessTokenDTO.builder();

    builder.id(entity.getId());
    builder.value(entity.getValue());
    builder.expiration(entity.getExpiration());
    builder.clientId(entity.getClient().getClientId());
    builder.scopes(entity.getScope());

    if (entity.getAuthenticationHolder().getUserAuth() != null) {
      builder.userId(entity.getAuthenticationHolder().getUserAuth().getName());
    }
    if (entity.getRefreshToken() != null) {
      builder.refreshTokenId(entity.getRefreshToken().getId());
    }
    return builder.build();
  }
}
