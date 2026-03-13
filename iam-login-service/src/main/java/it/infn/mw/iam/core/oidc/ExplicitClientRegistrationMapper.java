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
package it.infn.mw.iam.core.oidc;

import java.util.Optional;

import org.springframework.stereotype.Component;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import it.infn.mw.iam.api.common.client.RegisteredClientDTO;
import it.infn.mw.iam.api.common.client.TokenEndpointAuthenticationMethod;

@Component
public class ExplicitClientRegistrationMapper extends BaseFedClientRegistrationMapper {

  @Override
  protected void setTokenEndpointAuthMethod(RegisteredClientDTO dto, OIDCClientMetadata metadata) {
    dto.setTokenEndpointAuthMethod(Optional.ofNullable(metadata.getTokenEndpointAuthMethod())
      .map(v -> TokenEndpointAuthenticationMethod.valueOf(v.getValue()))
      .orElse(TokenEndpointAuthenticationMethod.client_secret_basic));
  }
}
