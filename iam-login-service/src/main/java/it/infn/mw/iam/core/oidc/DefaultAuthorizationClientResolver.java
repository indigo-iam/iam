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

import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletResponse;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.persistence.repository.client.IamClientRepository;

@Component
@Profile("!openid-federation")
public class DefaultAuthorizationClientResolver implements AuthorizationClientResolver {

  private final IamClientRepository clientRepo;

  public DefaultAuthorizationClientResolver(IamClientRepository clientRepo) {
    this.clientRepo = clientRepo;
  }

  @Override
  public Optional<ClientDetailsEntity> resolveClient(
      String clientId,
      Map<String, String> params,
      HttpServletResponse response) {

    return clientRepo.findByClientId(clientId);
  }
}