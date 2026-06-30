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
package it.infn.mw.iam.api.tokens;

import java.util.Optional;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.tokens.service.TokenService;
import it.infn.mw.iam.api.tokens.service.paging.TokensPageRequest;

public class TokensControllerSupport {

  public static final String APPLICATION_JSON_CONTENT_TYPE = "application/json";

  protected <T> ListResponseDTO<T> getFilteredList(TokensPageRequest pageRequest, String username,
      String clientId, TokenService<T> tokenService) {

    Optional<String> user = Optional.ofNullable(username);
    Optional<String> client = Optional.ofNullable(clientId);

    if (user.isPresent() && client.isPresent()) {
      return tokenService.getTokensForClientAndUser(user.get(), client.get(), pageRequest);
    }
    if (user.isPresent()) {
      return tokenService.getTokensForUser(user.get(), pageRequest);
    }
    if (client.isPresent()) {
      return tokenService.getTokensForClient(client.get(), pageRequest);
    }
    return tokenService.getAllTokens(pageRequest);
  }

}
