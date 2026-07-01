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
package it.infn.mw.iam.api.tokens.service;

import java.util.List;
import java.util.Optional;

import it.infn.mw.iam.api.common.ListResponseDTO;
import it.infn.mw.iam.api.tokens.service.paging.TokensPageRequest;

public interface TokenService<T> {

  ListResponseDTO<T> getAllTokens(TokensPageRequest pageRequest);

  List<T> getAllTokensForUser(String username);

  ListResponseDTO<T> getTokensForUser(String username, TokensPageRequest pageRequest);

  ListResponseDTO<T> getTokensForClient(String clientId, TokensPageRequest pageRequest);

  ListResponseDTO<T> getTokensForClientAndUser(String username, String clientId, TokensPageRequest pageRequest);

  Optional<T> getToken(Long id);

  void revoke(Long id);

}
