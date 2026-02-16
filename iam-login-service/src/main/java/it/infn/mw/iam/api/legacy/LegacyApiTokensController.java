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

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.core.OAuth2TokenEntityService;
import it.infn.mw.iam.persistence.model.IamAccount;

@RestController
public class LegacyApiTokensController {

  private final OAuth2TokenEntityService tokenService;
  private final AccessTokenConverter accessTokenConverter;
  private final AccountUtils accountUtils;

  public LegacyApiTokensController(AccessTokenConverter accessTokenConverter,
      OAuth2TokenEntityService tokenService, AccountUtils accountUtils) {
    this.accessTokenConverter = accessTokenConverter;
    this.tokenService = tokenService;
    this.accountUtils = accountUtils;
  }

  @GetMapping(value = "/api/tokens/access")
  @PreAuthorize("hasRole('ROLE_USER')")
  List<AccessTokenDTO> getAccessTokensForAuthenticatedUser() {

    Optional<IamAccount> account = accountUtils.getAuthenticatedUserAccount();
    if (account.isPresent()) {
      tokenService.getAllAccessTokensForUser(account.get().getUsername())
        .stream()
        .map(accessTokenConverter::fromEntityToDTO)
        .collect(Collectors.toList());
    }
    return List.of();
  }
}
