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
package it.infn.mw.iam.api.scim.updater;

import java.util.List;
import java.util.function.Consumer;
import java.util.function.Predicate;

import org.mitre.oauth2.model.OAuth2AccessTokenEntity;
import org.mitre.oauth2.model.OAuth2RefreshTokenEntity;

import it.infn.mw.iam.audit.events.account.UsernameReplacedEvent;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamOAuthAccessTokenRepository;
import it.infn.mw.iam.persistence.repository.IamOAuthRefreshTokenRepository;

public class UsernameUpdater extends DefaultAccountUpdater<String, UsernameReplacedEvent> {

  private IamOAuthAccessTokenRepository accessTokenRepo;
  private IamOAuthRefreshTokenRepository refreshTokenRepo;
  private String oldUsername;

  public UsernameUpdater(IamAccount account, UpdaterType type, Consumer<String> consumer,
      String newVal, Predicate<String> predicate,
      AccountEventBuilder<String, UsernameReplacedEvent> eventBuilder,
      IamOAuthAccessTokenRepository accessTokenRepo,
      IamOAuthRefreshTokenRepository refreshTokenRepo) {
    super(account, type, consumer, newVal, predicate, eventBuilder);
    this.accessTokenRepo = accessTokenRepo;
    this.refreshTokenRepo = refreshTokenRepo;
  }

  @Override
  public void beforeUpdate() {
    oldUsername = this.getAccount().getUsername();
  }

  @Override
  public void afterUpdate() {

    List<OAuth2AccessTokenEntity> accessTokens =
        accessTokenRepo.findAccessTokensForUser(oldUsername);

    List<OAuth2RefreshTokenEntity> refreshTokens =
        refreshTokenRepo.findRefreshTokensForUser(oldUsername);

    for (OAuth2AccessTokenEntity t : accessTokens) {
      t.getAuthenticationHolder().getUserAuth().setName(newValue);
      accessTokenRepo.save(t);
    }

    for (OAuth2RefreshTokenEntity t : refreshTokens) {
      t.getAuthenticationHolder().getUserAuth().setName(newValue);
      refreshTokenRepo.save(t);
    }
  }

}
