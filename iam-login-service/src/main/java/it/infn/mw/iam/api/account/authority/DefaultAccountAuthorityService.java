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
package it.infn.mw.iam.api.account.authority;

import static com.google.common.base.Preconditions.checkNotNull;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.audit.events.account.authority.AuthorityAddedEvent;
import it.infn.mw.iam.audit.events.account.authority.AuthorityRemovedEvent;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAuthority;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamAuthoritiesRepository;

@Service
public class DefaultAccountAuthorityService
    implements AccountAuthorityService, ApplicationEventPublisherAware {

  public static final String ACCOUNT_NOT_NULL_MSG = "account must not be null";

  final IamAuthoritiesRepository authRepo;
  final IamAccountRepository accountRepo;
  private ApplicationEventPublisher eventPublisher;

  @Autowired
  public DefaultAccountAuthorityService(IamAuthoritiesRepository authRepo,
      IamAccountRepository accountRepo) {
    this.authRepo = authRepo;
    this.accountRepo = accountRepo;
  }

  public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
    this.eventPublisher = publisher;
  }

  protected IamAuthority findAuthorityFromString(String authority) {
    checkNotNull(authority, "authority must not be null");

    return authRepo.findByAuthority(authority).orElseThrow(
        () -> new InvalidAuthorityError(String.format("Invalid authority: '%s'", authority)));
  }

  @Override
  public void addAuthorityToAccount(IamAccount account, String authority) {
    checkNotNull(account, ACCOUNT_NOT_NULL_MSG);

    IamAuthority iamAuthority = findAuthorityFromString(authority);

    if (account.getAuthorities().contains(iamAuthority)) {
      String msg = String.format("Authority '%s' is already bound to user '%s' (%s)", authority,
          account.getUsername(), account.getUuid());
      throw new AuthorityAlreadyBoundError(msg);
    }

    account.getAuthorities().add(iamAuthority);
    accountRepo.save(account);

    final String message =
        String.format("Authority %s was added to user %s.", authority, account.getUsername());

    eventPublisher.publishEvent(new AuthorityAddedEvent(this, account, message, authority));
  }

  @Override
  public void removeAuthorityFromAccount(IamAccount account, String authority) {
    checkNotNull(account, ACCOUNT_NOT_NULL_MSG);
    IamAuthority iamAuthority = findAuthorityFromString(authority);
    account.getAuthorities().remove(iamAuthority);
    accountRepo.save(account);

    final String message =
        String.format("Authority %s was removed from user %s.", authority, account.getUsername());

    eventPublisher.publishEvent(new AuthorityRemovedEvent(this, account, message, authority));
  }

  @Override
  public Set<String> getAccountAuthorities(IamAccount account) {
    checkNotNull(account, ACCOUNT_NOT_NULL_MSG);

    return account.getAuthorities()
      .stream()
      .map(IamAuthority::getAuthority)
      .collect(Collectors.toSet());
  }

}
