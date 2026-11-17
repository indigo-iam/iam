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
package it.infn.mw.iam.api.account;

import static it.infn.mw.iam.core.oauth.scope.IamSystemScopeService.ADMIN_WRITE_SCOPE;
import static it.infn.mw.iam.core.oauth.scope.IamSystemScopeService.SCIM_WRITE_SCOPE;

import java.util.Optional;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import it.infn.mw.iam.api.common.error.NoSuchAccountError;
import it.infn.mw.iam.api.scim.provisioning.ScimUserProvisioning;
import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.core.userinfo.OAuth2AuthenticationScopeResolver;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Service
@Transactional
@SuppressWarnings("deprecation")
public class DefaultAccountManagementService implements AccountManagementService {

  private final IamAccountRepository accountRepo;
  private final IamAccountService accountService;
  private final ScimUserProvisioning userProvisioning;
  private final AccountUtils accountUtils;
  private final OAuth2AuthenticationScopeResolver scopeResolver;

  public DefaultAccountManagementService(IamAccountRepository accountRepo,
      IamAccountService accountService, ScimUserProvisioning userProvisioning,
      AccountUtils accountUtils, OAuth2AuthenticationScopeResolver scopeResolver) {
    this.accountRepo = accountRepo;
    this.accountService = accountService;
    this.userProvisioning = userProvisioning;
    this.accountUtils = accountUtils;
    this.scopeResolver = scopeResolver;
  }

  @Override
  public void enableAccount(String uuid) {
    IamAccount account = lockManageableAccount(uuid, ADMIN_WRITE_SCOPE)
      .orElseThrow(() -> NoSuchAccountError.forUuid(uuid));
    if (!account.isActive()) {
      accountService.restoreAccount(account);
    }
  }

  @Override
  public void disableAccount(String uuid) {
    IamAccount account = lockManageableAccount(uuid, ADMIN_WRITE_SCOPE)
      .orElseThrow(() -> NoSuchAccountError.forUuid(uuid));
    if (account.isActive()) {
      accountService.disableAccount(account);
    }
  }

  @Override
  public void removeAccount(String uuid) {
    lockManageableAccount(uuid, SCIM_WRITE_SCOPE);
    userProvisioning.delete(uuid);
  }

  private Optional<IamAccount> lockManageableAccount(String uuid, String adminScope) {
    Optional<IamAccount> account = accountRepo.findByUuidForUpdate(uuid);
    account.ifPresent(a -> checkCallerCanManage(a, adminScope));
    return account;
  }

  private void checkCallerCanManage(IamAccount account, String adminScope) {

    Authentication authn = SecurityContextHolder.getContext().getAuthentication();

    if (isAdministrator(authn, adminScope)) {
      return;
    }

    if (accountUtils.isAdmin(account) || accountUtils.isUserManager(account)) {
      throw new AccessDeniedException(
          "Administrator and user manager accounts can be managed only by administrators");
    }

    if (authn instanceof OAuth2Authentication oauth && oauth.getUserAuthentication() == null) {
      return;
    }

    boolean callerHoldsTheRole = accountUtils.getAuthenticatedUserAccount(authn)
      .filter(IamAccount::isActive)
      .filter(c -> accountUtils.isUserManager(c) || accountUtils.isAdmin(c))
      .isPresent();

    if (!callerHoldsTheRole) {
      throw new AccessDeniedException("The user is no longer allowed to manage accounts");
    }
  }

  private boolean isAdministrator(Authentication authn, String adminScope) {

    if (authn instanceof OAuth2Authentication oauth) {
      return scopeResolver.resolveScope(oauth).contains(adminScope);
    }

    return accountUtils.isAdmin(authn);
  }
}
