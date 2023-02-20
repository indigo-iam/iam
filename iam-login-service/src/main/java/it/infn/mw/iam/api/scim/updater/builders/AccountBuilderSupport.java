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
package it.infn.mw.iam.api.scim.updater.builders;

import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.springframework.security.crypto.password.PasswordEncoder;

import it.infn.mw.iam.core.user.IamAccountService;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.registration.validation.UsernameValidator;

public abstract class AccountBuilderSupport {

  protected final IamAccountRepository repo;
  protected final IamAccountService accountService;
  protected final PasswordEncoder encoder;
  protected final IamAccount account;
  protected final OAuth2TokenEntityService tokenService;
  protected final UsernameValidator usernameValidator;

  public AccountBuilderSupport(IamAccountRepository repo, IamAccountService accountService,
      OAuth2TokenEntityService tokenService, PasswordEncoder encoder, UsernameValidator usernameValidator, IamAccount account) {
    this.repo = repo;
    this.encoder = encoder;
    this.accountService = accountService;
    this.tokenService = tokenService;
    this.usernameValidator = usernameValidator;
    this.account = account;
  }

  public AccountBuilderSupport(IamAccountRepository repo, IamAccountService accountService,
      IamAccount account) {
    this(repo, accountService, null, null, new UsernameValidator(), account);
  }

}

