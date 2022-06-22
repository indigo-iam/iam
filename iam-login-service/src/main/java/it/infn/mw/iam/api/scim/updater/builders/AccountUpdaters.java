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

public class AccountUpdaters {

  private AccountUpdaters() {
  }
  
  public static Adders adders(IamAccountRepository repo, IamAccountService accountService,
      PasswordEncoder encoder,
      IamAccount account, OAuth2TokenEntityService tokenService) {
    return new Adders(repo, accountService, encoder, account, tokenService);
  }

  public static Removers removers(IamAccountRepository repo, IamAccountService accountService,
      IamAccount account) {
    return new Removers(repo, accountService, account);
  }

  public static Replacers replacers(IamAccountRepository repo, IamAccountService accountService,
      PasswordEncoder encoder,
      IamAccount account, OAuth2TokenEntityService tokenService) {
    return new Replacers(repo, accountService, encoder, account, tokenService);
  }
  

}
