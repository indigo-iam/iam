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
package it.infn.mw.iam.authn.multi_factor_authentication;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import dev.samstevens.totp.code.CodeVerifier;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.CodeDTO;
import it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.error.IncorrectCodeError;
import it.infn.mw.iam.api.account.multi_factor_authentication.authenticator_app.error.InvalidCodeError;
import it.infn.mw.iam.authn.multi_factor_authentication.error.AccountNotFoundException;
import it.infn.mw.iam.persistence.model.IamAccount;

@Controller
public class Verify2faController {

  private final AccountUtils accountUtils;
  private final CodeVerifier codeVerifier;

  @Autowired
  public Verify2faController(AccountUtils accountUtils, CodeVerifier codeVerifier) {
    this.accountUtils = accountUtils;
    this.codeVerifier = codeVerifier;
  }

  @PreAuthorize("hasRole('PRE_AUTHENTICATED')")
  @RequestMapping(method = RequestMethod.GET, path = "/iam/verify2fa")
  public String getVerify2faView() {
    return "iam/verify2fa";
  }

  @PreAuthorize("hasRole('PRE_AUTHENTICATED')")
  @RequestMapping(method = RequestMethod.POST, path = "/iam/verify2fa")
  public String verify2fa(@ModelAttribute @Valid CodeDTO code, BindingResult validationResult) {
    if (validationResult.hasErrors()) {
      throw new InvalidCodeError("Invalid code format. Code must be six numeric characters");
    }

    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(() -> new AccountNotFoundException("Account not found"));

    if (!codeVerifier.isValidCode(account.getTotpMfa().getSecret(), code.getCode())) {
      throw new IncorrectCodeError("Incorrect code. Try again");
    }

    SecurityContext sc = SecurityContextHolder.getContext();
    Authentication authentication = sc.getAuthentication();
    List<GrantedAuthority> updatedAuthorities =
        new ArrayList<>(Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));

    Authentication newAuth = new UsernamePasswordAuthenticationToken(authentication.getPrincipal(),
        authentication.getCredentials(), updatedAuthorities);
    sc.setAuthentication(newAuth);

    // TODO touch account, i.e. log the successful verification

    return "redirect:/dashboard";
  }
}