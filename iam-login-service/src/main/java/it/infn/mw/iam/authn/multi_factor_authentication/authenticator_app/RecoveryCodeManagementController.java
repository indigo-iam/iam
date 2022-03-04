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
package it.infn.mw.iam.authn.multi_factor_authentication.authenticator_app;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.authn.multi_factor_authentication.error.MultiFactorAuthenticationError;
import it.infn.mw.iam.authn.multi_factor_authentication.error.NoMultiFactorSecretError;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpRecoveryCode;

// TODO if the resetting of recovery codes after use is a requirement, we need to prevent the user
// from accessing IAM webpages after authenticating. This may require an additional ROLE for
// handling this. Should also try and tie this in with a generic page for resetting recovery codes
// for anyone who is logged in

@Controller
public class RecoveryCodeManagementController {

  public static final String RECOVERY_CODE_RESET_URL = "/iam/authenticator-app/recovery-code/reset";
  public static final String RECOVERY_CODE_VIEW_URL = "/iam/authenticator-app/recovery-code/view";
  public static final String RECOVERY_CODE_GET_URL = "/iam/authenticator-app/recovery-code/get";

  private final AccountUtils accountUtils;

  @Autowired
  public RecoveryCodeManagementController(AccountUtils accountUtils) {
    this.accountUtils = accountUtils;
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(method = RequestMethod.GET, path = RECOVERY_CODE_RESET_URL)
  public String getResetRecoveryCodesResetView() {
    return RECOVERY_CODE_RESET_URL;
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(method = RequestMethod.GET, path = RECOVERY_CODE_VIEW_URL)
  public String viewRecoveryCodes(ModelMap model) {
    String[] codes = getRecoveryCodes();

    model.addAttribute("recoveryCodes", codes);
    return RECOVERY_CODE_VIEW_URL;
  }

  @PreAuthorize("hasRole('USER')")
  @RequestMapping(method = RequestMethod.GET, path = RECOVERY_CODE_GET_URL)
  public @ResponseBody String[] getRecoveryCodes() {
    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(() -> new MultiFactorAuthenticationError("Account not found"));

    if (account.getTotpMfa() == null || !account.getTotpMfa().isActive()) {
      throw new NoMultiFactorSecretError(
          "No multi-factor secret is associated with account " + account.getUsername());
    }

    List<IamTotpRecoveryCode> recs = new ArrayList<>(account.getTotpMfa().getRecoveryCodes());
    String[] codes = new String[recs.size()];

    for (int i = 0; i < recs.size(); i++) {
      codes[i] = recs.get(i).getCode();
    }

    return codes;
  }

  @ResponseStatus(code = HttpStatus.BAD_REQUEST)
  @ExceptionHandler(MultiFactorAuthenticationError.class)
  @ResponseBody
  public ErrorDTO handleMultiFactorAuthenticationError(MultiFactorAuthenticationError e) {
    return ErrorDTO.fromString(e.getMessage());
  }

  @ResponseStatus(code = HttpStatus.NOT_FOUND)
  @ExceptionHandler(NoMultiFactorSecretError.class)
  @ResponseBody
  public ErrorDTO handleNoMultiFactorSecretError(NoMultiFactorSecretError e) {
    return ErrorDTO.fromString(e.getMessage());
  }
}
