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
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpRecoveryCodeResetService;
import it.infn.mw.iam.api.common.ErrorDTO;
import it.infn.mw.iam.authn.multi_factor_authentication.error.MultiFactorAuthenticationError;
import it.infn.mw.iam.authn.multi_factor_authentication.error.NoMultiFactorSecretError;
import it.infn.mw.iam.core.user.exception.MfaSecretNotFoundException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.model.IamTotpRecoveryCode;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

/**
 * Provides webpages related to recovery codes. Most of this appears if the user chooses to use a
 * recovery code in the MFA login flow. Also partially used in the multi-factor settings menu on the
 * dashboard.
 */
@Controller
public class RecoveryCodeManagementController {

  public static final String RECOVERY_CODE_RESET_URL = "/iam/authenticator-app/recovery-code/reset";
  public static final String RECOVERY_CODE_VIEW_URL = "/iam/authenticator-app/recovery-code/view";
  public static final String RECOVERY_CODE_GET_URL = "/iam/authenticator-app/recovery-code/get";

  private final AccountUtils accountUtils;
  private final IamTotpMfaRepository totpMfaRepository;
  private final IamTotpRecoveryCodeResetService recoveryCodeResetService;

  @Autowired
  public RecoveryCodeManagementController(AccountUtils accountUtils,
      IamTotpMfaRepository totpMfaRepository,
      IamTotpRecoveryCodeResetService recoveryCodeResetService) {
    this.accountUtils = accountUtils;
    this.totpMfaRepository = totpMfaRepository;
    this.recoveryCodeResetService = recoveryCodeResetService;
  }

  /**
   * @return page for asking if the user wishes to reset their recovery codes or skip this step
   */
  @PreAuthorize("hasRole('USER')")
  @RequestMapping(method = RequestMethod.GET, path = RECOVERY_CODE_RESET_URL)
  public String getResetRecoveryCodesResetView() {
    return RECOVERY_CODE_RESET_URL;
  }

  /**
   * Calls method to fetch account MFA recovery codes to display on returned page
   * 
   * @param model to add recovery codes array to
   * @return page for viewing account MFA recovery codes post-reset
   */
  @PreAuthorize("hasRole('USER')")
  @RequestMapping(method = RequestMethod.GET, path = RECOVERY_CODE_VIEW_URL)
  public String viewRecoveryCodes(ModelMap model) {
    String[] codes = getRecoveryCodes();

    model.addAttribute("recoveryCodes", codes);
    return RECOVERY_CODE_VIEW_URL;
  }

  /**
   * Populates and returns the array of recovery codes attached to the authenticated user account
   * Also called in the MFA settings menu for display
   * 
   * @return the array of recovery codes
   */
  @PreAuthorize("hasRole('USER')")
  @RequestMapping(method = RequestMethod.GET, path = RECOVERY_CODE_GET_URL)
  public @ResponseBody String[] getRecoveryCodes() {
    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(() -> new MultiFactorAuthenticationError("Account not found"));

    Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(account);
    if (!totpMfaOptional.isPresent()) {
      throw new MfaSecretNotFoundException("No multi-factor secret is attached to this account");
    }

    IamTotpMfa totpMfa = totpMfaOptional.get();
    if (!totpMfa.isActive()) {
      throw new MfaSecretNotFoundException("No multi-factor secret is attached to this account");
    }

    List<IamTotpRecoveryCode> recs = new ArrayList<>(totpMfa.getRecoveryCodes());
    String[] codes = new String[recs.size()];

    for (int i = 0; i < recs.size(); i++) {
      codes[i] = recs.get(i).getCode();
    }

    return codes;
  }

  /**
   * Request to reset the recovery codes on the authenticated account. TODO may wish to protect this
   * endpoint a bit more to prevent this being done outside of the regular flow
   * 
   * @return 200 response upon success
   */
  @PreAuthorize("hasRole('USER')")
  @RequestMapping(method = RequestMethod.PUT, path = RECOVERY_CODE_RESET_URL)
  public ResponseEntity<String> resetRecoveryCodes() {
    IamAccount account = accountUtils.getAuthenticatedUserAccount()
      .orElseThrow(() -> new MultiFactorAuthenticationError("Account not found"));

    recoveryCodeResetService.resetRecoveryCodes(account);

    return ResponseEntity.ok().build();
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
