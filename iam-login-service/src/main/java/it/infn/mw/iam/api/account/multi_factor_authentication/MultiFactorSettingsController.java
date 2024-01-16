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
package it.infn.mw.iam.api.account.multi_factor_authentication;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import it.infn.mw.iam.api.common.NoSuchAccountError;
import it.infn.mw.iam.config.mfa.IamTotpMfaProperties;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamTotpMfa;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;
import it.infn.mw.iam.persistence.repository.IamTotpMfaRepository;

/**
 * Controller for retrieving all multi-factor settings for a user account
 */
@SuppressWarnings("deprecation")
@Controller
public class MultiFactorSettingsController {

  public static final String MULTI_FACTOR_SETTINGS_URL = "/iam/multi-factor-settings";
  private final IamAccountRepository accountRepository;
  private final IamTotpMfaRepository totpMfaRepository;
  private final IamTotpMfaProperties iamTotpMfaProperties;

  @Autowired
  public MultiFactorSettingsController(IamAccountRepository accountRepository,
      IamTotpMfaRepository totpMfaRepository,
      IamTotpMfaProperties iamTotpMfaProperties) {
    this.accountRepository = accountRepository;
    this.totpMfaRepository = totpMfaRepository;
    this.iamTotpMfaProperties = iamTotpMfaProperties;
  }


  /**
   * Retrieve info about MFA settings and return them in a DTO
   * 
   * @return MultiFactorSettingsDTO the MFA settings for the account
   */
  @PreAuthorize("hasRole('USER')")
  @RequestMapping(value = MULTI_FACTOR_SETTINGS_URL, method = RequestMethod.GET,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ResponseBody
  public MultiFactorSettingsDTO getMultiFactorSettings() {

    final String username = getUsernameFromSecurityContext();
    IamAccount account = accountRepository.findByUsername(username)
      .orElseThrow(() -> NoSuchAccountError.forUsername(username));
    Optional<IamTotpMfa> totpMfaOptional = totpMfaRepository.findByAccount(account);
    MultiFactorSettingsDTO dto = new MultiFactorSettingsDTO();
    if (totpMfaOptional.isPresent()) {
      IamTotpMfa totpMfa = totpMfaOptional.get();
      dto.setAuthenticatorAppActive(totpMfa.isActive());
    } else {
      dto.setAuthenticatorAppActive(false);
    }

    // add further factors if/when implemented
    if (iamTotpMfaProperties.getPasswordToEncryptOrDecrypt().length() > 15) {
      dto.setMfaFeatureDisabled(false);
    } else {
      dto.setMfaFeatureDisabled(true);
    }

    return dto;
  }


  /**
   * Fetch and return the logged-in username from security context
   * 
   * @return String username
   */
  private String getUsernameFromSecurityContext() {

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth instanceof OAuth2Authentication) {
      OAuth2Authentication oauth = (OAuth2Authentication) auth;
      auth = oauth.getUserAuthentication();
    }
    return auth.getName();
  }
}
