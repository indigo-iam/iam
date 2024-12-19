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
package it.infn.mw.iam.config;

import static it.infn.mw.iam.authn.multi_factor_authentication.MfaVerifyController.MFA_VERIFY_URL;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.account.multi_factor_authentication.IamTotpMfaService;
import it.infn.mw.iam.service.aup.AUPSignatureCheckService;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorTotpCheckProvider;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorVerificationFilter;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorVerificationSuccessHandler;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

/**
 * Beans for handling TOTP MFA functionality
 */
@Configuration
public class IamTotpMfaConfig {

  @Value("${iam.baseUrl}")
  private String iamBaseUrl;

  @Autowired
  private IamAccountRepository accountRepo;

  @Autowired
  private AUPSignatureCheckService aupSignatureCheckService;

  @Autowired
  private AccountUtils accountUtils;

  /**
   * Responsible for generating new TOTP secrets
   * 
   * @return SecretGenerator
   */
  @Bean
  @Qualifier("secretGenerator")
  SecretGenerator secretGenerator() {
    return new DefaultSecretGenerator();
  }


  /**
   * Responsible for generating QR code data URI strings from given input parameters, e.g. TOTP
   * secret, issuer, etc.
   * 
   * @return QrGenerator
   */
  @Bean
  @Qualifier("qrGenerator")
  QrGenerator qrGenerator() {
    return new ZxingPngQrGenerator();
  }


  /**
   * Generates a TOTP from an MFA secret and verifies a user-provided TOTP matches it
   * 
   * @return CodeVerifier
   */
  @Bean
  @Qualifier("codeVerifier")
  CodeVerifier codeVerifier() {
    return new DefaultCodeVerifier(new DefaultCodeGenerator(), new SystemTimeProvider());
  }

  @Bean(name = "MultiFactorVerificationFilter")
  MultiFactorVerificationFilter multiFactorVerificationFilter(
      @Qualifier("MultiFactorVerificationAuthenticationManager") AuthenticationManager authenticationManager) {

    return new MultiFactorVerificationFilter(authenticationManager, successHandler(),
        failureHandler());
  }

  /**
   * Authentication manager for the MFA verification process
   * 
   * @param totpCheckProvider checks a provided TOTP
   * @return a new provider manager
   */
  @Bean(name = "MultiFactorVerificationAuthenticationManager")
  AuthenticationManager authenticationManager(MultiFactorTotpCheckProvider totpCheckProvider) {
    return new ProviderManager(Arrays.asList(totpCheckProvider));
  }

  public AuthenticationSuccessHandler successHandler() {
    return new MultiFactorVerificationSuccessHandler(accountUtils, aupSignatureCheckService,
        accountRepo, iamBaseUrl);
  }

  /**
   * If we can't verify the user in step-up authentication, redirect back to the /verify endpoint
   * with an error param
   * 
   * @return failure handler to redirect to /verify endpoint
   */
  public AuthenticationFailureHandler failureHandler() {
    return new SimpleUrlAuthenticationFailureHandler(MFA_VERIFY_URL + "?error=failure");
  }

  @Bean
  MultiFactorTotpCheckProvider totpCheckProvider(IamTotpMfaService totpMfaService) {
    return new MultiFactorTotpCheckProvider(accountRepo, totpMfaService);
  }

}
