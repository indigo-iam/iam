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
import dev.samstevens.totp.recovery.RecoveryCodeGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import it.infn.mw.iam.api.account.AccountUtils;
import it.infn.mw.iam.api.aup.AUPSignatureCheckService;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorRecoveryCodeCheckProvider;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorTotpCheckProvider;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorVerificationFilter;
import it.infn.mw.iam.authn.multi_factor_authentication.MultiFactorVerificationSuccessHandler;
import it.infn.mw.iam.authn.multi_factor_authentication.ResetOrSkipRecoveryCodesFilter;
import it.infn.mw.iam.authn.multi_factor_authentication.ViewRecoveryCodesFilter;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

// TODO add admin config options from properties file

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
  public SecretGenerator secretGenerator() {
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
  public QrGenerator qrGenerator() {
    return new ZxingPngQrGenerator();
  }


  /**
   * Generates a TOTP from an MFA secret and verifies a user-provided TOTP matches it
   * 
   * @return CodeVerifier
   */
  @Bean
  @Qualifier("codeVerifier")
  public CodeVerifier codeVerifier() {
    return new DefaultCodeVerifier(new DefaultCodeGenerator(), new SystemTimeProvider());
  }


  /**
   * Responsible for generating random recovery codes for backup authentication
   * 
   * @return RecoveryCodeGenerator
   */
  @Bean
  @Qualifier("recoveryCodeGenerator")
  public RecoveryCodeGenerator recoveryCodeGenerator() {
    return new RecoveryCodeGenerator();
  }

  @Bean(name = "MultiFactorVerificationFilter")
  public MultiFactorVerificationFilter multiFactorVerificationFilter(
      @Qualifier("MultiFactorVerificationAuthenticationManager") AuthenticationManager authenticationManager) {

    MultiFactorVerificationFilter filter = new MultiFactorVerificationFilter(authenticationManager,
        successHandler(), failureHandler());

    return filter;
  }

  @Bean(name = "ResetOrSkipRecoveryCodesFilter")
  public ResetOrSkipRecoveryCodesFilter resetOrSkipRecoveryCodesFilter() {

    ResetOrSkipRecoveryCodesFilter filter = new ResetOrSkipRecoveryCodesFilter(accountUtils,
        aupSignatureCheckService, accountRepo, iamBaseUrl);

    return filter;
  }

  @Bean(name = "ViewRecoveryCodesFilter")
  public ViewRecoveryCodesFilter viewRecoveryCodesFilter() {

    ViewRecoveryCodesFilter filter = new ViewRecoveryCodesFilter(accountUtils,
        aupSignatureCheckService, accountRepo, iamBaseUrl);

    return filter;
  }

  @Bean(name = "MultiFactorVerificationAuthenticationManager")
  public AuthenticationManager authenticationManager(MultiFactorTotpCheckProvider totpCheckProvider,
      MultiFactorRecoveryCodeCheckProvider recoveryCodeCheckProvider) {
    return new ProviderManager(Arrays.asList(totpCheckProvider, recoveryCodeCheckProvider));
  }

  public AuthenticationSuccessHandler successHandler() {
    return new MultiFactorVerificationSuccessHandler(accountUtils, aupSignatureCheckService,
        accountRepo, iamBaseUrl);
  }

  public AuthenticationFailureHandler failureHandler() {
    return new SimpleUrlAuthenticationFailureHandler("/iam/verify?error=failure");
  }

  @Bean
  public MultiFactorTotpCheckProvider totpCheckProvider(CodeVerifier codeVerifier) {
    return new MultiFactorTotpCheckProvider(accountRepo, codeVerifier);
  }

  @Bean
  public MultiFactorRecoveryCodeCheckProvider recoveryCodeCheckProvider() {
    return new MultiFactorRecoveryCodeCheckProvider(accountRepo);
  }
}
