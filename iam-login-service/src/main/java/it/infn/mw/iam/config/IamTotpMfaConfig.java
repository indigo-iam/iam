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

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.recovery.RecoveryCodeGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;

// TODO add admin config options from properties file

/**
 * Beans for handling TOTP MFA functionality
 */
@Configuration
public class IamTotpMfaConfig {


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
}
