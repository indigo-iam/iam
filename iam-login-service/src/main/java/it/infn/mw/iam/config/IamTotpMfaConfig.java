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

@Configuration
public class IamTotpMfaConfig {

  @Bean
  @Qualifier("secretGenerator")
  public SecretGenerator secretGenerator() {
    return new DefaultSecretGenerator();
  }

  @Bean
  @Qualifier("qrGenerator")
  public QrGenerator qrGenerator() {
    return new ZxingPngQrGenerator();
  }

  @Bean
  @Qualifier("codeVerifier")
  public CodeVerifier codeVerifier() {
    return new DefaultCodeVerifier(new DefaultCodeGenerator(), new SystemTimeProvider());
  }

  @Bean
  @Qualifier("recoveryCodeGenerator")
  public RecoveryCodeGenerator recoveryCodeGenerator() {
    return new RecoveryCodeGenerator();
  }
}
