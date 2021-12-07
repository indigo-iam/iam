package it.infn.mw.iam.core.web.multi_factor_authentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.config.IamProperties.Logo;

import com.google.common.base.Strings;

@Component
public class DefaultMultiFactorVerificationPageConfiguration
    implements MultiFactorVerificationPageConfiguration {

  private final IamProperties iamProperties;

  public static final String DEFAULT_VERIFICATION_BUTTON_TEXT = "Verify";

  @Autowired
  public DefaultMultiFactorVerificationPageConfiguration(IamProperties properties) {
    this.iamProperties = properties;
  }

  @Override
  public Logo getLogo() {
    return iamProperties.getLogo();
  }

  @Override
  public String getVerifyButtonText() {
    if (Strings.isNullOrEmpty(iamProperties.getVerifyButton().getText())) {
      return DEFAULT_VERIFICATION_BUTTON_TEXT;
    }
    return iamProperties.getVerifyButton().getText();
  }

}
