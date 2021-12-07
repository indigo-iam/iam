package it.infn.mw.iam.core.web.multi_factor_authentication;

import it.infn.mw.iam.config.IamProperties.Logo;

public interface MultiFactorVerificationPageConfiguration {

  String getVerifyButtonText();

  Logo getLogo();
}
