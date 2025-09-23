package it.infn.mw.iam.core.oauth.profile.wlcg;

import static it.infn.mw.iam.core.oauth.profile.wlcg.WlcgExtraClaimNames.AUTH_TIME;
import static it.infn.mw.iam.core.oauth.profile.wlcg.WlcgExtraClaimNames.EDUPERSON_ASSURANCE;
import static it.infn.mw.iam.core.oauth.profile.wlcg.WlcgExtraClaimNames.WLCG_GROUPS;
import static it.infn.mw.iam.core.oauth.profile.wlcg.WlcgExtraClaimNames.WLCG_VER;

import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import it.infn.mw.iam.api.scim.converter.SshKeyConverter;
import it.infn.mw.iam.config.IamProperties;
import it.infn.mw.iam.core.oauth.attributes.AttributeMapHelper;
import it.infn.mw.iam.core.oauth.profile.aarc.AarcClaimValueHelper;
import it.infn.mw.iam.core.oauth.profile.iam.IamClaimValueHelper;
import it.infn.mw.iam.persistence.model.IamAccount;

@SuppressWarnings("deprecation")
public class WlcgClaimValueHelper extends IamClaimValueHelper {

  public WlcgClaimValueHelper(IamProperties properties, SshKeyConverter sshConverter,
      AttributeMapHelper attrHelper, ScopeClaimTranslationService scopeClaimTranslationService) {
    super(properties, sshConverter, attrHelper, scopeClaimTranslationService);
  }

  @Override
  public Object resolveClaim(String claimName, IamAccount account, OAuth2Authentication auth) {

    switch (claimName) {
      case WLCG_VER:
        return WlcgJWTProfile.PROFILE_VERSION;
      case WLCG_GROUPS:
        return WlcgGroupHelper.resolveGroupNames(auth.getOAuth2Request().getScope(),
            account.getUserInfo().getGroups());
      case EDUPERSON_ASSURANCE:
        return AarcClaimValueHelper.DEFAULT_LOA;
      case AUTH_TIME:
        return account.getLastLoginTime();
      default:
        return super.resolveClaim(claimName, account, auth);
    }
  }
}
