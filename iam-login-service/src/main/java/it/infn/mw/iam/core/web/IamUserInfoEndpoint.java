package it.infn.mw.iam.core.web;

import static it.infn.mw.iam.authn.util.AuthenticationUtils.isSupportedExternalAuthenticationToken;

import java.util.Map;

import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.service.UserInfoService;
import org.mitre.openid.connect.view.HttpCodeView;
import org.mitre.openid.connect.view.UserInfoView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.google.common.base.Strings;

import it.infn.mw.iam.authn.ExternalAuthenticationInfoProcessor;
import it.infn.mw.iam.core.web.view.IamUserInfoView;

@Controller
@RequestMapping("/userinfo")
public class IamUserInfoEndpoint {

  @Autowired
  private UserInfoService userInfoService;

  @Autowired
  private ExternalAuthenticationInfoProcessor extAuthnInfoProcessor;

  private static final Logger LOG = LoggerFactory.getLogger(IamUserInfoEndpoint.class);



  private void processExternalAuthenticationInfo(OAuth2Authentication auth, Model model) {

    if (isSupportedExternalAuthenticationToken(auth.getUserAuthentication())) {

      Map<String, String> processedAuthInfo = extAuthnInfoProcessor.process(auth);

      if (!processedAuthInfo.isEmpty()) {
        model.addAttribute(IamUserInfoView.EXTN_AUTHN_INFO_KEY, processedAuthInfo);
      }
    }
  }


  @PreAuthorize("hasRole('ROLE_USER') and #oauth2.hasScope('" + SystemScopeService.OPENID_SCOPE
      + "')")
  @RequestMapping(method = {RequestMethod.GET, RequestMethod.POST},
      produces = {MediaType.APPLICATION_JSON_VALUE})
  public String getInfo(
      @RequestParam(value = "claims", required = false) String claimsRequestJsonString,
      @RequestHeader(value = HttpHeaders.ACCEPT, required = false) String acceptHeader,
      OAuth2Authentication auth, Model model) {


    String username = auth.getName();

    UserInfo userInfo =
        userInfoService.getByUsernameAndClientId(username, auth.getOAuth2Request().getClientId());

    if (userInfo == null) {
      LOG.error("user not found: {}", username);
      model.addAttribute(HttpCodeView.CODE, HttpStatus.NOT_FOUND);
      return HttpCodeView.VIEWNAME;
    }

    model.addAttribute(UserInfoView.SCOPE, auth.getOAuth2Request().getScope());

    model.addAttribute(UserInfoView.AUTHORIZED_CLAIMS,
        auth.getOAuth2Request().getExtensions().get("claims"));

    if (!Strings.isNullOrEmpty(claimsRequestJsonString)) {
      model.addAttribute(UserInfoView.REQUESTED_CLAIMS, claimsRequestJsonString);
    }

    model.addAttribute(UserInfoView.USER_INFO, userInfo);


    processExternalAuthenticationInfo(auth, model);


    return IamUserInfoView.VIEWNAME;
  }


}
