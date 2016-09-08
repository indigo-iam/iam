package it.infn.mw.iam.core.web.view;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mitre.openid.connect.view.UserInfoView;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import com.google.gson.JsonObject;

@Primary
@Component(IamUserInfoView.VIEWNAME)
public class IamUserInfoView extends UserInfoView {

  public static final String VIEWNAME = "iamUserInfo";

  public static final String EXTN_AUTHN_INFO_KEY = "external_authn";

  protected void addExternalAuthenticationInfo(JsonObject json, Map<String, Object> model) {

    Map<String, String> externalAuthnInfo = (Map<String, String>) model.get(EXTN_AUTHN_INFO_KEY);

    JsonObject extAuthn = new JsonObject();
    for (Map.Entry<String, String> e : externalAuthnInfo.entrySet()) {
      extAuthn.addProperty(e.getKey(), e.getValue());
    }

    json.add(EXTN_AUTHN_INFO_KEY, extAuthn);
  }

  @Override
  protected void writeOut(JsonObject json, Map<String, Object> model, HttpServletRequest request,
      HttpServletResponse response) {

    if (model.containsKey(EXTN_AUTHN_INFO_KEY)) {
      addExternalAuthenticationInfo(json, model);
    }

    super.writeOut(json, model, request, response);
  }

}
