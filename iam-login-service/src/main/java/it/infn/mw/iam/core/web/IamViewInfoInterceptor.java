package it.infn.mw.iam.core.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import it.infn.mw.iam.core.IamProperties;

@Component
public class IamViewInfoInterceptor extends HandlerInterceptorAdapter {

  public static final String LOGIN_PAGE_CONFIGURATION_KEY = "loginPageConfiguration";
  public static final String IAM_PROPERTIES_KEY = "iamProperties";

  @Value("${iam.version}")
  String iamVersion;

  @Value("${git.commit.id.abbrev}")
  String gitCommitId;

  @Autowired
  LoginPageConfiguration loginPageConfiguration;

  @Autowired
  IamProperties properties;

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
      throws Exception {

    request.setAttribute("iamVersion", iamVersion);
    request.setAttribute("gitCommitId", gitCommitId);

    request.setAttribute(LOGIN_PAGE_CONFIGURATION_KEY, loginPageConfiguration);
    request.setAttribute(IAM_PROPERTIES_KEY, properties);

    return true;
  }

}
