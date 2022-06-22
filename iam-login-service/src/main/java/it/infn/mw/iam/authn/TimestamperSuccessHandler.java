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
package it.infn.mw.iam.authn;

import static org.slf4j.LoggerFactory.getLogger;

import java.io.IOException;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.slf4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import it.infn.mw.iam.core.util.IamAuthenticationLogger;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@SuppressWarnings("deprecation")
public class TimestamperSuccessHandler implements AuthenticationSuccessHandler {

  public static final Logger LOG = getLogger(TimestamperSuccessHandler.class);
  private final AuthenticationSuccessHandler delegate;
  
  private final IamAccountRepository accountRepository;
  
  public TimestamperSuccessHandler(AuthenticationSuccessHandler delegate,
      IamAccountRepository accountRepository) {
    this.delegate = delegate;
    this.accountRepository = accountRepository;
  }

  protected void setAuthenticationTimestamp(HttpServletRequest request,
      HttpServletResponse response, Authentication authentication) {

    Date timestamp = new Date();
    HttpSession session = request.getSession();
    session.setAttribute(AuthenticationTimeStamper.AUTH_TIMESTAMP, timestamp);
    IamAuthenticationLogger.INSTANCE.logAuthenticationSuccess(authentication);
  }

  protected void touchLastLoginTimeForIamAccount(Authentication authentication){
    if (authentication instanceof OAuth2Authentication){
      OAuth2Authentication oauth = (OAuth2Authentication) authentication;
      if (oauth.getUserAuthentication() != null){
        accountRepository.touchLastLoginTimeForUserWithUsername(oauth.getUserAuthentication().getName());
      }
    }else {
      accountRepository.touchLastLoginTimeForUserWithUsername(authentication.getName());
    }
  }
  
  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {

    delegate.onAuthenticationSuccess(request, response, authentication);
    setAuthenticationTimestamp(request, response, authentication);
    touchLastLoginTimeForIamAccount(authentication);

  }
}
