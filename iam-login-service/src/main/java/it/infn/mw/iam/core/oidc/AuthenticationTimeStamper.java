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
package it.infn.mw.iam.core.oidc;

import java.io.IOException;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationTimeStamper extends SavedRequestAwareAuthenticationSuccessHandler {

  private static final Logger LOG = LoggerFactory.getLogger(AuthenticationTimeStamper.class);

  public static final String AUTH_TIMESTAMP = "AUTH_TIMESTAMP";

  /**
   * Set the TIMESTAMP on the session to mark when the authentication happened, useful for
   * calculating authentication age. This gets stored in the session and can get pulled out by other
   * components.
   */
  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {

    Date authTimestamp = new Date();

    HttpSession session = request.getSession();

    session.setAttribute(AUTH_TIMESTAMP, authTimestamp);

    if (session.getAttribute(ConnectRequestParameters.PROMPT_REQUESTED) != null) {
      session.setAttribute(ConnectRequestParameters.PROMPTED, Boolean.TRUE);
      session.removeAttribute(ConnectRequestParameters.PROMPT_REQUESTED);
    }

    LOG.info("Successful Authentication of {} at {}", authentication.getName(), authTimestamp);

    super.onAuthenticationSuccess(request, response, authentication);

  }

}
