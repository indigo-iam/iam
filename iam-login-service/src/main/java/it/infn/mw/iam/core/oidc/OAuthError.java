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

import static org.mitre.openid.connect.request.ConnectRequestParameters.ERROR;
import static org.mitre.openid.connect.request.ConnectRequestParameters.STATE;

import java.io.IOException;
import java.net.URISyntaxException;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.http.client.utils.URIBuilder;

import com.google.common.base.Strings;

public class OAuthError {

  private OAuthError() {
    // Add a private constructor to hide the implicit public one.
  }

  public static void sendAuthenticationError(HttpServletResponse response, String redirectUri,
      String state, String error, String description) throws IOException {

    if (!Strings.isNullOrEmpty(redirectUri)) {

      try {

        URIBuilder uriBuilder = new URIBuilder(redirectUri);

        uriBuilder.addParameter(ERROR, error);

        if (!Strings.isNullOrEmpty(description)) {
          uriBuilder.addParameter("error_description", description);
        }

        if (!Strings.isNullOrEmpty(state)) {
          uriBuilder.addParameter(STATE, state);
        }

        response.sendRedirect(uriBuilder.build().toString());

      } catch (URISyntaxException e) {

        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "invalid_redirect_uri");
      }

    } else {

      response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
      response.setContentType("text/html;charset=UTF-8");

      response.getWriter()
        .write(
            "<html><head><title>OAuth Error</title></head><body>" + "<h2>Authorization Error</h2>"
                + "<p><strong>error:</strong> " + StringEscapeUtils.escapeHtml(error) + "</p>"
                + "<p><strong>error_description:</strong> "
                + StringEscapeUtils.escapeHtml(description) + "</p>" + "</body></html>");
      response.flushBuffer();
    }
  }
}
