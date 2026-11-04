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
package it.infn.mw.iam.core.oauth;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Adds the RFC 9728 (Section 5.1) <code>resource_metadata</code> parameter to the bearer
 * challenge returned when a request to an IAM protected resource is not authenticated.
 *
 * The same entry point also handles client authentication failures on the authorization server
 * endpoints (token, introspection, revocation); those are not protected resources, so the
 * parameter is not added there.
 */
@SuppressWarnings("deprecation")
public class ProtectedResourceAuthenticationEntryPoint extends OAuth2AuthenticationEntryPoint {

  private static final RequestMatcher AUTHORIZATION_SERVER_ENDPOINTS =
      new OrRequestMatcher(new AntPathRequestMatcher("/token"),
          new AntPathRequestMatcher("/introspect/**"), new AntPathRequestMatcher("/revoke**"));

  private final String resourceMetadataParam;

  public ProtectedResourceAuthenticationEntryPoint(String resourceMetadataUrl) {
    this.resourceMetadataParam = String.format("resource_metadata=\"%s\"", resourceMetadataUrl);
  }

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException) throws IOException, ServletException {

    if (AUTHORIZATION_SERVER_ENDPOINTS.matches(request)) {
      super.commence(request, response, authException);
    } else {
      super.commence(request, new ResourceMetadataChallengeResponse(response), authException);
    }
  }

  private class ResourceMetadataChallengeResponse extends HttpServletResponseWrapper {

    ResourceMetadataChallengeResponse(HttpServletResponse response) {
      super(response);
    }

    private String withResourceMetadata(String name, String value) {
      if (!HttpHeaders.WWW_AUTHENTICATE.equalsIgnoreCase(name)
          || !value.regionMatches(true, 0, "Bearer", 0, 6)) {
        return value;
      }
      return value.trim().equalsIgnoreCase("Bearer") ? value + " " + resourceMetadataParam
          : value + ", " + resourceMetadataParam;
    }

    @Override
    public void setHeader(String name, String value) {
      super.setHeader(name, withResourceMetadata(name, value));
    }

    @Override
    public void addHeader(String name, String value) {
      super.addHeader(name, withResourceMetadata(name, value));
    }
  }
}
