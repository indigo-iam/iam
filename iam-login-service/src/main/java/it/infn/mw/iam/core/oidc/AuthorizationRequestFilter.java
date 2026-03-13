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

import static org.mitre.openid.connect.request.ConnectRequestParameters.CLIENT_ID;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.mitre.oauth2.model.ClientDetailsEntity;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.GenericFilterBean;

public class AuthorizationRequestFilter extends GenericFilterBean {

  private final AuthorizationClientResolver clientResolver;
  private final LoginHintService loginHintService;
  private final PromptService promptService;
  private final MaxAgeService maxAgeService;

  private RequestMatcher requestMatcher =
      new AntPathRequestMatcher("/authorize");

  public AuthorizationRequestFilter(
      AuthorizationClientResolver clientResolver,
      LoginHintService loginHintService,
      PromptService promptService,
      MaxAgeService maxAgeService) {

    this.clientResolver = clientResolver;
    this.loginHintService = loginHintService;
    this.promptService = promptService;
    this.maxAgeService = maxAgeService;
  }

  @Override
  public void doFilter(
      ServletRequest req,
      ServletResponse res,
      FilterChain chain) throws IOException, ServletException {

    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) res;

    if (!requestMatcher.matches(request)) {
      chain.doFilter(req, res);
      return;
    }

    HttpSession session = request.getSession();
    Map<String,String> params = createRequestMap(request.getParameterMap());

    String clientId = params.get(CLIENT_ID);

    Optional<ClientDetailsEntity> client =
        clientResolver.resolveClient(clientId, params, response);

    if (response.isCommitted()) {
      return;
    }

    if (clientId != null && client.isEmpty()) {
      OAuthError.sendAuthenticationError(
          response, null, null, "invalid_client", "Unknown client");
      return;
    }

    loginHintService.handleLoginHint(params, session);

    if (!promptService.handlePrompt(
            params, client, session, request, response, chain)) {
      return;
    }

    maxAgeService.enforceMaxAge(params, client, session);

    chain.doFilter(req, res);
  }

  private Map<String,String> createRequestMap(
      Map<String,String[]> parameterMap) {

    Map<String,String> requestMap = new HashMap<>();

    parameterMap.forEach((k,v) -> {
      if (v != null && v.length > 0) {
        requestMap.put(k, v[0]);
      }
    });

    return requestMap;
  }
}
