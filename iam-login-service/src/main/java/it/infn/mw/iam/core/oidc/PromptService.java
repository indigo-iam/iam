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
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.stereotype.Service;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;

import it.infn.mw.iam.persistence.model.ClientDetailsEntity;

@SuppressWarnings("deprecation")
@Service
public class PromptService {

  private final RedirectResolver redirectResolver;

  public PromptService(RedirectResolver redirectResolver) {
    this.redirectResolver = redirectResolver;
  }

  public boolean handlePrompt(Map<String, String> params, Optional<ClientDetailsEntity> client,
      HttpSession session, HttpServletRequest request, HttpServletResponse response,
      FilterChain chain) throws IOException, ServletException {

    String prompt = params.get(ConnectRequestParameters.PROMPT);

    if (prompt == null) {
      return true;
    }

    List<String> prompts = Splitter.on(ConnectRequestParameters.PROMPT_SEPARATOR)
      .splitToList(Strings.nullToEmpty(prompt));

    if (prompts.contains(ConnectRequestParameters.PROMPT_NONE)) {

      Authentication auth = SecurityContextHolder.getContext().getAuthentication();

      if (auth != null) {
        chain.doFilter(request, response);
        return false;
      }

      if (client.isPresent() && params.get(ConnectRequestParameters.REDIRECT_URI) != null) {

        String url = redirectResolver
          .resolveRedirect(params.get(ConnectRequestParameters.REDIRECT_URI), client.get());

        OAuthError.sendAuthenticationError(response, url,
            params.get(ConnectRequestParameters.STATE), ConnectRequestParameters.LOGIN_REQUIRED,
            null);

        return false;
      }

      response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");

      return false;
    }

    if (prompts.contains(ConnectRequestParameters.PROMPT_LOGIN)) {

      if (session.getAttribute(ConnectRequestParameters.PROMPTED) == null) {

        session.setAttribute(ConnectRequestParameters.PROMPT_REQUESTED, Boolean.TRUE);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null) {
          SecurityContextHolder.getContext().setAuthentication(null);
        }

      } else {
        session.removeAttribute(ConnectRequestParameters.PROMPTED);
      }

      chain.doFilter(request, response);
      return false;
    }

    return true;
  }
}
