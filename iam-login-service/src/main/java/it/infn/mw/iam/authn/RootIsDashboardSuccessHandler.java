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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

public class RootIsDashboardSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

  public static final String DASHBOARD_URL = "/dashboard";

  private final RequestCache requestCache;

  private final String iamBaseUrl;

  public RootIsDashboardSuccessHandler(String iamBaseUrl, RequestCache cache) {
    setRequestCache(cache);
    this.requestCache = cache;
    setDefaultTargetUrl(DASHBOARD_URL);
    this.iamBaseUrl = iamBaseUrl;
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws ServletException, IOException {

    SavedRequest savedRequest = requestCache.getRequest(request, response);

    if (savedRequest == null) {
      super.onAuthenticationSuccess(request, response, authentication);
      return;
    }

    if (savedRequest.getRedirectUrl().equals(iamBaseUrl)) {
      requestCache.removeRequest(request, response);
    }

    if (savedRequest.getRedirectUrl().equals(iamBaseUrl + "/")) {
      requestCache.removeRequest(request, response);
    }

    super.onAuthenticationSuccess(request, response, authentication);
  }

}
