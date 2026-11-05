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

import static it.infn.mw.iam.core.oauth.IamOAuthRequestParameters.RESOURCE_KEY;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

/**
 * RFC 8707 requests multiple resources by repeating the <code>resource</code> parameter, but the
 * OAuth endpoints only see the first value of each parameter. This filter joins the repeated values
 * into the space-separated form already understood by IAM, so that every requested resource is
 * validated and ends up in the token audience.
 */
public class RepeatedResourceParameterFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain) throws ServletException, IOException {

    String[] values = request.getParameterValues(RESOURCE_KEY);

    if (values == null || values.length < 2) {
      chain.doFilter(request, response);
    } else {
      chain.doFilter(new JoinedResourceRequest(request, String.join(" ", values)), response);
    }
  }

  private static class JoinedResourceRequest extends HttpServletRequestWrapper {

    private final String resource;
    private final Map<String, String[]> parameterMap;

    JoinedResourceRequest(HttpServletRequest request, String resource) {
      super(request);
      this.resource = resource;
      Map<String, String[]> params = new LinkedHashMap<>(request.getParameterMap());
      params.put(RESOURCE_KEY, new String[] {resource});
      this.parameterMap = Collections.unmodifiableMap(params);
    }

    @Override
    public String getParameter(String name) {
      return RESOURCE_KEY.equals(name) ? resource : super.getParameter(name);
    }

    @Override
    public String[] getParameterValues(String name) {
      return RESOURCE_KEY.equals(name) ? new String[] {resource} : super.getParameterValues(name);
    }

    @Override
    public Map<String, String[]> getParameterMap() {
      return parameterMap;
    }
  }
}
