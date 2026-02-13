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
package it.infn.mw.iam.config;

import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@Profile("openid-federation")
public class BasicAuthLoggingFilter extends OncePerRequestFilter {

  private static final Logger log = LoggerFactory.getLogger(BasicAuthLoggingFilter.class);

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    if (log.isDebugEnabled()) {

      // Hierarchical dump of all headers
      Enumeration<String> headerNames = request.getHeaderNames();

      if (headerNames != null) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Incoming Request Headers ===\n");
        sb.append(request.getMethod()).append(" ").append(request.getRequestURI()).append("\n");

        while (headerNames.hasMoreElements()) {
          String name = headerNames.nextElement();

          Enumeration<String> values = request.getHeaders(name);
          while (values.hasMoreElements()) {
            sb.append(name).append(": ").append(values.nextElement()).append("\n");
          }
        }

        log.debug(sb.toString());
      }
    }

    filterChain.doFilter(request, response);
  }
}
