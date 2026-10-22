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
package it.infn.mw.iam.jwkfallback;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.info.InfoEndpoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class FallbackSecurityConfig {

    @Bean
    SecurityFilterChain fallbackFilterChain(HttpSecurity http) throws Exception {
        http
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeRequests(auth -> auth
                        .antMatchers("/jwk", "/fallback-info").permitAll()
                        .requestMatchers(
                                EndpointRequest.toLinks(),
                                EndpointRequest.to(HealthEndpoint.class, InfoEndpoint.class))
                        .permitAll()
                        .anyRequest().denyAll())
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(this::handleDenied)
                        .accessDeniedHandler(this::handleDenied));
        return http.build();
    }

    private void handleDenied(HttpServletRequest request, HttpServletResponse response,
            Exception ex) throws IOException {

        response.setHeader("Cache-Control", "no-store");
        // Attempt to redirect if it looks like a browser
        if (looksLikeBrowserNavigation(request)) {
            response.sendRedirect(request.getContextPath() + "/fallback-info");
        //Otherwise just send error
        } else {
            response.setHeader("Retry-After", "300");
            response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }
    }

    private boolean looksLikeBrowserNavigation(HttpServletRequest request) {
        if (!"GET".equals(request.getMethod())) {
            return false;
        }
        String fetchMode = request.getHeader("Sec-Fetch-Mode");
        if (fetchMode != null) {
            return "navigate".equals(fetchMode);
        }
        String accept = request.getHeader(HttpHeaders.ACCEPT);
        return accept != null && accept.contains("text/html");
    }
}
