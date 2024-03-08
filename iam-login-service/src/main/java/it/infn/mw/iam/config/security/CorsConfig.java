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
package it.infn.mw.iam.config.security;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@ConfigurationProperties("cors")
@Configuration
public class CorsConfig {

  private static final String[] CORS_ENDPOINT_MATCHERS =
  // @formatter:off
    {
        "/api/**",
        "/resource/**",
        "/register/**",
        "/iam/**",
        "/scim/**",
        "/token",
        "/introspect",
        "/userinfo",
        "/revoke/**",
        "/jwk",
        "/devicecode",
        "/.well-known/openid-configuration"
    };
    //@formatter:on

  private List<String> allowedOrigins;

  public List<String> getAllowedOrigins() {
    return allowedOrigins;
  }

  public void setAllowedOrigins(List<String> allowedOrigins) {
    this.allowedOrigins = allowedOrigins;
  }

  @Bean
  CorsFilter corsFilter() {

    CorsConfiguration corsConfig = new CorsConfiguration();
    corsConfig.setAllowedMethods(
        java.util.List.of("HEAD", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
    corsConfig.applyPermitDefaultValues();
    corsConfig.setAllowedOriginPatterns(allowedOrigins);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    for (String m : CORS_ENDPOINT_MATCHERS) {
      source.registerCorsConfiguration(m, corsConfig);
    }

    return new CorsFilter(source);
  }
}
