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

import static org.springframework.http.HttpMethod.POST;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@Order(18)
public class IamFederationRegistrationSecurityConfig extends WebSecurityConfigurerAdapter {

  private static final String ENDPOINT = "/iam/api/oid-fed/client-registration";

  @Override
  protected void configure(HttpSecurity http) throws Exception {

    http.antMatcher(ENDPOINT)

      .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

      .requestCache(cache -> cache.disable())

      .cors(Customizer.withDefaults())

      .authorizeRequests(
          authorize -> authorize.antMatchers(POST, ENDPOINT).permitAll().anyRequest().denyAll())

      .csrf(csrf -> csrf.disable());
  }
}
