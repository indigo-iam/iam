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
package it.infn.mw.iam.rcauth;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
@ConditionalOnProperty(name = "rcauth.enabled", havingValue = "true")
@Order(110)
public class RCAuthSecurityConfig extends WebSecurityConfigurerAdapter {

 
  public LoginUrlAuthenticationEntryPoint authenticationEntryPoint() {
    return new LoginUrlAuthenticationEntryPoint("/login");
  }
  
  @Override
  protected void configure(final HttpSecurity http) throws Exception {
    // @formatter:off
    http
      .requestMatchers()
        .antMatchers("/rcauth/**", "/rcauth**")
      .and()
        .exceptionHandling()
          .authenticationEntryPoint(authenticationEntryPoint())
      .and()
        .authorizeRequests()
          .antMatchers("/rcauth/**","/rcauth**")
            .hasRole("USER");
    // @formatter:on
  }

}
