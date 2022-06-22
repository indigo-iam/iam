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
package it.infn.mw.iam.core.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

@SuppressWarnings("deprecation")
public enum IamAuthenticationLogger implements AuthenticationLogger {

  INSTANCE;

  private final Logger log = LoggerFactory.getLogger(IamAuthenticationLogger.class);

  @Override
  public void logAuthenticationSuccess(Authentication auth) {
    if (!(auth instanceof OAuth2Authentication)) {
      log.info("{} was authenticated succesfully", auth.getName());
      return;
    }

    final OAuth2Authentication oauth = (OAuth2Authentication) auth;
    final String clientName = oauth.getName();

    if (oauth.getUserAuthentication() != null) {
      final String userName = oauth.getUserAuthentication().getName();
      log.info("{} acting for {} was authenticated succesfully", clientName, userName);
    } else {
      log.info("Client {} was authenticated succesfully", clientName);
    }
  }

}
