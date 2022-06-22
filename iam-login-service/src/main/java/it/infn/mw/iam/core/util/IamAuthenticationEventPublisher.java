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

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class IamAuthenticationEventPublisher
    implements AuthenticationEventPublisher, ApplicationEventPublisherAware {

  private ApplicationEventPublisher eventPublisher;

  @Override
  public void publishAuthenticationSuccess(Authentication authentication) {
    IamAuthenticationLogger.INSTANCE.logAuthenticationSuccess(authentication);
    eventPublisher.publishEvent(new AuthenticationSuccessEvent(authentication));
  }

  @Override
  public void publishAuthenticationFailure(AuthenticationException exception,
      Authentication authentication) {
    eventPublisher
      .publishEvent(new AuthenticationFailureBadCredentialsEvent(authentication, exception));

  }

  @Override
  public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {

    eventPublisher = applicationEventPublisher;
  }

}
