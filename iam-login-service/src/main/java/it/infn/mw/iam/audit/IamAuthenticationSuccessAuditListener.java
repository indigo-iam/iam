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
package it.infn.mw.iam.audit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.audit.events.auth.IamAuthenticationSuccessEvent;

@Component
public class IamAuthenticationSuccessAuditListener
    implements ApplicationListener<AbstractAuthenticationEvent> {

  private final AuditEventLogger logger;

  @Autowired
  public IamAuthenticationSuccessAuditListener(AuditEventLogger logger) {
    this.logger = logger;
  }

  @Override
  public void onApplicationEvent(AbstractAuthenticationEvent event) {

    if ((event instanceof AuthenticationSuccessEvent)
        || (event instanceof InteractiveAuthenticationSuccessEvent)) {
      IamAuthenticationSuccessEvent ev = new IamAuthenticationSuccessEvent(event);
      logger.logAuditEvent(ev);
    }

  }

}

