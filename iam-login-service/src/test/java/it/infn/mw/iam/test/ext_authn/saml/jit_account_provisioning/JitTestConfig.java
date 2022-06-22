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
package it.infn.mw.iam.test.ext_authn.saml.jit_account_provisioning;

import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import it.infn.mw.iam.audit.events.account.AccountCreatedEvent;

@Configuration
public class JitTestConfig {

  public static class CountAccountCreatedEventsListener
      implements ApplicationListener<AccountCreatedEvent> {

    long eventCount = 0;

    @Override
    public void onApplicationEvent(AccountCreatedEvent event) {
      eventCount++;
    }

    public void resetCount() {
      eventCount = 0;
    }

    public long getCount() {
      return eventCount;
    }

  }

  public JitTestConfig() {}

  @Bean
  public CountAccountCreatedEventsListener accountCreatedEventiListener() {
    return new CountAccountCreatedEventsListener();
  }

}
