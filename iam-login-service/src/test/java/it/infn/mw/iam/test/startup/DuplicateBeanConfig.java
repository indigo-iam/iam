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
package it.infn.mw.iam.test.startup;

import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;

@SuppressWarnings("deprecation")
@Configuration
public class DuplicateBeanConfig {

  class TofuUserApprovalHandler implements UserApprovalHandler {

    @Override
    public boolean isApproved(AuthorizationRequest authorizationRequest,
        Authentication userAuthentication) {
      return true;
    }

    @Override
    public AuthorizationRequest checkForPreApproval(AuthorizationRequest authorizationRequest,
        Authentication userAuthentication) {
      return null;
    }

    @Override
    public AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest,
        Authentication userAuthentication) {
      return null;
    }

    @Override
    public Map<String, Object> getUserApprovalRequest(AuthorizationRequest authorizationRequest,
        Authentication userAuthentication) {
      return null;
    }
  }

  @Bean
  UserApprovalHandler userApprovalHandler2() {
    return new TofuUserApprovalHandler();
  }
}