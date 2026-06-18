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
package it.infn.mw.iam.test.util.oauth;

import org.mitre.oauth2.service.SystemScopeService;

import it.infn.mw.iam.test.oauth.scope.StructuredScopeTestSupportConstants;

public class SecurityContextUtils implements StructuredScopeTestSupportConstants {

  protected MockOAuth2Filter authFilter;

  protected MockOAuthSecurityContextService securityService;

  public SecurityContextUtils(MockOAuth2Filter authFilter,
      MockOAuthSecurityContextService securityService) {

    this.authFilter = authFilter;
    this.securityService = securityService;
  }

  public void cleanupSecurityContext() {
    authFilter.cleanupSecurityContext();
  }

  public void useLocalAdminUser() {
    useLocalAdminUser(PASSWORD_CLIENT_ID);
  }

  public void useLocalAdminUser(String clientId) {
    useLocalUser(ADMIN_USERNAME, clientId, new String[] {"ROLE_USER", "ROLE_ADMIN"});
  }

  public void useLocalUser(String username, String clientId, String[] authorities) {
    securityService.authenticate(clientId, username, null, authorities, false, null);
  }

  public void useBearerAdminToken() {
    useBearerAdminToken(PASSWORD_CLIENT_ID);
  }

  public void useBearerAdminToken(String clientId) {
    useBearerAdminToken(clientId, new String[] {"iam:admin.read", "iam:admin.write"});
  }

  public void useBearerAdminToken(String clientId, String[] scopes) {
    useBearerToken(clientId, ADMIN_USERNAME, new String[] {"ROLE_USER", "ROLE_ADMIN"}, scopes);
  }

  public void useLocalTestUser() {
    useLocalTestUser(PASSWORD_CLIENT_ID);
  }

  public void useLocalTestUser(String clientId) {
    useLocalUser(TEST_USERNAME, clientId, new String[] {"ROLE_USER"});
  }

  public void useAnotherLocalUser(String clientId) {
    useLocalUser(ANOTHER_USERNAME, clientId, new String[] {"ROLE_USER"});
  }

  public void useBearerTestToken(String[] scopes) {
    useBearerTestToken(PASSWORD_CLIENT_ID, scopes);
  }

  public void useBearerTestToken(String clientId, String[] scopes) {
    useBearerToken(clientId, TEST_USERNAME, new String[] {"ROLE_USER"}, scopes);
  }

  public void useBearerRegistrationAccessToken(String clientId) {
    useBearerToken(clientId, null, new String[] {"ROLE_CLIENT"},
        new String[] {SystemScopeService.REGISTRATION_TOKEN_SCOPE});
  }

  public void useBearerClientToken() {
    useBearerClientToken(new String[] {"openid", "profile"});
  }

  public void useBearerClientToken(String[] scopes) {
    useBearerClientToken(CLIENT_CREDENTIALS_CLIENT_ID, scopes);
  }

  public void useBearerClientToken(String clientId, String[] scopes) {
    useBearerToken(clientId, null, new String[] {"ROLE_CLIENT"}, scopes);
  }

  public void useBearerToken(String clientId, String username, String[] authorities,
      String[] scopes) {
    securityService.authenticate(clientId, username, scopes, authorities, false, null);
  }
}
