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
package it.infn.mw.iam.core.oauth.profile.iam;

import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

public interface IamExtraClaimNames extends StandardClaimNames {

  String ACR = "acr";
  String ACT = "act";
  String AFFILIATION = "affiliation";
  String AMR = "amr";
  String ATTR = "attr";
  String CLIENT_ID = "client_id";
  String EXTERNAL_AUTHN = "external_authn";
  String GROUPS = "groups";
  String LAST_LOGIN_AT = "last_login_at";
  String SCOPE = "scope";
  String SSH_KEYS = "ssh_keys";
  String ORGANISATION_NAME = "organisation_name";
}
