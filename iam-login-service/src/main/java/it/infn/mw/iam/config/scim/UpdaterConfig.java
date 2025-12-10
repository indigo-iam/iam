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
package it.infn.mw.iam.config.scim;

import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_ADD_SSH_KEY;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_GROUP_MEMBERSHIP;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_OIDC_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_PICTURE;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_SAML_ID;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REMOVE_SSH_KEY;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_EMAIL;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_FAMILY_NAME;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_GIVEN_NAME;
import static it.infn.mw.iam.api.scim.updater.UpdaterType.ACCOUNT_REPLACE_PICTURE;

import java.util.EnumSet;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import it.infn.mw.iam.api.scim.updater.UpdaterType;
import it.infn.mw.iam.config.IamProperties;

@Configuration
public class UpdaterConfig {

  public static final EnumSet<UpdaterType> ACCOUNT_LINKING_UPDATERS =
      EnumSet.of(ACCOUNT_REMOVE_OIDC_ID, ACCOUNT_REMOVE_SAML_ID, ACCOUNT_ADD_SSH_KEY,
          ACCOUNT_REMOVE_SSH_KEY, ACCOUNT_REMOVE_GROUP_MEMBERSHIP);

  private final IamProperties iamProperties;

  public UpdaterConfig(IamProperties iamProperties) {
    this.iamProperties = iamProperties;
  }

  @Bean
  Set<UpdaterType> enabledUpdaters() {

    EnumSet<UpdaterType> enabledUpdaters = EnumSet.noneOf(UpdaterType.class);

    enabledUpdaters.addAll(ACCOUNT_LINKING_UPDATERS);

    iamProperties.getUserProfile().getEditableFields().forEach(e -> {
      switch (e) {
        case NAME -> enabledUpdaters.add(ACCOUNT_REPLACE_GIVEN_NAME);
        case SURNAME -> enabledUpdaters.add(ACCOUNT_REPLACE_FAMILY_NAME);
        case PICTURE -> {
          enabledUpdaters.add(ACCOUNT_REPLACE_PICTURE);
          enabledUpdaters.add(ACCOUNT_REMOVE_PICTURE);
        }
        case EMAIL -> enabledUpdaters.add(ACCOUNT_REPLACE_EMAIL);
      }
    });

    return enabledUpdaters;
  }
}
