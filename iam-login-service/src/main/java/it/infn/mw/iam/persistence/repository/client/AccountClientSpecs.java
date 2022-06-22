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
package it.infn.mw.iam.persistence.repository.client;

import static it.infn.mw.iam.persistence.repository.client.ClientSpecs.CLIENT_ID;
import static it.infn.mw.iam.persistence.repository.client.ClientSpecs.CLIENT_NAME;
import static it.infn.mw.iam.persistence.repository.client.ClientSpecs.wildcardify;

import org.springframework.data.jpa.domain.Specification;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamAccountClient;

public class AccountClientSpecs {

  public static final String ACCOUNT = "account";
  public static final String CLIENT = "client";

  private AccountClientSpecs() {
    // prevent instantiation
  }

  public static Specification<IamAccountClient> isOwnedByAccount(IamAccount account) {
    return (root, query, builder) -> builder.equal(root.get(ACCOUNT), account);
  }


  public static Specification<IamAccountClient> hasScope(String scope) {
    return (root, query, builder) -> builder.equal(root.join(CLIENT).joinSet(ClientSpecs.SCOPE),
        scope);
  }

  public static Specification<IamAccountClient> hasClientIdLike(String filter) {
    return (root, query, builder) -> builder.like(root.join(CLIENT).get(CLIENT_ID),
        wildcardify(filter));
  }

  public static Specification<IamAccountClient> hasClientNameLike(String filter) {
    return (root, query, builder) -> builder.like(root.join(CLIENT).get(CLIENT_NAME),
        wildcardify(filter));
  }

}
