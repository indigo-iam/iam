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
package it.infn.mw.iam.test.notification.resolver;

import static java.lang.String.format;

import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamUserInfo;

public class AddressResolutionServiceTestSupport {

  public static final String INVALID_AUDIENCE = "papisilvio";
  public static final String ROLE_ADMIN = "ROLE_ADMIN";

  public static final String GROUP_ADMIN_001 = "ROLE_GM:001";

  public static final String ADMIN_1 = "admin_1";
  public static final String ADMIN_2 = "admin_2";

  public static final String ADMIN_1_EMAIL = format("%s@example", ADMIN_1);
  public static final String ADMIN_2_EMAIL = format("%s@example", ADMIN_2);

  protected IamAccount createAccount(String name, String emailAddress) {
    IamAccount a = new IamAccount();
    a.setUserInfo(new IamUserInfo());
    a.getUserInfo().setEmail(emailAddress);
    a.getUserInfo().setName(name);
    return a;
  }
}
