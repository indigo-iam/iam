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
package it.infn.mw.iam.test.api.account.search.service;

import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import java.util.List;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamUserInfo;

public class AccountServiceUtils {

  public static void assertSortIsByNameAsc(List<IamAccount> accounts) {

    if (accounts.size() > 1) {
      for (int i = 1; i < accounts.size(); i++) {
        assertThatSortIsByNameAsc(accounts.get(i - 1), accounts.get(i));
      }
    }
  }

  public static void assertSortIsByNameDesc(List<IamAccount> accounts) {

    if (accounts.size() > 1) {
      for (int i = 1; i < accounts.size(); i++) {
        assertThatSortIsByNameDesc(accounts.get(i - 1), accounts.get(i));
      }
    }
  }

  public static void assertSortIsByEmailAsc(List<IamAccount> accounts) {

    if (accounts.size() > 1) {
      for (int i = 1; i < accounts.size(); i++) {
        assertThatSortIsByEmailAsc(accounts.get(i - 1), accounts.get(i));
      }
    }
  }

  public static void assertSortIsByEmailDesc(List<IamAccount> accounts) {

    if (accounts.size() > 1) {
      for (int i = 1; i < accounts.size(); i++) {
        assertThatSortIsByEmailDesc(accounts.get(i - 1), accounts.get(i));
      }
    }
  }

  public static void assertThatSortIsByNameAsc(IamAccount prior, IamAccount next) {

    IamUserInfo priorUI = prior.getUserInfo();
    IamUserInfo nextUI = next.getUserInfo();
    assertThat(priorUI.getGivenName(), lessThanOrEqualTo(nextUI.getGivenName()));
    if (priorUI.getGivenName().equals(nextUI.getGivenName())) {
      assertThat(priorUI.getFamilyName(), lessThanOrEqualTo(nextUI.getFamilyName()));
    }
  }

  public static void assertThatSortIsByNameDesc(IamAccount prior, IamAccount next) {

    IamUserInfo priorUI = prior.getUserInfo();
    IamUserInfo nextUI = next.getUserInfo();
    assertThat(priorUI.getGivenName(), greaterThanOrEqualTo(nextUI.getGivenName()));
    if (priorUI.getGivenName().equals(nextUI.getGivenName())) {
      assertThat(priorUI.getFamilyName(), greaterThanOrEqualTo(nextUI.getFamilyName()));
    }
  }

  public static void assertThatSortIsByEmailAsc(IamAccount prior, IamAccount next) {

    IamUserInfo priorUI = prior.getUserInfo();
    IamUserInfo nextUI = next.getUserInfo();
    assertThat(priorUI.getEmail(), lessThanOrEqualTo(nextUI.getEmail()));
  }

  public static void assertThatSortIsByEmailDesc(IamAccount prior, IamAccount next) {

    IamUserInfo priorUI = prior.getUserInfo();
    IamUserInfo nextUI = next.getUserInfo();
    assertThat(priorUI.getEmail(), greaterThanOrEqualTo(nextUI.getEmail()));
  }
}
