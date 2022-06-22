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
import it.infn.mw.iam.persistence.model.IamGroup;

public class GroupServiceUtils {

  public static void assertSortIsByNameAsc(List<IamGroup> groups) {

    if (groups.size() > 1) {
      for (int i = 1; i < groups.size(); i++) {
        assertThatSortIsByNameAsc(groups.get(i - 1), groups.get(i));
      }
    }
  }

  public static void assertSortIsByNameDesc(List<IamGroup> groups) {

    if (groups.size() > 1) {
      for (int i = 1; i < groups.size(); i++) {
        assertThatSortIsByNameDesc(groups.get(i - 1), groups.get(i));
      }
    }
  }

  public static void assertThatSortIsByNameAsc(IamGroup prior, IamGroup next) {

    assertThat(prior.getName(), lessThanOrEqualTo(next.getName()));
  }

  public static void assertThatSortIsByNameDesc(IamGroup prior, IamGroup next) {

    assertThat(prior.getName(), greaterThanOrEqualTo(next.getName()));
  }
}
