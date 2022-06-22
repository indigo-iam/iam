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
package it.infn.mw.voms;

import static it.infn.mw.voms.aa.VOMSNamingScheme.isQualifiedRole;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class NamingSchemeTests {

  @Test
  public void namingSchemeTests() {

    String[] roleFqans = {"/test/Role=production", "/test/subgroup/Role=VO-Admin"};
    
    String[] groupFqans = {"/test", "/test/subgroup", "/dteam"};

    for (String fqan: roleFqans) {
      assertThat(isQualifiedRole(fqan), is(true));
    }
    
    for (String fqan: groupFqans) {
      assertThat(isQualifiedRole(fqan), is(false));
    }
  }
}
