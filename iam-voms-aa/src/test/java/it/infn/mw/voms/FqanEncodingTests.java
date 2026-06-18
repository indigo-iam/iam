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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import it.infn.mw.voms.aa.impl.LegacyFQANEncoding;
import it.infn.mw.voms.aa.impl.NullFQANEncoding;

@ExtendWith(MockitoExtension.class)
class FqanEncodingTests {

  static final String GROUP_FQAN = "/test";
  static final String ROLE_FQAN = "/test/Role=test";

  static final String GROUP_FQAN_LEGACY = "/test/Role=NULL/Capability=NULL";
  static final String ROLE_FQAN_LEGACY = "/test/Role=test/Capability=NULL";

  final NullFQANEncoding nullEncoding = new NullFQANEncoding();
  final LegacyFQANEncoding legacyEncoding = new LegacyFQANEncoding();

  @Test
  void testNullEncoding() {

    assertThat(nullEncoding.encodeFQAN(GROUP_FQAN), is(GROUP_FQAN));
    assertThat(nullEncoding.decodeFQAN(GROUP_FQAN), is(GROUP_FQAN));
    assertThat(nullEncoding.encodeFQAN(ROLE_FQAN), is(ROLE_FQAN));
    assertThat(nullEncoding.decodeFQAN(ROLE_FQAN), is(ROLE_FQAN));
  }

  @Test
  void testLegacyEncoding() {

    assertThat(legacyEncoding.encodeFQAN(GROUP_FQAN), is(GROUP_FQAN_LEGACY));
    assertThat(legacyEncoding.decodeFQAN(GROUP_FQAN_LEGACY), is(GROUP_FQAN));
    assertThat(legacyEncoding.decodeFQAN(GROUP_FQAN), is(GROUP_FQAN));

    assertThat(legacyEncoding.encodeFQAN(ROLE_FQAN), is(ROLE_FQAN_LEGACY));
    assertThat(legacyEncoding.decodeFQAN(ROLE_FQAN_LEGACY), is(ROLE_FQAN));
    assertThat(legacyEncoding.decodeFQAN(ROLE_FQAN), is(ROLE_FQAN));
  }
}
