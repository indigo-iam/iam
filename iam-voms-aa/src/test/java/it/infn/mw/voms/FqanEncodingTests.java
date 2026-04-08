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

import static org.junit.jupiter.api.Assertions.assertEquals;

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

    assertEquals(GROUP_FQAN, nullEncoding.encodeFQAN(GROUP_FQAN));
    assertEquals(GROUP_FQAN, nullEncoding.decodeFQAN(GROUP_FQAN));
    assertEquals(ROLE_FQAN, nullEncoding.encodeFQAN(ROLE_FQAN));
    assertEquals(ROLE_FQAN, nullEncoding.decodeFQAN(ROLE_FQAN));
  }

  @Test
  void testLegacyEncoding() {

    assertEquals(GROUP_FQAN_LEGACY, legacyEncoding.encodeFQAN(GROUP_FQAN));
    assertEquals(GROUP_FQAN, legacyEncoding.decodeFQAN(GROUP_FQAN_LEGACY));
    assertEquals(GROUP_FQAN, legacyEncoding.decodeFQAN(GROUP_FQAN));

    assertEquals(ROLE_FQAN_LEGACY, legacyEncoding.encodeFQAN(ROLE_FQAN));
    assertEquals(ROLE_FQAN, legacyEncoding.decodeFQAN(ROLE_FQAN_LEGACY));
    assertEquals(ROLE_FQAN, legacyEncoding.decodeFQAN(ROLE_FQAN));
  }
}
