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
package it.infn.mw.iam.test.scim.model;

import org.junit.Assert;
import org.junit.Test;

import it.infn.mw.iam.api.scim.model.ScimAddress;

public class ScimAddressTests {

  final ScimAddress DEFAULT_ADDRESS = ScimAddress.builder()
    .country("IT")
    .formatted("viale Berti Pichat 6/2\nBologna IT")
    .locality("Bologna")
    .postalCode("40121")
    .region("Emilia Romagna")
    .streetAddress("viale Berti Pichat")
    .build();

  @Test
  public void testEqualsFailsForCountry() {

    ScimAddress address = ScimAddress.builder()
      .country("UK")
      .formatted(DEFAULT_ADDRESS.getFormatted())
      .locality(DEFAULT_ADDRESS.getLocality())
      .postalCode(DEFAULT_ADDRESS.getPostalCode())
      .region(DEFAULT_ADDRESS.getRegion())
      .streetAddress(DEFAULT_ADDRESS.getStreetAddress())
      .build();

    Assert.assertFalse(address.equals(DEFAULT_ADDRESS));
  }

  @Test
  public void testEqualsFailsForFormatted() {

    ScimAddress address = ScimAddress.builder()
      .country(DEFAULT_ADDRESS.getCountry())
      .formatted("viale Berti Pichat 6/2 Bologna IT")
      .locality(DEFAULT_ADDRESS.getLocality())
      .postalCode(DEFAULT_ADDRESS.getPostalCode())
      .region(DEFAULT_ADDRESS.getRegion())
      .streetAddress(DEFAULT_ADDRESS.getStreetAddress())
      .build();

    Assert.assertFalse(address.equals(DEFAULT_ADDRESS));
  }

  @Test
  public void testEqualsFailsForLocality() {

    ScimAddress address = ScimAddress.builder()
      .country(DEFAULT_ADDRESS.getCountry())
      .formatted(DEFAULT_ADDRESS.getFormatted())
      .locality("Casalecchio di Reno")
      .postalCode(DEFAULT_ADDRESS.getPostalCode())
      .region(DEFAULT_ADDRESS.getRegion())
      .streetAddress(DEFAULT_ADDRESS.getStreetAddress())
      .build();

    Assert.assertFalse(address.equals(DEFAULT_ADDRESS));
  }

  @Test
  public void testEqualsFailsForPostalCode() {

    ScimAddress address = ScimAddress.builder()
      .country(DEFAULT_ADDRESS.getCountry())
      .formatted(DEFAULT_ADDRESS.getFormatted())
      .locality(DEFAULT_ADDRESS.getLocality())
      .postalCode("12345")
      .region(DEFAULT_ADDRESS.getRegion())
      .streetAddress(DEFAULT_ADDRESS.getStreetAddress())
      .build();

    Assert.assertFalse(address.equals(DEFAULT_ADDRESS));
  }

  @Test
  public void testEqualsFailsForRegion() {

    ScimAddress address = ScimAddress.builder()
      .country(DEFAULT_ADDRESS.getCountry())
      .formatted(DEFAULT_ADDRESS.getFormatted())
      .locality(DEFAULT_ADDRESS.getLocality())
      .postalCode(DEFAULT_ADDRESS.getPostalCode())
      .region("Romagna")
      .streetAddress(DEFAULT_ADDRESS.getStreetAddress())
      .build();

    Assert.assertFalse(address.equals(DEFAULT_ADDRESS));
  }

  @Test
  public void testEqualsFailsForStreetAddress() {

    ScimAddress address = ScimAddress.builder()
      .country(DEFAULT_ADDRESS.getCountry())
      .formatted(DEFAULT_ADDRESS.getFormatted())
      .locality(DEFAULT_ADDRESS.getLocality())
      .postalCode(DEFAULT_ADDRESS.getPostalCode())
      .region(DEFAULT_ADDRESS.getRegion())
      .streetAddress("via Ranzani 13/2c")
      .build();

    Assert.assertFalse(address.equals(DEFAULT_ADDRESS));
  }
}
