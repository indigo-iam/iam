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
