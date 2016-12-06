package it.infn.mw.iam.api.scim.converter;

import org.mitre.openid.connect.model.Address;
import org.mitre.openid.connect.model.DefaultAddress;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.model.ScimAddress;

@Service
public class AddressConverter implements Converter<ScimAddress, Address> {

  @Override
  public Address fromScim(ScimAddress scim) {

    Address address = new DefaultAddress();

    address.setCountry(scim.getCountry());
    address.setFormatted(scim.getFormatted());
    address.setLocality(scim.getLocality());
    address.setCountry(scim.getCountry());
    address.setPostalCode(scim.getPostalCode());
    address.setRegion(scim.getRegion());
    address.setStreetAddress(scim.getStreetAddress());

    return address;
  }

  @Override
  public ScimAddress toScim(Address entity) {

    ScimAddress address =
        ScimAddress.builder().country(entity.getCountry()).formatted(entity.getFormatted())
            .locality(entity.getLocality()).postalCode(entity.getPostalCode())
            .region(entity.getRegion()).streetAddress(entity.getStreetAddress()).build();

    return address;
  }

}
