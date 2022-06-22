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
package it.infn.mw.iam.persistence.repository;

import org.mitre.openid.connect.model.Address;

import it.infn.mw.iam.persistence.model.IamAddress;

public class AddressAdapter implements Address {

  private static final long serialVersionUID = 1L;
  
  final IamAddress address;

  private AddressAdapter(it.infn.mw.iam.persistence.model.IamAddress address) {
    this.address = address;
  }

  public Long getId() {
    return address.getId();
  }

  public String getFormatted() {
    return address.getFormatted();
  }

  public void setFormatted(String formatted) {
    address.setFormatted(formatted);
  }

  public String getStreetAddress() {
    return address.getStreetAddress();
  }

  public void setStreetAddress(String streetAddress) {
    address.setStreetAddress(streetAddress);
  }

  public String getLocality() {
    return address.getLocality();
  }

  public void setLocality(String locality) {
    address.setLocality(locality);
  }

  public String getRegion() {
    return address.getRegion();
  }

  public void setRegion(String region) {
    address.setRegion(region);
  }

  public String getPostalCode() {
    return address.getPostalCode();
  }

  public void setPostalCode(String postalCode) {
    address.setPostalCode(postalCode);
  }

  public String getCountry() {
    return address.getCountry();
  }

  public void setCountry(String country) {
    address.setCountry(country);
  }

  public static AddressAdapter forIamAddress(IamAddress a) {
    return new AddressAdapter(a);
  }

}
