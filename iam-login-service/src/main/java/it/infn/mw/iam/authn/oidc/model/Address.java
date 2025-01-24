package it.infn.mw.iam.authn.oidc.model;

import java.io.Serializable;

public interface Address extends Serializable {

    public Long getId();

    public String getFormatted();

    public void setFormatted(String formatted);

    public String getStreetAddress();

    public void setStreetAddress(String streetAddress);

    public String getLocality();

    public void setLocality(String locality);

    public String getRegion();

    public void setRegion(String region);

    public String getPostalCode();

    public void setPostalCode(String postalCode);

    public String getCountry();

    public void setCountry(String country);

}
