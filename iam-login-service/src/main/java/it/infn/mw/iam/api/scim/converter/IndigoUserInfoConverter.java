package it.infn.mw.iam.api.scim.converter;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.model.ScimIndigoUserInfo;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@Service
public class IndigoUserInfoConverter implements Converter<ScimIndigoUserInfo, IamUserInfo> {

  @Override
  public IamUserInfo fromScim(ScimIndigoUserInfo scim) {

    IamUserInfo ui = new IamUserInfo();

    ui.setGivenName(scim.getGivenName());
    ui.setFamilyName(scim.getFamilyName());
    ui.setMiddleName(scim.getMiddleName());
    ui.setBirthdate(scim.getBirthdate());
    ui.setAddress(scim.getAddress());
    ui.setEmail(scim.getEmail());
    ui.setEmailVerified(scim.getEmailVerified());
    ui.setGender(scim.getGender());
    ui.setLocale(scim.getLocale());
    ui.setNickname(scim.getNickname());
    ui.setPhoneNumber(scim.getPhoneNumber());
    ui.setPhoneNumberVerified(scim.getPhoneNumberVerified());
    ui.setPicture(scim.getPicture());
    ui.setProfile(scim.getProfile());
    ui.setWebsite(scim.getWebsite());
    ui.setZoneinfo(scim.getZoneinfo());

    return ui;
  }

  @Override
  public ScimIndigoUserInfo toScim(IamUserInfo entity) {

    ScimIndigoUserInfo.Builder b = ScimIndigoUserInfo.builder();

    b.address(entity.getAddress())
      .birthdate(entity.getBirthdate())
      .email(entity.getEmail())
      .emailVerified(entity.getEmailVerified())
      .familyName(entity.getFamilyName())
      .gender(entity.getGender())
      .givenName(entity.getGivenName())
      .locale(entity.getLocale())
      .middleName(entity.getMiddleName())
      .nickname(entity.getNickname())
      .phoneNumber(entity.getPhoneNumber())
      .phoneNumberVerified(entity.getPhoneNumberVerified())
      .picture(entity.getPicture())
      .profile(entity.getProfile())
      .website(entity.getWebsite())
      .zoneinfo(entity.getZoneinfo());
    
    return b.build();
  }

}
