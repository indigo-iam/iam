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
package it.infn.mw.iam.api.scim.converter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import it.infn.mw.iam.api.scim.exception.ScimException;
import it.infn.mw.iam.api.scim.model.ScimAddress;
import it.infn.mw.iam.api.scim.model.ScimGroupRef;
import it.infn.mw.iam.api.scim.model.ScimIndigoUser;
import it.infn.mw.iam.api.scim.model.ScimLabel;
import it.infn.mw.iam.api.scim.model.ScimMeta;
import it.infn.mw.iam.api.scim.model.ScimName;
import it.infn.mw.iam.api.scim.model.ScimPhoto;
import it.infn.mw.iam.api.scim.model.ScimUser;
import it.infn.mw.iam.config.scim.ScimProperties;
import it.infn.mw.iam.config.scim.ScimProperties.LabelDescriptor;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.model.IamOidcId;
import it.infn.mw.iam.persistence.model.IamSamlId;
import it.infn.mw.iam.persistence.model.IamSshKey;
import it.infn.mw.iam.persistence.model.IamUserInfo;
import it.infn.mw.iam.persistence.model.IamX509Certificate;
import it.infn.mw.iam.util.ssh.InvalidSshKeyException;
import it.infn.mw.iam.util.ssh.RSAPublicKeyUtils;

@Service
public class UserConverter implements Converter<ScimUser, IamAccount> {

  private final ScimResourceLocationProvider resourceLocationProvider;

  private final AddressConverter addressConverter;

  private final OidcIdConverter oidcIdConverter;
  private final SshKeyConverter sshKeyConverter;
  private final SamlIdConverter samlIdConverter;
  private final X509CertificateConverter x509CertificateIamConverter;

  private final ScimProperties properties;

  @Autowired
  public UserConverter(ScimProperties properties, ScimResourceLocationProvider rlp,
      AddressConverter ac, OidcIdConverter oidc, SshKeyConverter sshc, SamlIdConverter samlc,
      X509CertificateConverter x509Iamcc) {

    this.resourceLocationProvider = rlp;
    this.properties = properties;
    this.addressConverter = ac;
    this.oidcIdConverter = oidc;
    this.sshKeyConverter = sshc;
    this.samlIdConverter = samlc;
    this.x509CertificateIamConverter = x509Iamcc;
  }

  @Override
  public IamAccount entityFromDto(ScimUser scimUser) {

    IamAccount account = new IamAccount();

    account.setUuid(scimUser.getId());
    account.setUsername(scimUser.getUserName());

    if (scimUser.getActive() != null) {

      account.setActive(scimUser.getActive());
    }

    if (scimUser.getPassword() != null) {

      account.setPassword(scimUser.getPassword());
    }

    if (scimUser.hasOidcIds()) {

      scimUser.getIndigoUser().getOidcIds().forEach(oidcId -> {

        IamOidcId iamOidcId = oidcIdConverter.entityFromDto(oidcId);
        iamOidcId.setAccount(account);
        account.getOidcIds().add(iamOidcId);

      });
    }

    if (scimUser.hasSshKeys()) {

      scimUser.getIndigoUser().getSshKeys().forEach(sshKey -> {

        IamSshKey iamSshKey = sshKeyConverter.entityFromDto(sshKey);

        if (iamSshKey.getFingerprint() == null && iamSshKey.getValue() != null) {

          try {
            iamSshKey.setFingerprint(RSAPublicKeyUtils.getSHA256Fingerprint(iamSshKey.getValue()));
          } catch (InvalidSshKeyException e) {
            throw new ScimException(e.getMessage(), e);
          }
        }

        iamSshKey.setAccount(account);

        if (iamSshKey.getLabel() == null) {

          iamSshKey.setLabel(account.getUsername() + "'s personal ssh key");
        }

        account.getSshKeys().add(iamSshKey);
      });
    }

    if (scimUser.hasSamlIds()) {

      scimUser.getIndigoUser().getSamlIds().forEach(samlId -> {

        IamSamlId iamSamlId = samlIdConverter.entityFromDto(samlId);
        iamSamlId.setAccount(account);
        account.getSamlIds().add(iamSamlId);

      });
    }

    if (scimUser.hasX509Certificates()) {
      scimUser.getIndigoUser().getCertificates().forEach(c -> {
        IamX509Certificate cert = x509CertificateIamConverter.entityFromDto(c);
        cert.setAccount(account);
        account.getX509Certificates().add(cert);
      });
    }

    IamUserInfo userInfo = new IamUserInfo();

    userInfo.setEmail(scimUser.getEmails().get(0).getValue());
    userInfo.setGivenName(scimUser.getName().getGivenName());
    userInfo.setFamilyName(scimUser.getName().getFamilyName());

    if (scimUser.hasPhotos()) {
      userInfo.setPicture(scimUser.getPhotos().get(0).getValue());
    }

    if (scimUser.hasAddresses()) {

      userInfo.setAddress(addressConverter.entityFromDto(scimUser.getAddresses().get(0)));
    }

    account.setUserInfo(userInfo);
    userInfo.setIamAccount(account);

    return account;
  }

  @Override
  public ScimUser dtoFromEntity(IamAccount entity) {

    ScimMeta meta = getScimMeta(entity);
    ScimName name = getScimName(entity);
    ScimIndigoUser indigoUser = getScimIndigoUser(entity);
    ScimAddress address = getScimAddress(entity);
    ScimPhoto picture = getScimPhoto(entity);

    ScimUser.Builder builder = new ScimUser.Builder(entity.getUsername()).id(entity.getUuid())
      .meta(meta)
      .name(name)
      .active(entity.isActive())
      .displayName(entity.getUsername())
      .locale(entity.getUserInfo().getLocale())
      .nickName(entity.getUserInfo().getNickname())
      .profileUrl(entity.getUserInfo().getProfile())
      .timezone(entity.getUserInfo().getZoneinfo())
      .buildEmail(entity.getUserInfo().getEmail())
      .indigoUserInfo(indigoUser);

    if (address != null) {

      builder.addAddress(address);
    }

    if (picture != null) {

      builder.addPhoto(picture);
    }

    entity.getGroups().forEach(group -> builder.addGroupRef(getScimGroupRef(group.getGroup())));

    return builder.build();
  }

  private ScimMeta getScimMeta(IamAccount entity) {

    return ScimMeta.builder(entity.getCreationTime(), entity.getLastUpdateTime())
      .location(resourceLocationProvider.userLocation(entity.getUuid()))
      .resourceType(ScimUser.RESOURCE_TYPE)
      .build();
  }

  private ScimName getScimName(IamAccount entity) {

    return ScimName.builder()
      .givenName(entity.getUserInfo().getGivenName())
      .familyName(entity.getUserInfo().getFamilyName())
      .build();
  }

  private ScimIndigoUser getScimIndigoUser(IamAccount entity) {

    ScimIndigoUser.Builder indigoUserBuilder = new ScimIndigoUser.Builder();

    entity.getOidcIds()
      .forEach(oidcId -> indigoUserBuilder.addOidcid(oidcIdConverter.dtoFromEntity(oidcId)));

    entity.getSshKeys()
      .forEach(sshKey -> indigoUserBuilder.addSshKey(sshKeyConverter.dtoFromEntity(sshKey)));

    entity.getSamlIds()
      .forEach(samlId -> indigoUserBuilder.addSamlId(samlIdConverter.dtoFromEntity(samlId)));

    entity.getX509Certificates()
      .forEach(cert -> indigoUserBuilder
        .addCertificate(x509CertificateIamConverter.dtoFromEntity(cert)));

    if (entity.getAupSignature() != null) {
      indigoUserBuilder.aupSignatureTime(entity.getAupSignature().getSignatureTime());
    }

    for (LabelDescriptor ld : properties.getIncludeLabels()) {
      entity.getLabelByPrefixAndName(ld.getPrefix(), ld.getName())
        .ifPresent(el -> indigoUserBuilder.addLabel(ScimLabel.builder()
          .withPrefix(el.getPrefix())
          .withName(el.getName())
          .withVaule(el.getValue())
          .build()));
    }

    indigoUserBuilder.endTime(entity.getEndTime());

    ScimIndigoUser indigoUser = indigoUserBuilder.build();

    return indigoUser.isEmpty() ? null : indigoUser;
  }

  private ScimGroupRef getScimGroupRef(IamGroup group) {

    return ScimGroupRef.builder()
      .value(group.getUuid())
      .display(group.getName())
      .ref(resourceLocationProvider.groupLocation(group.getUuid()))
      .build();
  }

  private ScimAddress getScimAddress(IamAccount entity) {

    if (entity.getUserInfo() != null && entity.getUserInfo().getAddress() != null) {

      return addressConverter.dtoFromEntity(entity.getUserInfo().getAddress());
    }
    return null;
  }

  private ScimPhoto getScimPhoto(IamAccount entity) {

    if (entity.getUserInfo() == null) {
      return null;
    }

    if (entity.getUserInfo().getPicture() == null || entity.getUserInfo().getPicture().isEmpty()) {
      return null;
    }

    return ScimPhoto.builder().value(entity.getUserInfo().getPicture()).build();
  }
}
