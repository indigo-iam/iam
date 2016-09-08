package it.infn.mw.iam.registration;

import org.springframework.stereotype.Service;

import it.infn.mw.iam.core.IamRegistrationRequestStatus;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamRegistrationRequest;
import it.infn.mw.iam.persistence.model.IamUserInfo;

@Service
public class RegistrationConverter {

  public RegistrationRequestDto fromEntity(final IamRegistrationRequest request) {

    RegistrationRequestDto item = new RegistrationRequestDto();
    item.setUuid(request.getUuid());
    item.setCreationTime(request.getCreationTime());
    item.setStatus(request.getStatus().name());
    item.setLastUpdateTime(request.getLastUpdateTime());
    item.setUsername(request.getAccount().getUsername());
    item.setGivenname(request.getAccount().getUserInfo().getGivenName());
    item.setFamilyname(request.getAccount().getUserInfo().getFamilyName());
    item.setEmail(request.getAccount().getUserInfo().getEmail());
    item.setAccountId(request.getAccount().getUuid());
    item.setNotes(request.getNotes());

    return item;
  }

  public IamRegistrationRequest toEntity(final RegistrationRequestDto request) {

    IamUserInfo userInfo = new IamUserInfo();
    userInfo.setFamilyName(request.getFamilyname());
    userInfo.setGivenName(request.getGivenname());
    userInfo.setEmail(request.getEmail());
    userInfo.setBirthdate(request.getBirthdate());

    IamAccount account = new IamAccount();
    account.setUsername(request.getUsername());
    account.setUserInfo(userInfo);
    account.setUuid(request.getAccountId());

    IamRegistrationRequest entity = new IamRegistrationRequest();
    entity.setUuid(request.getUuid());
    entity.setCreationTime(request.getCreationTime());
    entity.setLastUpdateTime(entity.getLastUpdateTime());
    entity.setStatus(IamRegistrationRequestStatus.valueOf(request.getStatus()));
    entity.setAccount(account);
    entity.setNotes(request.getNotes());

    return entity;
  }

}
