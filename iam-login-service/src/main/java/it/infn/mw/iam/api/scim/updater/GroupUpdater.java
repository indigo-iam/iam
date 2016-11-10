package it.infn.mw.iam.api.scim.updater;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.infn.mw.iam.api.scim.exception.ScimException;
import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimMemberRef;
import it.infn.mw.iam.api.scim.updater.group.MembershipUpdater;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

@Component
public class GroupUpdater implements Updater<IamGroup, List<ScimMemberRef>> {

  @Autowired
  private MembershipUpdater membershipUpdater;

  @Autowired
  private IamAccountRepository accountRepository;

  @Override
  public boolean add(IamGroup group, List<ScimMemberRef> members) {

    if (members == null) {
      throw new ScimException("PATCH add members to group: expected not null list of members");
    }
    if (members.isEmpty()) {
      return false;
    }
    boolean hasChanged = false;

    for (ScimMemberRef member : members) {
      hasChanged |= addMembership(member.getValue(), group);
    }
    return hasChanged;
  }

  @Override
  public boolean remove(IamGroup group, List<ScimMemberRef> members) {

    if (members == null) {
      if (group.getAccounts().isEmpty()) {
        return false;
      }
      return removeAllMembers(group);
    } else {
      boolean hasChanged = false;
      for (ScimMemberRef member : members) {
        hasChanged |= removeMembership(member.getValue(), group);
      }
      return hasChanged;
    }
  }

  @Override
  public boolean replace(IamGroup group, List<ScimMemberRef> members) {

    if (members == null) {
      throw new ScimException("PATCH replace members to group: expected not null list of members");
    }

    boolean hasChanged = false;
    // update groups of removed members
    for (IamAccount member : group.getAccounts()) {
      boolean found = false;
      for (ScimMemberRef newMember : members) {
        if (newMember.getValue().equals(member.getUuid())) {
          found = true;
        }
      }
      if (!found) {
        hasChanged |= removeMembership(member.getUuid(), group);
      }
    }
    // add new members
    for (ScimMemberRef member : members) {
      hasChanged |= addMembership(member.getValue(), group);
    }
    return hasChanged;
  }

  private boolean removeAllMembers(IamGroup group) {

    boolean hasChanged = false;
    for (IamAccount account : group.getAccounts()) {
      hasChanged |= membershipUpdater.remove(account, group);
    }
    return hasChanged;
  }

  private boolean addMembership(String uuid, IamGroup group) {

    IamAccount account = accountRepository.findByUuid(uuid)
      .orElseThrow(() -> new ScimResourceNotFoundException("No user mapped to id '" + uuid + "'"));

    return membershipUpdater.add(account, group);
  }

  private boolean removeMembership(String uuid, IamGroup group) {

    IamAccount account = accountRepository.findByUuid(uuid)
      .orElseThrow(() -> new ScimResourceNotFoundException("No user mapped to id '" + uuid + "'"));

    return membershipUpdater.remove(account, group);
  }
}
