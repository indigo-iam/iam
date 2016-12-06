package it.infn.mw.iam.api.scim.updater.factory;

import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.add;
import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.remove;
import static it.infn.mw.iam.api.scim.model.ScimPatchOperation.ScimPatchOperationType.replace;

import java.util.Collection;
import java.util.List;
import java.util.function.Predicate;
import java.util.function.Supplier;

import com.google.common.collect.Lists;

import it.infn.mw.iam.api.scim.exception.ScimResourceNotFoundException;
import it.infn.mw.iam.api.scim.model.ScimMemberRef;
import it.infn.mw.iam.api.scim.model.ScimPatchOperation;
import it.infn.mw.iam.api.scim.updater.AccountUpdater;
import it.infn.mw.iam.api.scim.updater.AccountUpdaterBuilder;
import it.infn.mw.iam.api.scim.updater.AccountUpdaterFactory;
import it.infn.mw.iam.api.scim.updater.builders.AccountUpdaters;
import it.infn.mw.iam.api.scim.updater.builders.Adders;
import it.infn.mw.iam.api.scim.updater.builders.Removers;
import it.infn.mw.iam.api.scim.updater.util.CollectionHelpers;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamGroup;
import it.infn.mw.iam.persistence.repository.IamAccountRepository;

public class DefaultGroupMembershipUpdaterFactory
    implements AccountUpdaterFactory<IamGroup, List<ScimMemberRef>> {

  final IamAccountRepository accountRepository;

  public DefaultGroupMembershipUpdaterFactory(IamAccountRepository accountRepository) {

    this.accountRepository = accountRepository;
  }

  @Override
  public List<AccountUpdater> getUpdatersForPatchOperation(IamGroup group,
      ScimPatchOperation<List<ScimMemberRef>> op) {

    final List<AccountUpdater> updaters = Lists.newArrayList();

    final List<IamAccount> members = memberRefToAccountConverter(op.getValue());

    if (op.getOp().equals(add)) {

      prepareAdders(updaters, members, group);

    }
    if (op.getOp().equals(remove)) {

      prepareRemovers(updaters, members, group);

    }
    if (op.getOp().equals(replace)) {

      prepareReplacers(updaters, members, group);
    }
    return updaters;

  }

  private void prepareAdders(List<AccountUpdater> updaters, List<IamAccount> membersToAdd,
      IamGroup group) {

    Supplier<Collection<IamGroup>> getter = () -> Lists.newArrayList(group);

    for (IamAccount memberToAdd : membersToAdd) {

      Adders add = AccountUpdaters.adders(accountRepository, null, memberToAdd);
      addUpdater(updaters, CollectionHelpers::notNullOrEmpty, getter, add::group);
    }
  }

  private void prepareRemovers(List<AccountUpdater> updaters, List<IamAccount> membersToRemove,
      IamGroup group) {

    Supplier<Collection<IamGroup>> getter = () -> Lists.newArrayList(group);

    if (membersToRemove.isEmpty()) {
      /* remove all members */
      membersToRemove.addAll(group.getAccounts());
    }

    for (IamAccount memberToRemove : membersToRemove) {

      Removers remove = AccountUpdaters.removers(accountRepository, memberToRemove);
      addUpdater(updaters, CollectionHelpers::notNullOrEmpty, getter, remove::group);
    }
  }

  private void prepareReplacers(List<AccountUpdater> updaters, List<IamAccount> membersToReplace,
      IamGroup group) {

    Supplier<Collection<IamGroup>> getter = () -> Lists.newArrayList(group);

    for (IamAccount oldMember : group.getAccounts()) {

      if (!membersToReplace.contains(oldMember)) {

        Removers remove = AccountUpdaters.removers(accountRepository, oldMember);
        addUpdater(updaters, CollectionHelpers::notNullOrEmpty, getter, remove::group);
      }
    }

    for (IamAccount newMember : membersToReplace) {

      if (!group.getAccounts().contains(newMember)) {

        Adders add = AccountUpdaters.adders(accountRepository, null, newMember);
        addUpdater(updaters, CollectionHelpers::notNullOrEmpty, getter, add::group);
      }
    }
  }

  private static <T> AccountUpdater buildUpdater(AccountUpdaterBuilder<T> factory,
      Supplier<T> valueSupplier) {
    return factory.build(valueSupplier.get());
  }

  private static <T> void addUpdater(List<AccountUpdater> updaters, Predicate<T> valuePredicate,
      Supplier<T> valueSupplier, AccountUpdaterBuilder<T> factory) {

    if (valuePredicate.test(valueSupplier.get())) {
      updaters.add(buildUpdater(factory, valueSupplier));
    }
  }

  private List<IamAccount> memberRefToAccountConverter(List<ScimMemberRef> members) {

    List<IamAccount> newAccounts = Lists.newArrayList();
    if (members == null) {
      return newAccounts;
    }
    for (ScimMemberRef memberRef : members) {
      String uuid = memberRef.getValue();
      IamAccount account = accountRepository.findByUuid(uuid)
        .orElseThrow(() -> new ScimResourceNotFoundException("User UUID " + uuid + " not found"));
      newAccounts.add(account);
    }
    return newAccounts;
  }

}
