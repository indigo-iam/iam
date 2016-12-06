package it.infn.mw.iam.api.scim.updater.util;

import java.util.Optional;

import it.infn.mw.iam.persistence.model.IamAccount;

@FunctionalInterface
public interface AccountFinder<T> {
  Optional<IamAccount> find(T id);
}
