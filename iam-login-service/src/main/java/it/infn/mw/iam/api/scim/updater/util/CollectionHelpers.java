package it.infn.mw.iam.api.scim.updater.util;

import static java.util.Objects.nonNull;

import java.util.Collection;

public class CollectionHelpers {

  public static <T> boolean notNullOrEmpty(Collection<T> c) {
    return nonNull(c) && !c.isEmpty();
  }

}
