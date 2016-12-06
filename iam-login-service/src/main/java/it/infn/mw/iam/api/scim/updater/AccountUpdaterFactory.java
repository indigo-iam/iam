package it.infn.mw.iam.api.scim.updater;

import java.util.List;

import it.infn.mw.iam.api.scim.model.ScimPatchOperation;

/**
 * Builds a list of {@link AccountUpdater} objects linked to a patch operation
 */
public interface AccountUpdaterFactory<EntityType, ScimType> {


  /**
   * 
   * @param entity @param u @return
   */
  List<AccountUpdater> getUpdatersForPatchOperation(EntityType entity, ScimPatchOperation<ScimType> u);
}
