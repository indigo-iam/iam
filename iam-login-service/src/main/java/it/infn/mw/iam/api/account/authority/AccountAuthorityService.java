package it.infn.mw.iam.api.account.authority;

import java.util.Set;

import it.infn.mw.iam.persistence.model.IamAccount;

/**
 * The IAM Account authority service
 *
 */
public interface AccountAuthorityService {

  /**
   * Returns the authorities linked to an IAM account
   * 
   * @param account the IAM account
   * 
   * @return a {@link Set} of {@link String}s representing the authorities
   */
  Set<String> getAccountAuthorities(IamAccount account);

  /**
   * Adds an authority to a given {@link IamAccount}
   * 
   * @param account the IAM account
   * 
   * @param authority the authority to be added
   * 
   * @throws AuthorityAlreadyBoundError if the authority is already bound to the account
   */
  void addAuthorityToAccount(IamAccount account, String authority);

  /**
   * Removes an authority from a given {@link IamAccount}
   * 
   * @param account the IAM account
   * 
   * @param authority the authority to be removed
   */
  void removeAuthorityFromAccount(IamAccount account, String authority);

}
