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
package it.infn.mw.iam.api.account.multi_factor_authentication.passkey;

import java.util.Collections;
import java.util.List;

import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.PasskeyChallenge.Purpose;
import it.infn.mw.iam.api.account.multi_factor_authentication.passkey.error.PasskeyDisabledException;
import it.infn.mw.iam.persistence.model.IamAccount;
import it.infn.mw.iam.persistence.model.IamPasskey;
import it.infn.mw.iam.persistence.repository.IamPasskeyRepository;

public class DisabledIamPasskeyService implements IamPasskeyService {

  public static final String DISABLED_MESSAGE = "Passkeys are disabled on this IAM instance";

  private final IamPasskeyRepository passkeyRepository;

  public DisabledIamPasskeyService(IamPasskeyRepository passkeyRepository) {
    this.passkeyRepository = passkeyRepository;
  }

  @Override
  public boolean isEnabled() {
    return false;
  }

  @Override
  public boolean isPasskeyActive(IamAccount account) {
    return false;
  }

  @Override
  public List<IamPasskey> getPasskeys(IamAccount account) {
    return Collections.emptyList();
  }

  @Override
  public PasskeyChallenge createChallenge(IamAccount account, Purpose purpose) {
    throw new PasskeyDisabledException(DISABLED_MESSAGE);
  }

  @Override
  public PasskeyRegistrationOptionsDTO getRegistrationOptions(IamAccount account,
      PasskeyChallenge challenge) {
    throw new PasskeyDisabledException(DISABLED_MESSAGE);
  }

  @Override
  public IamPasskey registerPasskey(IamAccount account, PasskeyChallenge challenge,
      PasskeyRegistrationDTO registration) {
    throw new PasskeyDisabledException(DISABLED_MESSAGE);
  }

  @Override
  public PasskeyAssertionOptionsDTO getAuthenticationOptions(IamAccount account,
      PasskeyChallenge challenge) {
    throw new PasskeyDisabledException(DISABLED_MESSAGE);
  }

  @Override
  public IamPasskey verifyPasskey(IamAccount account, PasskeyChallenge challenge,
      PasskeyAssertionDTO assertion) {
    throw new PasskeyDisabledException(DISABLED_MESSAGE);
  }

  @Override
  public IamPasskey removePasskey(IamAccount account, String passkeyUuid) {
    throw new PasskeyDisabledException(DISABLED_MESSAGE);
  }

  /**
   * Passkeys stored before the feature was disabled are still removed, so that an administrator
   * resetting the second factors of an account does not leave behind credentials that would
   * become active again once the feature is re-enabled
   */
  @Override
  public List<IamPasskey> removeAllPasskeys(IamAccount account) {
    List<IamPasskey> passkeys = passkeyRepository.findByAccountId(account.getId());
    passkeyRepository.deleteAll(passkeys);
    return passkeys;
  }
}
