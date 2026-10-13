/*
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
(function () {
  'use strict';

  angular.module('dashboardApp')
    .controller('AddPasskeyController', AddPasskeyController);

  angular.module('dashboardApp')
    .controller('RemovePasskeyController', RemovePasskeyController);

  AddPasskeyController.$inject = ['$scope', '$uibModalInstance', 'PasskeyService'];

  RemovePasskeyController.$inject = [
    '$scope', '$uibModalInstance', 'PasskeyService', 'passkey', 'proofOptions'
  ];

  function AddPasskeyController($scope, $uibModalInstance, PasskeyService) {
    var passkeyCtrl = this;

    passkeyCtrl.label = '';
    passkeyCtrl.labelMaxlength = 128;
    passkeyCtrl.requestPending = false;
    passkeyCtrl.supported = PasskeyService.isSupported();
    passkeyCtrl.dismiss = dismiss;
    passkeyCtrl.clearError = clearError;
    passkeyCtrl.submitRegister = submitRegister;

    function dismiss() { return $uibModalInstance.dismiss('Cancel'); }

    function clearError() { $scope.operationResult = null; }

    function submitRegister() {
      if (passkeyCtrl.requestPending || !passkeyCtrl.supported || !passkeyCtrl.label) {
        return;
      }
      passkeyCtrl.requestPending = true;
      PasskeyService.registerPasskey(passkeyCtrl.label)
        .then(function () {
          passkeyCtrl.requestPending = false;
          $uibModalInstance.close('Passkey registered');
        })
        .catch(function (error) {
          passkeyCtrl.requestPending = false;
          $scope.operationResult = { type: 'error', text: PasskeyService.describeError(error) };
        });
    }
  }

  /**
   * Removing a passkey requires a proof of a second factor. The modal offers the proofs the
   * account can give: an assertion with one of its passkeys (when the feature is enabled and the
   * browser supports it) and a code of the authenticator app (when it is active). While passkeys
   * are disabled the stored credentials are inert and the server needs no proof
   */
  function RemovePasskeyController($scope, $uibModalInstance, PasskeyService, passkey,
      proofOptions) {
    var passkeyCtrl = this;

    passkeyCtrl.passkey = passkey;
    passkeyCtrl.passkeyEnabled = !!proofOptions.passkeyEnabled;
    passkeyCtrl.passkeyProofAvailable = passkeyCtrl.passkeyEnabled && PasskeyService.isSupported();
    passkeyCtrl.totpProofAvailable = !!proofOptions.authenticatorAppActive;
    passkeyCtrl.proofRequired = passkeyCtrl.passkeyEnabled;
    passkeyCtrl.code = '';
    passkeyCtrl.codeMinlength = 6;
    passkeyCtrl.requestPending = false;
    passkeyCtrl.dismiss = dismiss;
    passkeyCtrl.clearError = clearError;
    passkeyCtrl.removeWithPasskey = removeWithPasskey;
    passkeyCtrl.removeWithTotp = removeWithTotp;
    passkeyCtrl.removeWithoutProof = removeWithoutProof;

    function dismiss() { return $uibModalInstance.dismiss('Cancel'); }

    function clearError() { $scope.operationResult = null; }

    function removeWithPasskey() {
      if (!passkeyCtrl.passkeyProofAvailable) {
        return;
      }
      remove(function () { return PasskeyService.removePasskeyWithPasskey(passkey.uuid); });
    }

    function removeWithTotp() {
      if (!passkeyCtrl.totpProofAvailable || !passkeyCtrl.code
          || passkeyCtrl.code.length < passkeyCtrl.codeMinlength) {
        return;
      }
      var code = passkeyCtrl.code;
      // A code is single use: a refused one is cleared, whatever the reason
      passkeyCtrl.code = '';
      remove(function () {
        return PasskeyService.removePasskeyWithTotp(passkey.uuid, code);
      });
    }

    function removeWithoutProof() {
      if (passkeyCtrl.proofRequired) {
        return;
      }
      remove(function () { return PasskeyService.removePasskey(passkey.uuid); });
    }

    function remove(request) {
      if (passkeyCtrl.requestPending) {
        return;
      }
      passkeyCtrl.requestPending = true;
      clearError();
      request()
        .then(function () {
          passkeyCtrl.requestPending = false;
          $uibModalInstance.close('Passkey removed');
        })
        .catch(function (error) {
          passkeyCtrl.requestPending = false;
          $scope.operationResult = { type: 'error', text: PasskeyService.describeError(error) };
        });
    }
  }
})();
