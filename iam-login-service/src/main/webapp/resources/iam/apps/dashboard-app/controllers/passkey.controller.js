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

  RemovePasskeyController.$inject = ['$scope', '$uibModalInstance', 'PasskeyService', 'passkey'];

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

  function RemovePasskeyController($scope, $uibModalInstance, PasskeyService, passkey) {
    var passkeyCtrl = this;

    passkeyCtrl.passkey = passkey;
    passkeyCtrl.requestPending = false;
    passkeyCtrl.dismiss = dismiss;
    passkeyCtrl.submitRemove = submitRemove;

    function dismiss() { return $uibModalInstance.dismiss('Cancel'); }

    function submitRemove() {
      if (passkeyCtrl.requestPending) {
        return;
      }
      passkeyCtrl.requestPending = true;
      PasskeyService.removePasskey(passkey.uuid)
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
