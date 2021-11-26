/*
 * Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2016-2019
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
(function() {
  'use strict';

  angular.module('dashboardApp')
      .controller('EnableAuthenticatorAppController', EnableAuthenticatorAppController);

  angular.module('dashboardApp')
      .controller('DisableAuthenticatorAppController', DisableAuthenticatorAppController);

  EnableAuthenticatorAppController.$inject = [
    '$scope', '$state', '$uibModalInstance', 'Utils', 'AuthenticatorAppService', 'user'
  ];

  DisableAuthenticatorAppController.$inject = [
    '$scope', '$state', '$uibModalInstance', 'Utils', 'AuthenticatorAppService', 'user'
  ];

  function EnableAuthenticatorAppController(
      $scope, $state, $uibModalInstance, Utils, AuthenticatorAppService, user) {
    var authAppCtrl = this;

    authAppCtrl.$onInit = function() {
      AuthenticatorAppService.addMfaSecretToUser().then(function(response) {
        authAppCtrl.secret = response.data.secret;
        authAppCtrl.dataUri = response.data.dataUri;
      });
    }

    authAppCtrl.userToEdit = user;
    authAppCtrl.codeMinlength = 6;

    authAppCtrl.dismiss = dismiss;
    authAppCtrl.reset = reset;

    function reset() {
      console.log('reset form');

      authAppCtrl.enabled = true;

      authAppCtrl.user = {
        code: ''
      };

      if ($scope.authenticatorAppForm) {
        $scope.authenticatorAppForm.$setPristine();
      }
    }

    authAppCtrl.reset();

    function dismiss() { return $uibModalInstance.dismiss('Cancel'); }

    authAppCtrl.message = '';

    authAppCtrl.submitEnable = function() {
      AuthenticatorAppService
          .enableAuthenticatorApp(
              authAppCtrl.user.code)
          .then(function() { return $uibModalInstance.close('Authenticator app enabled'); })
          .catch(function(error) {
            console.error(error);
            $scope.operationResult = Utils.buildErrorResult(error.data);
          });
    };
  }

  function DisableAuthenticatorAppController(
      $scope, $state, $uibModalInstance, Utils, AuthenticatorAppService, user) {
    var authAppCtrl = this;

    authAppCtrl.userToEdit = user;
    authAppCtrl.codeMinlength = 6;

    authAppCtrl.dismiss = dismiss;
    authAppCtrl.reset = reset;

    function reset() {
      console.log('reset form');

      authAppCtrl.enabled = true;

      authAppCtrl.user = {
        code: ''
      };

      if ($scope.authenticatorAppForm) {
        $scope.authenticatorAppForm.$setPristine();
      }
    }

    authAppCtrl.reset();

    function dismiss() { return $uibModalInstance.dismiss('Cancel'); }

    authAppCtrl.message = '';

    authAppCtrl.submitDisable = function() {
      AuthenticatorAppService
          .disableAuthenticatorApp(
              authAppCtrl.user.code)
          .then(function() { return $uibModalInstance.close('Authenticator app disabled'); })
          .catch(function(error) {
            console.error(error);
            $scope.operationResult = Utils.buildErrorResult(error.data);
          });
    };
  }
})();