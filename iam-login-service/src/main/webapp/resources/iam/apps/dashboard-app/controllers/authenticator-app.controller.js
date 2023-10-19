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
    .controller('EnableAuthenticatorAppController', EnableAuthenticatorAppController);

  angular.module('dashboardApp')
    .controller('DisableAuthenticatorAppController', DisableAuthenticatorAppController);

  angular.module('dashboardApp')
    .controller('ViewRecoveryCodesController', ViewRecoveryCodesController);

  angular.module('dashboardApp')
    .controller('ResetRecoveryCodesController', ResetRecoveryCodesController);

  EnableAuthenticatorAppController.$inject = [
    '$scope', '$uibModalInstance', 'Utils', 'AuthenticatorAppService', 'user', '$uibModal'
  ];

  DisableAuthenticatorAppController.$inject = [
    '$scope', '$uibModalInstance', 'Utils', 'AuthenticatorAppService', 'user'
  ];

  ViewRecoveryCodesController.$inject = [
    '$uibModalInstance', '$uibModal', 'AuthenticatorAppService'
  ];

  ResetRecoveryCodesController.$inject = [
    '$uibModalInstance', 'Utils', 'AuthenticatorAppService'
  ];

  function EnableAuthenticatorAppController(
    $scope, $uibModalInstance, Utils, AuthenticatorAppService, user, $uibModal) {
    var authAppCtrl = this;

    authAppCtrl.user = {
      ...user,
      code: ''
    };

    authAppCtrl.$onInit = function () {
      AuthenticatorAppService.addMfaSecretToUser().then(function (response) {
        authAppCtrl.secret = response.data.secret;
        authAppCtrl.dataUri = response.data.dataUri;
      });
    }

    authAppCtrl.codeMinlength = 6;
    authAppCtrl.requestPending = false;

    authAppCtrl.dismiss = dismiss;
    authAppCtrl.reset = reset;
    authAppCtrl.viewRecoveryCodes = viewRecoveryCodes;

    function reset() {
      console.log('reset form');

      authAppCtrl.user.code = '';

      if ($scope.authenticatorAppForm) {
        $scope.authenticatorAppForm.$setPristine();
      }

      authAppCtrl.requestPending = false;
    }

    authAppCtrl.reset();

    function dismiss() { return $uibModalInstance.dismiss('Cancel'); }

    function viewRecoveryCodes() {
      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/apps/dashboard-app/templates/home/view-recovery-codes.html',
        controller: 'ViewRecoveryCodesController',
        controllerAs: 'authAppCtrl',
        resolve: { user: function () { return self.user; } }
      });

      modalInstance.result.then(function (msg) {
        return $uibModalInstance.close(msg);
      });
    }

    authAppCtrl.message = '';

    authAppCtrl.submitEnable = function () {
      authAppCtrl.requestPending = true;
      AuthenticatorAppService
        .enableAuthenticatorApp(
          authAppCtrl.user.code)
        .then(function () {
          authAppCtrl.requestPending = false;
          authAppCtrl.viewRecoveryCodes();
          $uibModalInstance.close('Authenticator app enabled');
        })
        .catch(function (error) {
          authAppCtrl.requestPending = false;
          $scope.operationResult = Utils.buildErrorResult(error.data.error);
          authAppCtrl.reset();
        });
    };
  }

  function DisableAuthenticatorAppController(
    $scope, $uibModalInstance, Utils, AuthenticatorAppService, user) {
    var authAppCtrl = this;

    authAppCtrl.user = {
      ...user,
      code: ''
    };

    authAppCtrl.codeMinlength = 6;
    authAppCtrl.requestPending = false;

    authAppCtrl.dismiss = dismiss;
    authAppCtrl.reset = reset;

    function reset() {
      console.log('reset form');

      authAppCtrl.user.code = '';

      if ($scope.authenticatorAppForm) {
        $scope.authenticatorAppForm.$setPristine();
      }

      authAppCtrl.requestPending = false;
    }

    authAppCtrl.reset();

    function dismiss() { return $uibModalInstance.dismiss('Cancel'); }

    authAppCtrl.message = '';

    authAppCtrl.submitDisable = function () {
      authAppCtrl.requestPending = true;
      AuthenticatorAppService
        .disableAuthenticatorApp(
          authAppCtrl.user.code)
        .then(function () {
          authAppCtrl.requestPending = false;
          return $uibModalInstance.close('Authenticator app disabled');
        })
        .catch(function (error) {
          authAppCtrl.requestPending = false;
          $scope.operationResult = Utils.buildErrorResult(error.data.error);
          authAppCtrl.reset();
        });
    };
  }

  function ViewRecoveryCodesController($uibModalInstance, $uibModal, AuthenticatorAppService) {
    var authAppCtrl = this;
    authAppCtrl.populateRecoveryCodes = populateRecoveryCodes;
    authAppCtrl.dismiss = dismiss;
    authAppCtrl.resetRecoveryCodesConfirmation = resetRecoveryCodesConfirmation;
    authAppCtrl.disabled = false;

    authAppCtrl.$onInit = function () {
      populateRecoveryCodes();
    }

    function populateRecoveryCodes() {
      AuthenticatorAppService.viewRecoveryCodes().then(function (response) {
        authAppCtrl.recoveryCodes = response.data;
        buildListElement();
      });
    }

    function buildListElement() {
      var str = '<ul>';
      authAppCtrl.recoveryCodes.forEach(function (recoveryCode) {
        str += '<li>' + recoveryCode + '</li>';
      });
      str += '</ul>';
      document.getElementById("recoveryCodes").innerHTML = str;
    }

    function dismiss() { return $uibModalInstance.dismiss('Back'); }

    function resetRecoveryCodesConfirmation() {
      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/apps/dashboard-app/templates/home/recovery-codes-reset-confirm.html',
        controller: 'ResetRecoveryCodesController',
        controllerAs: 'authAppCtrl',
        resolve: { user: function () { return self.user; } }
      });

      modalInstance.result.then(function () {
        populateRecoveryCodes();
      });
    }
  }

  function ResetRecoveryCodesController($uibModalInstance, Utils, AuthenticatorAppService) {
    var authAppCtrl = this;
    authAppCtrl.dismiss = dismiss;
    authAppCtrl.resetRecoveryCodes = resetRecoveryCodes;
    authAppCtrl.requestPending = false;

    function dismiss() { return $uibModalInstance.dismiss('Back'); }

    function resetRecoveryCodes() {
      authAppCtrl.requestPending = true;
      AuthenticatorAppService.resetRecoveryCodes()
        .then(function () {
          authAppCtrl.requestPending = false;
          $uibModalInstance.close('Recovery codes updated');
        })
        .catch(function (error) {
          authAppCtrl.requestPending = false;
          $scope.operationResult = Utils.buildErrorResult(error.data);
        });
    }
  }

})();