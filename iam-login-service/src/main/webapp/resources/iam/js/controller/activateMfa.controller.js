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

'use strict';

angular.module('activateMfaApp').controller('ActivateMfaController', ActivateMfaController);


ActivateMfaController.$inject = [
  '$scope', '$window', 'ActivateMfaService'
];

function ActivateMfaController($scope, $window, ActivateMfaService) {
  var authAppCtrl = this;

  
  authAppCtrl.user = {user:'', code: ''};
  authAppCtrl.secret = null;
  authAppCtrl.dataUri = null;
  
  authAppCtrl.codeMinlength = 6;
  authAppCtrl.requestPending = false;
  $scope.operationResult = null;
  authAppCtrl.reset = reset;

  authAppCtrl.$onInit = function () {
    ActivateMfaService.addMfaSecretToUser().then(function (response) {
      authAppCtrl.secret = response.data.secret;
      authAppCtrl.dataUri = response.data.dataUri;
    });
  }

  
  authAppCtrl.$onInit = function () {
    setPending(true);
    ActivateMfaService.addMfaSecretToUser()
      .then(function (response) {
        var data = (response && response.data) || {};
        authAppCtrl.secret = data.secret || null;
        authAppCtrl.dataUri = data.dataUri || null;
      })
      .catch(handleError)
      .finally(function () { setPending(false); });

    authAppCtrl.reset();
  };


  function reset() {
    console.log('Reset form');

    authAppCtrl.user.code = '';
    $scope.operationResult = null;

    if ($scope.activateMfaForm) {
      $scope.activateMfaForm.$setPristine();
    }

    setPending(false);
  }

  authAppCtrl.reset();

  authAppCtrl.clearError = function () {
    $scope.operationResult = null;
  };

  authAppCtrl.submitEnable = function () {
    
      if (authAppCtrl.requestPending) { return; }
      if ($scope.activateMfaForm && $scope.activateMfaForm.$invalid) { return; }
      if (!authAppCtrl.user.code || authAppCtrl.user.code.length < authAppCtrl.codeMinlength) { return; }

      setPending(true);

    ActivateMfaService.enableAuthenticatorApp(authAppCtrl.user.code)
      .then(function () {
        $window.location.href = '/logout';
      })
      .catch(handleError)
      .finally(function () { setPending(false); });
  };

  
  function setPending(val) {
    authAppCtrl.requestPending = !!val;
  }

  function handleError(error) {
    var msg =
      (error && error.data && error.data.error) ||
      (error && error.message) ||
      'Something went wrong. Please try again.';
    $scope.operationResult = { type: 'error', text: msg };
    authAppCtrl.user.code = '';
  }

}