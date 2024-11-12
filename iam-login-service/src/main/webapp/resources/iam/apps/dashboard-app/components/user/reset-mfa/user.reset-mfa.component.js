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
(function() {
  'use strict';

  function ResetMfaController(
      toaster, Utils, ModalService, $uibModal) {
    var self = this;

    self.$onInit = function () {
      console.log('ResetMfaController onInit');
      self.enabled = true;
      self.user = self.userCtrl.user;
    };

    self.isMe = function() { return self.userCtrl.isMe(); };
    self.isVoAdmin = function () { return self.userCtrl.isVoAdmin(); };

    self.openResetMfaModal = function() {
      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/apps/dashboard-app/templates/home/resetMfaSettings.html',
        controller: 'ResetMfaController',
        controllerAs: 'resetMfaCtrl',
        resolve: {user: function() { return self.user; }}
      });

      modalInstance.result.then(function(msg) {
        self.userCtrl.loadUser().then(function () {
          toaster.pop({
            type: 'success',
            body: msg
          });
        });
      });
    };
  }



  angular.module('dashboardApp').component('userResetMfa', {
    require: {userCtrl: '^user'},
    templateUrl:
        '/resources/iam/apps/dashboard-app/components/user/reset-mfa/user.reset-mfa.component.html',
    controller: [
      'toaster', 'Utils', 'ModalService', '$uibModal',
      ResetMfaController
    ]
  });
})();