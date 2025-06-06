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

  function EditMfaController(
      toaster, Utils, ModalService, $uibModal) {
    var self = this;

    self.$onInit = function() {
      console.log('EditMfaController onInit');
      self.enabled = true;
      self.user = self.userCtrl.user;
    };

    self.isMe = function() { return self.userCtrl.isMe(); };

    self.isMfaActive = function() { return self.userCtrl.user.isMfaActive; };

    self.openUserMfaModal = function() {
      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/apps/dashboard-app/templates/home/editmfasettings.html',
        controller: 'UserMfaController',
        controllerAs: 'userMfaCtrl',
        resolve: {user: function() { return self.user; }}
      });

      modalInstance.result.then(function (msg) {
        self.userCtrl.loadUser().then(function () {
          toaster.pop({
            type: 'success',
            body: msg
          });
        });
      });
    };
  }



  angular.module('dashboardApp').component('userMfa', {
    require: {userCtrl: '^user'},
    templateUrl:
        '/resources/iam/apps/dashboard-app/components/user/mfa/user.mfa.component.html',
    controller: [
      'toaster', 'Utils', 'ModalService', '$uibModal',
      EditMfaController
    ]
  });
})();