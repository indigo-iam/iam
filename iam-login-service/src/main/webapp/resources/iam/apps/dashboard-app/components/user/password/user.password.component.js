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

  function UserPasswordController(
      toaster, Utils, ModalService, ResetPasswordService, $uibModal) {
    var self = this;

    self.$onInit = function() {
      console.log('UserPasswordController onInit');
      self.enabled = true;
      self.user = self.userCtrl.user;
    };

    self.isMe = function() { return self.userCtrl.isMe(); };

    self.doPasswordReset = function() {

      ResetPasswordService.forgotPassword(self.user.emails[0].value)
          .then(
              function(response) {
                toaster.pop({
                  type: 'success',
                  body:
                      'A password reset link has just been sent to the user email address'
                });
              },
              function(error) { toaster.pop({type: 'error', body: error}); });
    };

    self.openResetPasswordModal = function() {
      self.enabled = false;

      var modalOptions = {
        closeButtonText: 'Cancel',
        actionButtonText: 'Send password reset e-mail',
        headerText: 'Send password reset e-mail',
        bodyText:
            `Are you sure you want to send the password reset e-mail to ${self.user.name.formatted}?`
      };

      ModalService.showModal({}, modalOptions)
          .then(
              function() {
                self.doPasswordReset();
                self.enabled = true;

              },
              function() { self.enabled = true; });

    };

    self.openEditPasswordModal = function() {

      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/apps/dashboard-app/templates/home/editpassword.html',
        controller: 'EditPasswordController',
        controllerAs: 'editPasswordCtrl',
        resolve: {user: function() { return self.user; }}
      });

      modalInstance.result.then(function(msg) {
        toaster.pop({type: 'success', body: msg});
      });
    };
  }



  angular.module('dashboardApp').component('userPassword', {
    require: {userCtrl: '^user'},
    templateUrl:
        '/resources/iam/apps/dashboard-app/components/user/password/user.password.component.html',
    controller: [
      'toaster', 'Utils', 'ModalService', 'ResetPasswordService', '$uibModal',
      UserPasswordController
    ]
  });
})();