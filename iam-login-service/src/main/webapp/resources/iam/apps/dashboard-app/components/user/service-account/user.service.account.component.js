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

  function UserServiceAccountStatusController(toaster, Utils, ModalService, scimFactory) {
    var self = this;

    self.$onInit = function() {
      self.enabled = true;
    };

    self.handleError = function(error) {
      self.userCtrl.handleError(error);
      self.enabled = true;
    };

    self.handleSuccess = function() {
      self.enabled = true;
      self.userCtrl.loadUser().then(function(user) {
        if (self.indigoUser().serviceAccount) {
          toaster.pop({
            type: 'success',
            body:
                `User '${user.name.formatted}' has been set as service account successfully.`
          });
        } else {
          toaster.pop({
            type: 'success',
            body: `User '${user.name.formatted}' is no longer a service account.`
          });
        }
      });
    };

    self.setServiceAccountStatus = function() {
      return scimFactory.setServiceAccountStatus(self.user.id, true)
          .then(self.handleSuccess)
          .catch(self.handleError);
    };

    self.revokeServiceAccountStatus = function() {
      return scimFactory.setServiceAccountStatus(self.user.id, false)
          .then(self.handleSuccess)
          .catch(self.handleError);
    };


    self.openDialog = function() {

      var modalOptions = null;
      var updateServiceAccountStatusFunc = null;

      if (self.indigoUser().serviceAccount) {
        modalOptions = {
          closeButtonText: 'Cancel',
          actionButtonText: 'Revoke service account status',
          headerText: 'Revoke service account status of ' + self.user.name.formatted,
          bodyText:
              `Are you sure you want to revoke service account status of '${self.user.name.formatted}'?`
        };
        updateServiceAccountStatusFunc = self.revokeServiceAccountStatus;
      } else {
        modalOptions = {
          closeButtonText: 'Cancel',
          actionButtonText: 'Set as service account',
          headerText: 'Set ' + self.user.name.formatted + ' as service account',
          bodyText:
              `Are you sure you want to set user '${self.user.name.formatted}' as service account?`
        };
        updateServiceAccountStatusFunc = self.setServiceAccountStatus;
      }

      self.enable = false;
      ModalService.showModal({}, modalOptions)
          .then(function() { updateServiceAccountStatusFunc(); })
          .catch(function() {

          });
    };


    self.isMe = function() { return Utils.isMe(self.user.id); };
    self.indigoUser = function() { return self.userCtrl.indigoUser(); };
  }

  angular.module('dashboardApp').component('userServiceAccount', {
    require: {userCtrl: '^user'},
    bindings: {user: '='},
    templateUrl:
        '/resources/iam/apps/dashboard-app/components/user/service-account/user.service.account.component.html',
    controller: [
      'toaster', 'Utils', 'ModalService', 'scimFactory', UserServiceAccountStatusController
    ]
  });

})();