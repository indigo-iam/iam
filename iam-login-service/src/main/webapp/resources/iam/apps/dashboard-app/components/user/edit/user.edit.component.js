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

  function UserEditController(toaster, Utils, $uibModal, scimFactory) {
    var self = this;

    self.$onInit = function () {
      console.log('userEditController onInit');
      self.enabled = true;
    };

    self.handleSuccess = function () {
      self.enabled = true;
      self.userCtrl.loadUser().then(function (user) {
        toaster.pop({
          type: 'success',
          body: `User '${user.name.formatted}' updated succesfully.`
        });
      });
    };

    self.openDialog = function () {
      self.enabled = false;
      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/apps/dashboard-app/components/user/edit/edit-user.dialog.html',
        controller: 'EditUserController',
        controllerAs: '$ctrl',
        resolve: {
          user: function () {
            return self.user;
          },
          userProfileProperties: function () {
            return scimFactory.getUserProfileConfig();
          }
        }
      });

      modalInstance.result.then(self.handleSuccess);

    };
  }

  angular.module('dashboardApp').component('userEdit', {
    require: {
      userCtrl: '^user'
    },
    templateUrl: '/resources/iam/apps/dashboard-app/components/user/edit/user.edit.component.html',
    bindings: {
      user: '='
    },
    controller: ['toaster', 'Utils', '$uibModal', 'scimFactory', UserEditController]
  });
})();