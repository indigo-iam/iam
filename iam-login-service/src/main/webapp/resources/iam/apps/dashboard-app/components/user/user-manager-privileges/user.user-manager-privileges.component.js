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

  function UserUserManagerPrivilegesController(toaster, Utils, $uibModal, Authorities) {
    var self = this;

    self.$onInit = function() {
      console.log('UserUserManagerPrivilegesController onInit');
      self.enabled = true;
    };

    self.isMe = function() { return Utils.isMe(self.user.id); };

    self.userIsUserManager = function() { return self.userCtrl.userIsUserManager(); };

    self.openAssignDialog = function() {

      var modalInstance = $uibModal.open({
        templateUrl:
            '/resources/iam/apps/dashboard-app/templates/user/assign-user-manager-privileges.html',
        controller: 'UserManagerPrivilegesController',
        controllerAs: 'ctrl',
        resolve: {user: function() { return self.user; }}
      });

      modalInstance.result.then(function() {
        self.userCtrl.loadUser().then(function(user) {
          toaster.pop({
            type: 'success',
            body: `User '${user.name.formatted}' now has user management privileges.`
          });
        });
      });
    };

    self.openRevokeDialog = function() {

      var modalInstance = $uibModal.open({
        templateUrl:
            '/resources/iam/apps/dashboard-app/templates/user/revoke-user-manager-privileges.html',
        controller: 'UserManagerPrivilegesController',
        controllerAs: 'ctrl',
        resolve: {user: function() { return self.user; }}
      });

      modalInstance.result.then(function() {
        self.userCtrl.loadUser().then(function(user) {
          toaster.pop({
            type: 'success',
            body:
                `User '${user.name.formatted}' no longer has user management privileges.`
          });
        });
      });
    };
  }

  angular.module('dashboardApp').component('userUserManagerPrivileges', {
    require: {userCtrl: '^user'},
    templateUrl:
        '/resources/iam/apps/dashboard-app/components/user/user-manager-privileges/user.user-manager-privileges.component.html',
    bindings: {user: '='},
    controller: [
      'toaster', 'Utils', '$uibModal', 'Authorities', UserUserManagerPrivilegesController
    ]
  });
})();
