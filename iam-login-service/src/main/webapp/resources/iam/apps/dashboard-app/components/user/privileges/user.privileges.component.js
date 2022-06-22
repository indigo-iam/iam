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

  function UserPrivilegesController(toaster, Utils, $uibModal, Authorities) {
    var self = this;

    self.$onInit = function() {
      console.log('UserPrivilegesController onInit');
      self.enabled = true;
    };

    self.isMe = function() { return Utils.isMe(self.user.id); };

    self.userIsVoAdmin = function() { return self.userCtrl.userIsVoAdmin(); };

    self.openAssignDialog = function() {

      var modalInstance = $uibModal.open({
        templateUrl:
            '/resources/iam/apps/dashboard-app/templates/user/assign-vo-admin-privileges.html',
        controller: 'AccountPrivilegesController',
        controllerAs: 'ctrl',
        resolve: {user: function() { return self.user; }}
      });

      modalInstance.result.then(function() {
        self.userCtrl.loadUser().then(function(user) {
          toaster.pop({
            type: 'success',
            body: `User '${user.name.formatted}' is now a VO administrator.`
          });
        });
      });
    };

    self.openRevokeDialog = function() {

      var modalInstance = $uibModal.open({
        templateUrl:
            '/resources/iam/apps/dashboard-app/templates/user/revoke-vo-admin-privileges.html',
        controller: 'AccountPrivilegesController',
        controllerAs: 'ctrl',
        resolve: {user: function() { return self.user; }}
      });

      modalInstance.result.then(function() {
        self.userCtrl.loadUser().then(function(user) {
          toaster.pop({
            type: 'success',
            body:
                `User '${user.name.formatted}' is no longer a VO administrator.`
          });
        });
      });
    };
  }

  angular.module('dashboardApp').component('userPrivileges', {
    require: {userCtrl: '^user'},
    templateUrl:
        '/resources/iam/apps/dashboard-app/components/user/privileges/user.privileges.component.html',
    bindings: {user: '='},
    controller: [
      'toaster', 'Utils', '$uibModal', 'Authorities', UserPrivilegesController
    ]
  });
})();