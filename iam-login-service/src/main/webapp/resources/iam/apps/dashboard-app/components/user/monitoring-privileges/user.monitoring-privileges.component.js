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

  function UserMonitoringPrivilegesController(toaster, Utils, $uibModal, Authorities) {
    var self = this;

    self.$onInit = function() {
      console.log('UserMonitoringPrivilegesController onInit');
      self.enabled = true;
    };

    self.isMe = function() { return Utils.isMe(self.user.id); };

    self.userIsReader = function() { return self.userCtrl.userIsReader(); };

    self.openAssignDialog = function() {

      var modalInstance = $uibModal.open({
        templateUrl:
            '/resources/iam/apps/dashboard-app/templates/user/assign-monitoring-privileges.html',
        controller: 'MonitoringPrivilegesController',
        controllerAs: 'ctrl',
        resolve: {user: function() { return self.user; }}
      });

      modalInstance.result.then(function() {
        self.userCtrl.loadUser().then(function(user) {
          toaster.pop({
            type: 'success',
            body: `User '${user.name.formatted}' now has monitoring privileges.`
          });
        });
      });
    };

    self.openRevokeDialog = function() {

      var modalInstance = $uibModal.open({
        templateUrl:
            '/resources/iam/apps/dashboard-app/templates/user/revoke-monitoring-privileges.html',
        controller: 'MonitoringPrivilegesController',
        controllerAs: 'ctrl',
        resolve: {user: function() { return self.user; }}
      });

      modalInstance.result.then(function() {
        self.userCtrl.loadUser().then(function(user) {
          toaster.pop({
            type: 'success',
            body:
                `User '${user.name.formatted}' no longer has monitoring prilileges.`
          });
        });
      });
    };
  }

  angular.module('dashboardApp').component('userMonitoringPrivileges', {
    require: {userCtrl: '^user'},
    templateUrl:
        '/resources/iam/apps/dashboard-app/components/user/monitoring-privileges/user.monitoring-privileges.component.html',
    bindings: {user: '='},
    controller: [
      'toaster', 'Utils', '$uibModal', 'Authorities', UserMonitoringPrivilegesController
    ]
  });
})();