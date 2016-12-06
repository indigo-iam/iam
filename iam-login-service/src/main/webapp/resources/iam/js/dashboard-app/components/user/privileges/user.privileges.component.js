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
            '/resources/iam/template/dashboard/user/assign-vo-admin-privileges.html',
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
            '/resources/iam/template/dashboard/user/revoke-vo-admin-privileges.html',
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
        '/resources/iam/js/dashboard-app/components/user/privileges/user.privileges.component.html',
    bindings: {user: '='},
    controller: [
      'toaster', 'Utils', '$uibModal', 'Authorities', UserPrivilegesController
    ]
  });
})();