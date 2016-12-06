(function() {
  'use strict';

  function UserGroupsController(toaster, $uibModal, ModalService, scimFactory) {
    var self = this;

    self.$onInit = function() {
      console.log('UserGroupsController onInit');
      self.enabled = true;
    };

    self.isVoAdmin = function() { return self.userCtrl.isVoAdmin(); };

    self.handleSuccess = function() {
      self.enabled = true;
      self.userCtrl.loadUser().then(function(user) {
        toaster.pop({
          type: 'success',
          body: `User '${user.name.formatted}' groups updated succesfully`
        });
      });
    };

    self.openAddGroupDialog = function() {
      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/template/dashboard/user/addusergroup.html',
        controller: 'AddUserGroupController',
        controllerAs: 'addGroupCtrl',
        resolve: {user: function() { return self.user; }}
      });

      modalInstance.result.then(self.handleSuccess);

    };

    self.openRemoveGroupDialog = function(group) {
      var modalOptions = {
        closeButtonText: 'Cancel',
        actionButtonText: 'Remove user from group',
        headerText:
            `Remove  '${self.user.name.formatted}' from group '${group.display}'`,
        bodyText:
            `Are you sure you want to remove '${self.user.name.formatted}' from group '${group.display}'?`
      };

      ModalService.showModal({}, modalOptions).then(function() {
        scimFactory
            .removeUserFromGroup(
                group.value, self.user.id, self.user.meta.location,
                self.user.name.formatted)
            .then(self.handleSuccess)
            .catch(self.userCtrl.handleError);
      });

    };
  }

  angular.module('dashboardApp').component('userGroups', {
    require: {userCtrl: '^user'},
    bindings: {user: '='},
    templateUrl:
        '/resources/iam/js/dashboard-app/components/user/groups/user.groups.component.html',
    controller: [
      'toaster', '$uibModal', 'ModalService', 'scimFactory',
      UserGroupsController
    ]
  });
})();