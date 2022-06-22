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

  function DeleteUserController($rootScope, $uibModalInstance, scimFactory, user) {
    var self = this;

    self.user = user;
    self.enabled = true;
    self.error = undefined;

    self.doDelete = function (user) {
      self.error = undefined;
      self.enabled = false;
      scimFactory.deleteUser(user.id).then(function (response) {
        $uibModalInstance.close(user);
        $rootScope.usersCount--;
        self.enabled = true;
      }).catch(function (error) {
        console.error(error);
        self.error = error;
        self.enabled = true;
      });
    };

    self.cancel = function () {
      $uibModalInstance.dismiss('Dismissed');
    };
  }

  function AddNewUserController($rootScope, $scope, $uibModalInstance, scimFactory, Utils) {
    var self = this;

    self.group = {};

    self.$onInit = function () {
      self.enabled = true;
      self.reset();
    };

    self.reset = function () {
      self.user = {
        name: '',
        surname: '',
        username: '',
        email: ''
      };
      if ($scope.userCreationForm) {
        $scope.userCreationForm.$setPristine();
      }
      self.enabled = true;
    };

    self.submit = function () {

      console.log("User info to add ", self.user);
      self.enabled = false;

      var scimUser = {};

      scimUser.id = Utils.uuid();
      scimUser.schemas = [];
      scimUser.schemas[0] = "urn:ietf:params:scim:schemas:core:2.0:User";
      scimUser.displayName = self.user.name + " " + self.user.surname;
      scimUser.name = {
        givenName: self.user.name,
        familyName: self.user.surname,
        middleName: ""
      };
      scimUser.emails = [{
        type: "work",
        value: self.user.email,
        primary: true
      }];
      scimUser.userName = self.user.username;
      scimUser.active = true;
      scimUser.picture = "";

      console.info("Adding user ... ", scimUser);

      scimFactory.createUser(scimUser).then(
        function (response) {
          console.info("Returned created user", response.data);
          $rootScope.usersCount++;
          $uibModalInstance.close(response.data);
          self.enabled = true;
        },
        function (error) {
          console.error('Error creating user', error);
          self.error = error;
          self.enabled = true;
        });
    };

    self.cancel = function () {
      $uibModalInstance.dismiss("cancel");
    };
  }

  function UsersListController($q, $scope, $rootScope, $uibModal, ModalService,
    UsersService, Utils, clipboardService, toaster) {

    var self = this;

    self.$onInit = function () {
      console.debug("UsersListController.self", self);
      // pagination controls
      self.currentPage = 1;
      self.currentOffset = 1;
      self.itemsPerPage = 10;
      self.totalResults = self.total;
      self.sortByValue = "name";
      self.sortDirection = "asc";
    };

    $scope.$on('refreshUsersList', function (e) {
      console.debug("received refreshUsersList event");
      self.searchUsers();
    });

    self.updateUsersCount = function (responseValue) {
      if (self.filter) {
        if (responseValue > $rootScope.usersCount) {
          $rootScope.usersCount = responseValue;
        }
      } else {
        $rootScope.usersCount = responseValue;
      }
    };

    self.resetFilter = function () {
      self.filter = undefined;
      self.searchUsers(1);
    };

    self.searchUsers = function () {

      $rootScope.pageLoadingProgress = 0;
      self.loaded = false;
      self.users = [];
      self.currentOffset = (self.currentPage - 1) * self.itemsPerPage + 1;

      var handleResponse = function (response) {
        self.totalResults = response.data.totalResults;
        angular.forEach(response.data.Resources, function (user) {
          self.users.push(user);
        });
        $rootScope.pageLoadingProgress = 100;
        self.updateUsersCount(response.data.totalResults);
        self.loaded = true;
        self.loadingModal.dismiss("Cancel");
      };

      var handleError = function (error) {
        self.loadingModal.dismiss("Error");
        toaster.pop({ type: 'error', body: error });
      };

      self.loadingModal = $uibModal.open({
        animation: false,
        templateUrl: '/resources/iam/apps/dashboard-app/templates/loading-modal.html'
      });

      self.loadingModal.opened.then(function () {
        return self.getUsersList(self.currentOffset, self.itemsPerPage, self.filter, self.sortByValue, self.sortDirection).then(handleResponse, handleError);
      });

      self.loadingModal.result.catch(res => {
        //do nothing, this is triggered by the modal dismiss
      });
    };

    self.getUsersList = function (startIndex, count, filter, sortByValue, sortDirection) {
      if (filter === undefined) {
        return UsersService.getUsersSortedBy(startIndex, count, sortByValue, sortDirection);
      }
      return UsersService.getUsersFilteredAndSortedBy(startIndex, count, filter, sortByValue, sortDirection);
    };

    self.sortBy = function (sortByValue, sortDirection) {
      self.sortByValue = sortByValue;
      self.sortDirection = sortDirection;
      self.searchUsers();
    };

    self.handleDeleteSuccess = function (user) {
      self.enabled = true;
      toaster.pop({
        type: 'success',
        body: 'User ' + user.name.formatted + ' has been removed successfully'
      });
      self.totalResults--;
      if (self.currentOffset > self.totalResults) {
        if (self.currentPage > 1) {
          self.currentPage--;
        }
      }
      self.searchUsers();
    };

    self.openDeleteUserDialog = function (user) {

      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/apps/dashboard-app/components/users/userslist/user.delete.dialog.html',
        controller: DeleteUserController,
        controllerAs: '$ctrl',
        resolve: {
          user: user
        }
      });

      modalInstance.result.then(self.handleDeleteSuccess);
    };

    self.handleAddNewUserSuccess = function (user) {
      toaster.pop({
        type: 'success',
        body: 'User ' + user.name.formatted + ' successfully added'
      });
      self.totalResults++;
      self.searchUsers(self.currentPage);
    };

    self.openAddNewUserDialog = function () {

      var modalInstance = $uibModal.open({
        templateUrl: '/resources/iam/apps/dashboard-app/components/users/userslist/user.add.dialog.html',
        controller: AddNewUserController,
        controllerAs: '$ctrl'
      });

      modalInstance.result.then(self.handleAddNewUserSuccess);
    };
  }

  angular
    .module('dashboardApp')
    .component(
      'userslist',
      {
        require: {
          $parent: '^users'
        },
        bindings: {
          users: '<',
          total: '<'
        },
        templateUrl: '/resources/iam/apps/dashboard-app/components/users/userslist/users.userslist.component.html',
        controller: ['$q', '$scope', '$rootScope', '$uibModal', 'ModalService',
          'UsersService', 'Utils', 'clipboardService', 'toaster', UsersListController]
      });
})();