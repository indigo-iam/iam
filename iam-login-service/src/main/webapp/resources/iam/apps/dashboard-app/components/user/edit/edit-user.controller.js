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

  angular.module('dashboardApp')
    .controller('EditUserController', EditUserController);

  EditUserController.$inject = [
    '$scope', '$rootScope', '$uibModalInstance', 'Utils',
    'scimFactory', 'user', 'userProfileProperties'
  ];

  function EditUserController(
    $scope, $rootScope, $uibModalInstance, Utils, scimFactory, user, userProfileProperties) {
    var self = this;

    self.pattern = "^[^<>%$]*$";

    self.oUser = user;
    self.id = user.id;

    self.submit = submit;
    self.reset = reset;
    self.dismiss = dismiss;
    self.isSubmitDisabled = isSubmitDisabled;
    self.isUserEditableField = isUserEditableField;
    self.isAdmin = isAdmin;

    self.userProfileProperties = userProfileProperties;

    self.reset();

    function isAdmin() {
      return Utils.isAdmin();
    }

    function submit() {
      self.enabled = false;

      var operations = [];

      // remove picture if it's dirty and empty
      if ($scope.userUpdateForm.picture.$dirty && !self.eUser.picture) {
        operations.push({
          op: 'remove',
          value: {
            photos: self.oUser.photos
          }
        });
      }

      if ($scope.userUpdateForm.name.$dirty ||
        $scope.userUpdateForm.surname.$dirty) {
        operations.push({
          op: 'replace',
          value: {
            displayName: self.eUser.name + ' ' + self.eUser.surname,
            name: {
              givenName: self.eUser.name,
              familyName: self.eUser.surname,
              middleName: ''
            }
          }
        });
      }
      if ($scope.userUpdateForm.email.$dirty) {
        operations.push({
          op: 'replace',
          value: {
            emails: [{
              type: 'work',
              value: self.eUser.email,
              primary: true
            }]
          }
        });
      }
      if ($scope.userUpdateForm.username.$dirty) {
        operations.push({
          op: 'replace',
          value: {
            userName: self.eUser.username
          }
        });
      }
      if ($scope.userUpdateForm.picture.$dirty) {
        operations.push({
          op: 'replace',
          value: {
            photos: [{
              type: 'photo',
              value: self.eUser.picture
            }]
          }
        });
      }

      console.info('Operations ... ', operations);

      var promise = null;

      if (Utils.isMe(user.id)) {
        promise = scimFactory.updateMe(operations);
      } else {
        promise = scimFactory.updateUser(user.id, operations);
      }

      promise
        .then(function (response) {
          if (Utils.isMe(user.id)) {
            $rootScope.reloadInfo();
          }

          $uibModalInstance.close(response);
          self.enabled = true;

        })
        .catch(function (error) {
          $scope.operationResult = Utils.buildErrorOperationResult(error);
          self.enabled = true;
        });
    }

    function reset() {
      self.eUser = {
        name: self.oUser.name.givenName,
        surname: self.oUser.name.familyName,
        picture: self.oUser.photos ? self.oUser.photos[0].value : '',
        email: self.oUser.emails[0].value,
        username: self.oUser.userName
      };
      if ($scope.userUpdateForm) {
        $scope.userUpdateForm.$setPristine();
      }
      self.enabled = true;
    }

    function isUserEditableField(name) {
      return userProfileProperties.editableFields.includes(name);
    }

    function dismiss() {
      $uibModalInstance.dismiss('Cancel');
    }

    function isSubmitDisabled() {
      return !self.enabled || !$scope.userUpdateForm.$dirty ||
        $scope.userUpdateForm.name.$invalid ||
        $scope.userUpdateForm.surname.$invalid ||
        ($scope.userUpdateForm.email.$invalid && $scope.userUpdateForm.email.$dirty) ||
        ($scope.userUpdateForm.username.$invalid && $scope.userUpdateForm.username.$dirty) ||
        $scope.userUpdateForm.picture.$invalid;
    }
  }
})();