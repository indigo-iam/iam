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
'use strict'

angular.module('passwordResetApp').controller('ResetPasswordController', ResetPasswordController);

ResetPasswordController.$inject = ['$scope', 'ResetPasswordService']

function ResetPasswordController($scope, ResetPasswordService) {
    var vm = this;
    vm.password;
    vm.passwordrepeat;
    vm.resetkey;
    vm.operationResult;
    vm.textAlert;

    vm.submit = submit;
    vm.reset = reset;




    function submit() {
        ResetPasswordService.changePassword(vm.resetKey, vm.password).then(
            function(response) {
                vm.operationResult = 'ok';
                vm.reset();
            },
            function(data) {
                vm.operationResult = 'err';
                if (data.status == -1) {
                    vm.textAlert = 'Could not enstabilish a connection to the IAM server. Are you online?'
                } else {
                    vm.textAlert = data.statusText + ': ' + data.data;
                }
            }
        );
    };

    function reset() {
        vm.password = '';
        vm.passwordrepeat = '';
        $scope.changePasswdForm.$setPristine();
    };
};


angular.module('passwordResetApp').controller('ForgotPasswordController', ForgotPasswordController);

ForgotPasswordController.$inject = ['$scope', '$uibModalInstance', 'ResetPasswordService']

function ForgotPasswordController($scope, $uibModalInstance, ResetPasswordService) {

    $scope.email;

    $scope.organisationName = getOrganisationName();

    $scope.submit = function() {
        ResetPasswordService.forgotPassword($scope.email).then(
            function(response) {
                $scope.operationResult = 'ok';
            },
            function(data) {
                $scope.operationResult = 'err';
                if (data.status == -1) {
                    $scope.textAlert = 'Could not enstabilish a connection to the IAM server. Are you online?'
                } else {
                    $scope.textAlert = data.statusText + ': ' + data.data;
                }
            });
        $scope.reset();
    }

    $scope.dismiss = function() {
        $uibModalInstance.close();
    };

    $scope.reset = function() {
        $scope.email = '';
        $scope.forgotPasswordForm.$setPristine();
    }
};


angular.module('passwordResetApp').controller('ForgotPasswordModalController', ForgotPasswordModalController);

ForgotPasswordModalController.$inject = ['$scope', '$uibModal'];

function ForgotPasswordModalController($scope, $uibModal) {
    $scope.open = function() {
        $uibModal.open({
            templateUrl: "/resources/iam/template/forgotPassword.html",
            controller: "ForgotPasswordController",
            size: '600px',
            animation: true
        });
    };
}