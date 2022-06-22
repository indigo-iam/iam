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

    function SetEndTimeController($uibModalInstance, AccountLifecycleService, user, successHandler) {
        var self = this;

        self.user = user;


        self.indigoUser = function () {
            return self.user['urn:indigo-dc:scim:schemas:IndigoUser'];
        };

        self.cancel = function () {
            $uibModalInstance.dismiss('Dismissed');
        };

        self.setEndTime = function () {
            $uibModalInstance.close();
            return AccountLifecycleService.setAccountEndTime(self.user.id, self.endTime).then(successHandler);
        };

        self.removeEndTime = function () {
            self.endTime = undefined;
            $uibModalInstance.close();
            return AccountLifecycleService.setAccountEndTime(self.user.id, self.endTime).then(successHandler);
        };


        if (self.indigoUser() != undefined) {
            self.endTime = self.indigoUser().endTime;
        }
        else {
            self.endTime = undefined;
        }
    }

    function UserEndTimeController(toaster, AccountLifecycleService, $uibModal, $filter) {
        var self = this;

        self.$onInit = function () {
            console.log('UserEndTimeController onInit');
            AccountLifecycleService.readOnlyAccountEndTime().then(function (res) {
                self.readOnly = res;
            });
            self.enabled = true;
        };

        self.handleSuccess = function (res) {
            self.userCtrl.loadUser().then(function (user) {
                var msg = 'User end time removed';

                if (user['urn:indigo-dc:scim:schemas:IndigoUser'].endTime) {
                    msg = 'User end time set to ' + $filter('relativeDate')(user['urn:indigo-dc:scim:schemas:IndigoUser'].endTime);
                }

                toaster.pop({
                    type: 'success',
                    body: msg
                });
            });
        };

        self.handleError = function (res) {
            console.log(res);
        };

        self.openSetEndTimeDialog = function () {
            $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/user/end-time/user.set-end-time.dialog.html',
                controller: SetEndTimeController,
                controllerAs: '$ctrl',
                resolve: {
                    user: function () {
                        return self.user;
                    },
                    successHandler: function () {
                        return self.handleSuccess;
                    },
                    errorHandler: function () {
                        return self.handleError;
                    }
                }
            });
        };

    }

    angular.module('dashboardApp').component('userEndTime', {
        require: {
            userCtrl: '^user'
        },
        templateUrl: '/resources/iam/apps/dashboard-app/components/user/end-time/user.end-time.component.html',
        bindings: {
            user: '='
        },
        controller: [
            'toaster', 'AccountLifecycleService', '$uibModal', '$filter', UserEndTimeController
        ]
    });
})();