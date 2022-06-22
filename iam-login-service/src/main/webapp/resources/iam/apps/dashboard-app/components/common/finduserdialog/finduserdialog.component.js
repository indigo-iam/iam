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

    function FindUserDialogController(UsersService, Utils, $scope) {
        var self = this;

        self.ok = ok;
        self.cancel = cancel;
        self.lookupUser = lookupUser;
        self.userSelected = userSelected;
        self.title = 'Find user';
        self.action = 'Ok';
        self.enabled = true;

        self.$onInit = function () {
            console.debug('FindUserDialogController.self', self);
            if (self.resolve.title) {
                self.title = self.resolve.title;
            }

            if (self.resolve.action) {
                self.action = self.resolve.action;
            }
        };

        function userSelected(user) {
            self.selectedUser = user;
            self.enabled = true;
        }

        function lookupUser(val) {
            self.enabled = false;
            return UsersService.getUsersFilteredBy(0, 100, val).then(res => {
                return res.data.Resources;
            }).catch(err => {
                console.error("Error fetching users: ", res);
                return [];
            });
        }

        function ok() {
            self.close({ $value: self.selectedUser });
        }

        function cancel() {
            self.dismiss({ $value: 'cancel' });
        }
    }

    angular
        .module('dashboardApp')
        .component('findUserDialog', findUserDialog());


    function findUserDialog() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/common/finduserdialog/finduserdialog.component.html",
            bindings: {
                resolve: '<',
                close: '&',
                dismiss: '&'
            },
            controller: ['UsersService', 'Utils', '$scope', FindUserDialogController],
            controllerAs: '$ctrl'
        };
    }

}());