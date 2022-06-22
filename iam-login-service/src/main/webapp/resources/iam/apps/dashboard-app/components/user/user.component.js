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

    function UserController(
        $timeout, $cookies, $rootScope, $uibModal, ModalService, scimFactory,
        UserService, Utils, toaster) {
        var self = this;

        self.$onInit = function () {
            console.log('userController onInit');
            self.loaded = true;
            $timeout(self.showAccountLinkingFeedback, 0);
        };

        self.accountLinkingEnabled = getAccountLinkingEnabled();
        self.externalAuthenticationEnabled = getExternalAuthenticationEnabled();

        self.isVoAdmin = function () {
            return Utils.isAdmin();
        };

        self.userIsVoAdmin = function () {
            return Utils.userIsVoAdmin(self.user);
        };

        self.isMe = function () {
            return Utils.isMe(self.user.id);
        };

        self.canManageLinkedAccounts = function () {
            if (!self.accountLinkingEnabled) {
                return self.isVoAdmin();
            }

            return self.isVoAdmin() && !self.isMe();
        };

        self.canLinkAccounts = function () {
            return self.accountLinkingEnabled && self.isMe();
        };

        self.showAccountLinkingFeedback = function () {
            if (_accountLinkingError) {
                toaster.pop({
                    type: 'error',
                    body: _accountLinkingError
                });
                _accountLinkingError = '';
            }

            if (_accountLinkingMessage) {
                toaster.pop({
                    type: 'success',
                    body: _accountLinkingMessage
                });
                _accountLinkingMessage = '';
            }
        };

        self.handleError = function (error) {
            console.error(error);
            toaster.pop({
                type: 'error',
                body: error
            });
        };

        self.openLoadingModal = function () {
            $rootScope.pageLoadingProgress = 0;
            self.modal = $uibModal.open({
                animation: false,
                templateUrl: '/resources/iam/apps/dashboard-app/templates/loading-modal.html'
            });

            return self.modal.opened;
        };

        self.closeLoadingModal = function () {
            $rootScope.pageLoadingProgress = 100;
            self.modal.dismiss('Cancel');
        };

        self.loadUser = function () {

            return self.openLoadingModal()
                .then(function () {
                    if (self.isMe()) {
                        return UserService.getMe();
                    } else {
                        return UserService.getUser(self.user.id);
                    }
                })
                .then(function (user) {
                    self.user = user;
                    self.closeLoadingModal();
                    return user;
                })
                .catch(self.handleError);
        };
    }


    angular.module('dashboardApp').component('user', {
        templateUrl: '/resources/iam/apps/dashboard-app/components/user/user.component.html',
        bindings: {
            user: '<',
            aup: '<',
            labels: '<',
            attrs: '<'
        },
        controller: [
            '$timeout', '$cookies', '$rootScope', '$uibModal', 'ModalService',
            'scimFactory', 'UserService', 'Utils', 'toaster', UserController
        ]
    });
})();