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

    function RemoveSamlIdController($uibModalInstance, scimFactory, user, samlId) {
        var self = this;

        self.error = undefined;
        self.user = user;
        self.samlId = samlId;
        self.enabled = true;

        self.cancel = function () {
            $uibModalInstance.dismiss("Cancel");
        };

        self.doRemove = function () {
            self.enabled = false;
            self.error = undefined;
            scimFactory.removeSamlId(self.user.id, self.samlId).then(function (response) {
                $uibModalInstance.close('External account removed');
                self.enabled = true;
            }).catch(function (error) {
                console.error(error);
                self.error = error;
                self.enabled = true;
            });
        };
    }

    function RemoveOidcController($uibModalInstance, scimFactory, user, account) {
        var self = this;

        self.user = user;
        self.enabled = true;
        self.error = undefined;
        self.account = account;

        self.doRemove = function () {
            self.error = undefined;
            self.enabled = false;
            scimFactory.removeOpenIDAccount(self.user.id, self.account).then(function (response) {
                $uibModalInstance.close('External account removed');
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

    function LinkAccountController(AccountLinkingService, $uibModalInstance, oidcProviders,
        wayfLoginButton, samlLoginShortcuts) {
        var self = this;
        self.enabled = true;
        self.error = undefined;
        self.oidcProviders = oidcProviders.data;
        self.wayfLoginButton = wayfLoginButton.data;
        self.samlLoginShortcuts = samlLoginShortcuts.data;

        self.samlActionUrl = '/iam/account-linking/SAML';
        self.oidcActionUrl = '/iam/account-linking/OIDC';

        self.doLinkOidc = function (provider) {
            self.enabled = false;
            var issuerElement = angular.element(document.querySelector('#oidc-issuer'));
            issuerElement.val(provider.issuer);
            document.getElementById("link-oidc-account-form").submit();
        };

        self.doLinkSaml = function (provider) {
            self.enabled = false;
            var idpIdElement = angular.element(document.querySelector('#idp-id'));

            if (provider === undefined) {
                idpIdElement.remove();
            } else {
                idpIdElement.val(provider.entityId);
            }
            document.getElementById("link-saml-account-form").submit();
        };

        self.cancel = function () {
            $uibModalInstance.dismiss('Dismissed');
        };

    }

    function LinkSamlController(AccountLinkingService, $uibModalInstance, action, account) {
        var self = this;

        self.enabled = true;
        self.showLinkButton = true;
        self.action = action;
        self.actionUrl = '/iam/account-linking/SAML';
        self.type = 'SAML';
        self.account = account;
        self.error = undefined;

        self.doLink = function () {
            self.enabled = false;
            document.getElementById("link-account-form").submit();
        };


        self.doUnlink = function () {
            self.enabled = false;
            self.error = undefined;

            AccountLinkingService.unlinkSamlAccount({
                iss: self.account.idpId,
                attr: self.account.attributeId,
                sub: self.account.userId
            }).then(function (response) {
                $uibModalInstance.close("External account unlinked");
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

    function LinkOidcController(AccountLinkingService, $uibModalInstance, action, account) {
        var self = this;

        self.action = action;
        self.actionUrl = '/iam/account-linking/OIDC';
        self.type = 'OpenID-Connect';
        self.account = account;
        self.enabled = true;
        self.showLinkButton = false;
        self.providers = [];

        self.linkOidcAccount = linkOidcAccount;

        self.doLink = function () {
            self.enabled = false;
            document.getElementById("link-account-form").submit();
        };

        self.doUnlink = function () {
            self.enabled = false;
            AccountLinkingService.unlinkOidcAccount(self.account).then(function (response) {
                $uibModalInstance.close("External account unlinked");
            }).catch(function (error) {
                console.error(error);
            });
        };

        self.cancel = function () {
            $uibModalInstance.dismiss('Dismissed');
        };

        function linkOidcAccount(issuerName) {
            var provider = findOidcProvider(issuerName);
            var input = angular.element(document.querySelector('#oidc-issuer'));
            input.val(provider.issuer);
            document.getElementById("oidc-link-account").submit();
        }
    }

    function UserLinkedAccountsController($uibModal, toaster, AccountLinkingService) {
        var self = this;

        self.indigoUser = function () {
            return self.user['urn:indigo-dc:scim:schemas:IndigoUser'];
        };

        self.$onInit = function () {
            console.log('UserLinkedAccountsController onInit');
            self.enabled = true;
        };

        self.hasOidcIds = function () {
            var oidcIds = self.getOidcIds();

            if (oidcIds) {
                return oidcIds.length > 0;
            }

            return false;
        };

        self.hasSamlIds = function () {

            var samlIds = self.getSamlIds();

            if (samlIds) {
                return samlIds.length > 0;
            }

            return false;
        };

        self.getSamlIds = function () {
            if (self.indigoUser()) {
                return self.indigoUser().samlIds;
            }

            return undefined;
        };

        self.getOidcIds = function () {
            if (self.indigoUser()) {
                return self.indigoUser().oidcIds;
            }

            return undefined;
        };

        self.isGoogleAccount = function (oidcId) {
            if (!oidcId) {
                return false;
            }

            return oidcId.issuer == "https://accounts.google.com";
        };

        self.openLinkExternalAccountDialog = function () {
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/user/linked-accounts/account.link.dialog.html',
                controller: LinkAccountController,
                controllerAs: '$ctrl',
                size: 'lg',
                resolve: {
                    oidcProviders: function () {
                        return AccountLinkingService.getOidcProviders();
                    },
                    wayfLoginButton: function () {
                        return AccountLinkingService.getWayfLoginButtonConfiguration();
                    },
                    samlLoginShortcuts: function () {
                        return AccountLinkingService.getSamlLoginShortcuts();
                    }
                }
            });

            modalInstance.result.then(self.handleSuccess);
        };

        self.openRemoveOidcAccountDialog = function (oidcId) {

            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/user/linked-accounts/oidc-id.remove.dialog.html',
                controller: RemoveOidcController,
                controllerAs: '$ctrl',
                resolve: {
                    user: function () {
                        return self.user;
                    },
                    account: oidcId
                }
            });

            modalInstance.result.then(self.handleSuccess);
        };

        self.openUnlinkOidcAccountDialog = function (oidcId) {

            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/user/linked-accounts/oidc-id.unlink.dialog.html',
                controller: LinkOidcController,
                controllerAs: '$ctrl',
                resolve: {
                    action: function () {
                        return 'unlink';
                    },
                    account: function () {
                        return {
                            iss: oidcId.issuer,
                            sub: oidcId.subject
                        }
                    }
                }
            });

            modalInstance.result.then(self.handleSuccess);
        };

        self.openUnlinkSamlAccountDialog = function (samlId) {
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/user/linked-accounts/saml-id.unlink.dialog.html',
                controller: LinkSamlController,
                controllerAs: '$ctrl',
                resolve: {
                    action: function () {
                        return 'unlink';
                    },
                    account: samlId
                }
            });

            modalInstance.result.then(self.handleSuccess);

        };

        self.handleSuccess = function (msg) {
            self.enabled = true;
            self.userCtrl.loadUser().then(function () {
                toaster.pop({
                    type: 'success',
                    body: msg
                });
            });
        };

        self.openRemoveSamlAccountDialog = function (samlId) {
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/user/linked-accounts/saml-id.remove.dialog.html',
                controller: RemoveSamlIdController,
                controllerAs: '$ctrl',
                resolve: {
                    user: function () {
                        return self.user;
                    },
                    samlId: samlId
                }
            });

            modalInstance.result.then(self.handleSuccess);
        };
    }

    angular.module('dashboardApp').component('userLinkedAccounts', {
        require: {
            userCtrl: '^user'
        },
        bindings: {
            user: '='
        },
        templateUrl: '/resources/iam/apps/dashboard-app/components/user/linked-accounts/user.linked-accounts.component.html',
        controller: [
            '$uibModal', 'toaster', 'AccountLinkingService', UserLinkedAccountsController
        ]
    });
})();