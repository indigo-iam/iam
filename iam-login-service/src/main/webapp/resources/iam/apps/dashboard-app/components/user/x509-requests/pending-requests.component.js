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

    angular
        .module('dashboardApp')
        .component('userCertLinkPendingRequests', userCertLinkPendingRequests());


    function AbortRequest(requestsService, $uibModalInstance, toaster, request) {
        var self = this;

        self.request = request;
        self.enabled = true;

        function handleSuccess(res) {
            $uibModalInstance.close(res);
        }

        function handleError(err) {
            var msg;

            if (err.data && err.data.error) {
                msg = err.data.error;
            } else {
                msg = err.statusText;
            }

            toaster.pop({
                type: 'error',
                body: msg
            });

            $uibModalInstance.dismiss(msg);
        }

        self.abortRequest = function () {
            requestsService.abortRequest(self.request).then(handleSuccess, handleError);
        };

        self.cancel = function () {
            $uibModalInstance.dismiss('Dismissed');
        };
    }

    function PendingCertLinkRequestsController(Utils, CertLinkRequestsService, toaster, $uibModal) {
        var self = this;

        self.certLinkRequests = [];

        self.$onInit = $onInit;
        self.abortRequest = abortRequest;

        function $onInit() {
            self.voAdmin = Utils.isAdmin();
            loadCertLinkRequests();
        }

        function loadCertLinkRequests() {
            return CertLinkRequestsService.getAllPendingCertLinkRequestsForAuthenticatedUser().then(function (reqs) {
                self.certLinkRequests = reqs;
            }).catch(function (error) {
                console.error('Error loading cert link requests');
            });
        }

        function abortRequest(request) {
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/user/x509-requests/cancel-cert-link-request.dialog.html',
                controller: AbortRequest,
                controllerAs: '$ctrl',
                resolve: {
                    request: request
                }
            });

            modalInstance.result.then(function (r) {
                loadCertLinkRequests();
                toaster.pop({
                    type: 'success',
                    body: 'Request aborted'
                });
            }).catch(function (r) {
                loadCertLinkRequests();
            });
        }
    }


    function userCertLinkPendingRequests() {
        return {
            templateUrl: "/resources/iam/apps/dashboard-app/components/user/x509-requests/pending-requests.component.html",
            bindings: {
                user: "<"
            },
            controller: [
                'Utils', 'CertLinkRequestsService', 'toaster', '$uibModal',
                PendingCertLinkRequestsController
            ],
            controllerAs: '$ctrl'
        };
    }

}());