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


    function AbortRequest(CertLinkRequestsService, $uibModalInstance, toaster, request) {
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
            CertLinkRequestsService.abortRequest(self.request).then(handleSuccess, handleError);
        };

        self.cancel = function () {
            $uibModalInstance.dismiss('Dismissed');
        };
    }

    function CertLinkRequest($uibModalInstance, CertLinkRequestsService, toaster, $sanitize, user, certificationAuthorities) {

        var self = this;

        self.user = user;
        self.enabled = true;
        self.certVal = {};
        self.inputMode = "pem";
        self.error = undefined;
        self.isRequest = true;
        self.titleMessage = "Request linking an X.509 certificate to your IAM account?";
        self.submitMessage = "Submit request";

        self.canSubmit = canSubmit;
        self.cancel = cancel;
        self.doAdd = doAdd;
        self.reset = reset;
        self.certLabelValid = certLabelValid;
        self.certificationAuthorities = certificationAuthorities;

        function canSubmit() {
            return self.certVal.notes && self.enabled;
        }

        function handleSuccess(res) {
            self.enabled = true;
            $uibModalInstance.close("Request submitted");
        }

        function handleError(err) {
            self.enabled = true;
            var msg;

            if (err.data) {
                msg = err.data.error;
            } else if (err.statusText) {
                msg = err.statusText;
            } else {
                msg = 'Invalid request';
            }

            toaster.pop({
                type: 'error',
                body: msg
            });

            $uibModalInstance.dismiss(msg);
        }

        function cancel() {
            $uibModalInstance.dismiss('Dismissed');
        }

        function doAdd() {
            self.error = undefined;
            self.enabled = false;

            const req = {
                notes: $sanitize(self.certVal.notes),
                label: self.certVal.label,
            }
            if (self.inputMode == "pem") {
                req.pemEncodedCertificate = self.certVal.pemEncodedCertificate;
            } else if (self.inputMode == "dn") {
                req.subjectDn = self.certVal.subjectDn;
                req.issuerDn = self.certVal.issuerDn;
            }

            CertLinkRequestsService.submit(req)
                .then(handleSuccess)
                .catch(handleError);
        }

        function reset() {
            self.certVal = {
                label: '',
                pemEncodedCertificate: '',
                subjectDn: '',
                issuerDn: '',
                notes: ''
            };
            self.error = undefined;
            self.inputMode = "pem";
        }

        function certLabelValid() {
            return $scope.certLabel.$dirty && $scope.certLabel.$valid;
        }

    }

    function PendingCertLinkRequestsController(Utils, CertLinkRequestsService, toaster, $uibModal, TrustsService) {
        var self = this;

        self.certLinkRequests = [];

        self.$onInit = $onInit;
        self.abortRequest = abortRequest;
        self.openRequestCertLinkDialog = openRequestCertLinkDialog;

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

        function openRequestCertLinkDialog() {
            var modalInstance = $uibModal.open({
                templateUrl: '/resources/iam/apps/dashboard-app/components/user/x509/cert.add.dialog.html',
                controller: CertLinkRequest,
                controllerAs: '$ctrl',
                resolve: {
                    user: () => self.user,
                    certificationAuthorities: () => TrustsService.getTrusts()
                }
            });

            modalInstance.result.then(function (r) {
                toaster.pop({
                    type: 'success',
                    body: `Certificate linking request submitted.`
                });
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
                'Utils', 'CertLinkRequestsService', 'toaster', '$uibModal', 'TrustsService',
                PendingCertLinkRequestsController
            ],
            controllerAs: '$ctrl'
        };
    }

}());