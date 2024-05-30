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
(function() {
  'use strict';

  function RequestAupSignatureController(toaster, Utils, ModalService, AupService, user, aup) {
    var self = this;
	self.enabled = true;

    self.isMe = function () {
      return Utils.isMe(self.user.id);
    };
    self.isVoAdmin = function () {
      return Utils.userIsVoAdmin(self.user);
    };
    self.aupIsEnabled = function () {
      return self.aup !== null;
    };

    self.openRequestAupSignatureModal = function() {
      self.enabled = false;

      var modalOptions = {
        closeButtonText: 'Cancel',
        actionButtonText: 'Request AUP signature',
        headerText: 'Do you want to request user to sign AUP?',
        bodyText:
            `Note that user MUST sign it again in order to get new tokens.`
      };

      ModalService.showModal({}, modalOptions)
          .then(
              function() {
                AupService.deleteAupSignatureForUser(self.user.id).then(function(result) {
                  if (result != null && result.status === 204) {
                    self.user.aupSignature = null;
                    toaster.pop({ type: 'success', body: "AUP signature requested to " + self.user.name.formatted });
                  } else {
                    var message = "Unable to request AUP signature";
                    console.error(message);
                    toaster.pop({
                      type: 'error',
                      body: message
                    });
                  }
                }).catch(function(error) { 
                  console.error(error);
                  toaster.pop({
                    type: 'error',
                    body: error
                  });
                });
                self.enabled = true;
              });

    };
  }

  angular.module('dashboardApp').component('userRequestAupSignature', {
    bindings: {
      user: '<',
      aup: '='
    },
    templateUrl:
      '/resources/iam/apps/dashboard-app/components/user/request-aup-signature/user.request-aup-signature.component.html',
    controller: [
      'toaster', 'Utils', 'ModalService', 'AupService', RequestAupSignatureController
    ]
  });
})();