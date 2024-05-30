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

  function AupSignOnBehalfController(toaster, Utils, ModalService, AupService, user) {
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

        
    self.openSignAupOnBehalfModal = function() {
      self.enabled = false;

      var modalOptions = {
        closeButtonText: 'Cancel',
        // templateUrl: '/resources/iam/apps/dashboard-app/templates/home/signonbehalf.html',
        actionButtonText: 'Sign on behalf',
        headerText: 'Sign AUP on behalf of this user',
        bodyText:
            `Are you sure you want to sign AUP on behalf of this user?`
      };

      ModalService.showModal({}, modalOptions)
          .then(
              function() {
                AupService.signAupOnBehalf(self.user.id).then(function(result) {
                  if (result != null) {
                    self.user.aupSignature = result.data;
                    toaster.pop({ type: 'success', body: "AUP signature updated for " + result.data.account.name });
                  } else {
                    var message = "Unable to sign AUP on behalf";
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

  angular.module('dashboardApp').component('userSignOnBehalf', {
    bindings: {
      user: '<'
    },
    templateUrl:
      '/resources/iam/apps/dashboard-app/components/user/sign-on-behalf/user.sign-on-behalf.component.html',
    controller: [
      'toaster', 'Utils', 'ModalService', 'AupService', AupSignOnBehalfController
    ]
  });
})();