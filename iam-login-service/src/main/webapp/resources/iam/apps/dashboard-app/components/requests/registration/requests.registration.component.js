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

function DialogController(
    $uibModalInstance, RegistrationRequestService, requests) {
  var self = this;

  self.motivation = '';
  self.busy = false;
  self.requests = requests;
  self.cancel = cancel;
  self.approve = approve;
  self.reject = reject;

  function cancel() {
    $uibModalInstance.dismiss('Dismissed');
  }

  function approve() {
    self.busy = true;
    var result = RegistrationRequestService.bulkApprove(self.requests);
    $uibModalInstance.close(result);
  }

  function reject() {
    self.busy = true;
    var result =
        RegistrationRequestService.bulkReject(self.requests, self.motivation);
    $uibModalInstance.close(result);
  }
}

function RejectRequest(
    $uibModalInstance, RegistrationRequestService, requests) {
  var self = this;

  self.requests = requests;

  self.cancel = function() {
    $uibModalInstance.dismiss('Dismissed');
  };

  self.reject = function() {
    RegistrationRequestService.rejectRequest(self.request)
        .then(function(r) {
          $uibModalInstance.close(r);
        })
        .catch(function(r) {
          toaster.pop({type: 'error', body: r.statusText});
        });
  };
}

function RegistrationRequests(
    Utils, $scope, $rootScope, $uibModal, $filter, $interval, $timeout, $q,
    RegistrationRequestService, filterFilter, toaster) {
  var self = this;

  self.loaded = false;
  self.filter = '';
  self.filtered = [];
  self.busy = false;
  self.itemsPerPage = 10;
  self.currentPage = 1;

  self.bulkApprove = bulkApprove;
  self.bulkReject = bulkReject;
  self.toggleSelectionForPageRequests = toggleSelectionForPageRequests;
  self.numSelected = numSelected;

  self.selectedRequests = {};



  function numSelected() {
    var selected = Object.keys(self.selectedRequests)
                       .filter(k => self.selectedRequests[k]);
    return selected.length;
  }

  function toggleSelectionForPageRequests() {
    if (self.filtered.length == 0) {
      return;
    }

    // Keep the order here in sync with what you have in the template
    var ordered = $filter('orderBy')(self.filtered, 'creationTime', true);
    for (var i = self.pageLeft; i <= self.pageRight; i++) {
      var reqId = ordered[i - 1].uuid;  // pages are 1-based
      self.selectedRequests[reqId] = self.masterCheckbox;
    }
  }


  function bulkRejectSuccess(r) {
    console.log(r);
    loadPendingRequests().then(function() {
      toaster.pop({type: 'success', body: `${r.length} requests rejected`});
    });
  }

  function bulkRejectError(r) {
    console.log(r);
    loadPendingRequests().then(function() {
      if (r != 'Dismissed') {
        toaster.pop(
            {type: 'error', body: `Rejection failed for ${r.length} requests`});
      }
    });
  }

  function bulkApproveSuccess(r) {
    console.log(r);
    loadPendingRequests().then(function() {
      toaster.pop({type: 'success', body: `${r.length} requests approved`});
    });
  }

  function bulkApproveError(r) {
    console.log(r);
    loadPendingRequests().then(function() {
      if (r != 'Dismissed') {
        toaster.pop(
            {type: 'error', body: `Approval failed for ${r.length} requests`});
      }
    });
  }

  function selectedRequests() {
    var reqKeys = Object.keys(self.selectedRequests)
                      .filter(k => self.selectedRequests[k]);
    var requests = self.requests.filter(r => reqKeys.includes(r.uuid));
    return requests;
  }


  function bulkApprove() {
    self.busy = true;

    var modal = $uibModal.open({
      templateUrl:
          '/resources/iam/apps/dashboard-app/components/requests/registration/bulk-approve.dialog.html',
      controller: DialogController,
      controllerAs: '$ctrl',
      resolve: {
        requests: function() {
          return selectedRequests();
        }
      }
    });

    modal.result.then(bulkApproveSuccess, bulkApproveError);
  }

  function bulkReject() {
    self.busy = true;
    var modal = $uibModal.open({
      templateUrl:
          '/resources/iam/apps/dashboard-app/components/requests/registration/bulk-reject.dialog.html',
      controller: DialogController,
      controllerAs: '$ctrl',
      resolve: {
        requests: function() {
          return selectedRequests();
        }
      }
    });

    modal.result.then(bulkRejectSuccess, bulkRejectError);
  }



  self.resetFilter = function() {
    self.filter = '';
  };

  function errorHandler(res) {
    return res;
  }

  function listRequestSuccess(res) {
    self.resetFilter();
    self.filtered = self.requests = res.data;
    updatePageCounters();
    updateRootScopeCounters(res);
    self.busy = false;
    self.loaded = true;
    self.reqCount = self.filtered.length;
    self.selectedRequests = {};
    self.masterCheckbox = undefined;
    return res;
  }

  function updateRootScopeCounters(res) {
    $rootScope.pendingRegistrationRequests(res.data);
  }

  function updatePageCounters() {
    self.pageLeft = ((self.currentPage - 1) * self.itemsPerPage) + 1;
    self.pageRight =
        Math.min(self.currentPage * self.itemsPerPage, self.filtered.length);
  }

  $scope.$watch('$ctrl.filter', function() {
    filterRequests();
  });

  function loadPendingRequests() {
    return RegistrationRequestService.listPending().then(
        listRequestSuccess, errorHandler);
  }

  function refreshPendingRequests() {
    self.busy = true;
    self.refreshing = true;

    return $timeout(loadPendingRequests, 1500).then(function(r) {
      self.refreshing = false;
      return r;
    });
  }

  function filterRequests() {
    self.filtered = filterFilter(self.requests, function(request) {
      if (!self.filter) {
        return true;
      }

      var query = self.filter.toLowerCase();

      if (request.familyname.toLowerCase().indexOf(query) != -1) {
        return true;
      }
      if (request.givenname.toLowerCase().indexOf(query) != -1) {
        return true;
      }
      if (request.username.toLowerCase().indexOf(query) != -1) {
        return true;
      }
      if (request.email.toLowerCase().indexOf(query) != -1) {
        return true;
      }
      if (request.notes.toLowerCase().indexOf(query) != -1) {
        return true;
      }
      return false;
    });

    if (self.filtered) {
      updatePageCounters();
    }
  }

  self.pageChanged = function() {
    updatePageCounters();
  };


  function decisionErrorHandler(res) {
    toaster.pop({type: 'error', body: r.statusText});
    self.busy = false;
  }

  self.reject = function(req) {
    var modal = $uibModal.open({
      templateUrl:
          '/resources/iam/apps/dashboard-app/components/requests/reject-request.dialog.html',
      controller: RejectRequest,
      controllerAs: '$ctrl',
      resolve: {
        request: req,
        userFullName: function() {
          return `${req.givenname} ${req.familyname}`;
        }
      }
    });

    modal.result.then(rejectSuccess, decisionErrorHandler);
  };

  self.$onInit = function() {
    console.log('RegistrationRequests onInit');
    self.api = {};
    self.api.load = loadPendingRequests;
    self.parentCb({$API: self.api});

    if (Utils.isAdmin()) {
      loadPendingRequests();
      $interval(refreshPendingRequests, 60000);
    }
  };
}

angular.module('dashboardApp')
    .component('registrationRequests', registrationRequests());

function registrationRequests() {
  return {
    bindings: {parentCb: '&'},
    templateUrl:
        '/resources/iam/apps/dashboard-app/components/requests/registration/requests.registration.component.html',
    controller: [
      'Utils', '$scope', '$rootScope', '$uibModal', '$filter', '$interval',
      '$timeout', '$q', 'RegistrationRequestService', 'filterFilter', 'toaster',
      RegistrationRequests
    ],
    controllerAs: '$ctrl'
  };
}
}());