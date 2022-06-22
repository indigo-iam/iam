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
'use strict';

angular.module('dashboardApp').controller('RequestManagementController', RequestManagementController);

RequestManagementController.$inject = ['$scope', '$rootScope', '$state', '$filter', 'filterFilter', '$uibModal', 'RegistrationRequestService', 'ModalService', 'Utils'];

function RequestManagementController($scope, $rootScope, $state, $filter, filterFilter, $uibModal, RegistrationRequestService, ModalService, Utils){

	if (!$rootScope.isRegistrationEnabled) {
		console.info("Registration is disabled");
		return;
	}

	var requests = this;

	$rootScope.requestsLoaded = undefined;

	requests.approveRequest = approveRequest;
	requests.rejectRequest = rejectRequest;
	requests.loadData = loadData;

	requests.list = [];
	requests.filtered = [];
	requests.sortType = 'creationTime';
	requests.sortReverse = true;
	requests.currentPage = 1;
	requests.maxSize = 5;
	requests.numPerPage = 10;

	// search
	requests.searchText = "";
	requests.resetFilters = resetFilters;
	requests.rebuildFilteredList = rebuildFilteredList;

	function resetFilters() {
		// needs to be a function or it won't trigger a $watch
		requests.searchText = "";
	}

	requests.loadData();

	function rebuildFilteredList() {

		requests.filtered = filterFilter(requests.list, function(request) {

			if (!requests.searchText) {
				return true;
			}

			var query = requests.searchText.toLowerCase();
			
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
	}

	$scope.$watch('requests.searchText', function() {

		requests.rebuildFilteredList();
	});

	function loadData() {
		
		$rootScope.pageLoadingProgress = 30;
		
		requests.loadingModal = $uibModal
		.open({
			animation: false,
			backdrop: 'static',
			templateUrl : '/resources/iam/apps/dashboard-app/templates/loading-modal.html'
		});

		requests.loadingModal.opened.then(function() {
		
			RegistrationRequestService.listPending().then(
				function(result) {
					requests.list = result.data;
					requests.rebuildFilteredList();
					$rootScope.pageLoadingProgress = 100;
					$rootScope.loggedUser.pendingRequests = result.data;
					$rootScope.requestsLoaded = true;
					requests.loadingModal.dismiss("Cancel");
				},
				function(error) {

					$rootScope.pageLoadingProgress = 100;
					$scope.operationResult = Utils.buildErrorOperationResult(error);
					requests.loadingModal.dismiss("Error");
				});
		});
	}

	function approveRequest(request) {
		$scope.buttonDisabled = true;
		
		$rootScope.pageLoadingProgress = 50;
		requests.approvingModal = $uibModal
		.open({
			animation: false,
			backdrop: 'static',
			templateUrl : '/resources/iam/apps/dashboard-app/templates/loading-modal.html'
		});
		
		requests.approvingModal.opened.then(function(){
			RegistrationRequestService.updateRequest(request.uuid, 'APPROVED').then(
				function() {
					$rootScope.pageLoadingProgress = 100;
					requests.approvingModal.dismiss("Cancel");
					var msg = request.givenname + " " + request.familyname + " request APPROVED successfully";
					$scope.operationResult = Utils.buildSuccessOperationResult(msg);
					requests.loadData();
					$scope.buttonDisabled = false;
				},
				function(error) {
					$rootScope.pageLoadingProgress = 100;
					requests.approvingModal.dismiss("Cancel");
					$scope.operationResult = Util.buildErrorOperationResult(error);
					$scope.buttonDisabled = false;
				})
		});
	};

	function rejectRequest(request) {
		
		var modalOptions = {
			closeButtonText: 'Cancel',
            actionButtonText: 'Reject Registration Request',
            headerText: 'Reject «' + request.givenname + " " + request.familyname + "» registration request",
            bodyText: `Are you sure you want to reject '${request.givenname} ${request.familyname}' registration request?`	
		};
		
		ModalService.showModal({}, modalOptions).then(
				function (){
					$rootScope.pageLoadingProgress = 50;
					requests.rejectingModal = $uibModal
					.open({
						animation: false,
						backdrop: 'static',
						templateUrl : '/resources/iam/apps/dashboard-app/templates/loading-modal.html'
					});
					
					requests.rejectingModal.opened.then(function(){
						RegistrationRequestService.updateRequest(request.uuid, 'REJECTED').then(
							function() {
								$rootScope.pageLoadingProgress = 100;
								requests.rejectingModal.dismiss("Cancel");
								var msg = request.givenname + " " + request.familyname + " request REJECTED successfully";
								$scope.operationResult = Utils.buildSuccessOperationResult(msg);
								requests.loadData();
							},
							function(error) {
								$rootScope.pageLoadingProgress = 100;
								requests.rejectingModal.dismiss("Cancel");
								$scope.operationResult = Utils.buildErrorOperationResult(error);
							})
					});
				});
	};
};
