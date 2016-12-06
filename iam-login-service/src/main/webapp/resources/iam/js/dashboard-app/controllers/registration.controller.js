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
			templateUrl : '/resources/iam/template/dashboard/loading-modal.html'
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
		RegistrationRequestService.updateRequest(request.uuid, 'APPROVED').then(
			function() {
				var msg = request.givenname + " " + request.familyname + " request APPROVED successfully";
				$scope.operationResult = Utils.buildSuccessOperationResult(msg);
				requests.loadData();
			},
			function(error) {
				$scope.operationResult = Utils.buildErrorOperationResult(error);
			})
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
					RegistrationRequestService.updateRequest(request.uuid, 'REJECTED').then(
							function() {
								var msg = request.givenname + " " + request.familyname + " request REJECTED successfully";
								$scope.operationResult = Utils.buildSuccessOperationResult(msg);
								requests.loadData();
							},
							function(error) {
								$scope.operationResult = Utils.buildErrorOperationResult(error);
							})
				});
	};
};
