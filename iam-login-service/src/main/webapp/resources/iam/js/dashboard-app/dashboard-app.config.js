angular.module('dashboardApp').value('getUserInfo', getUserInfo);

angular.module('dashboardApp').config(function($stateProvider, $urlRouterProvider, $httpProvider) {

    $httpProvider.interceptors.push('gatewayErrorInterceptor');
    $httpProvider.interceptors.push('sessionExpiredInterceptor');

	$urlRouterProvider.otherwise(function($injector, $location){
		if (getUserAuthorities().indexOf("ROLE_ADMIN") != -1) {
			return '/user/' + getUserInfo().sub;
		} else {
			return '/home';
		}
	});

	$stateProvider.state('home', {
		url : '',
		onEnter: function($state, $timeout) {
			if (getUserAuthorities().indexOf("ROLE_ADMIN") == -1) {
	            $timeout(function() {
	                $state.go('homeuser');
	            }, 0);
	        } else {
	            $timeout(function() {
	                $state.go('user', {id: getUserInfo().sub});
	            }, 0);
	        }
	    }
	}).state('homeuser', {
		url : '/home',
		views: {
		      'content' : {
		        templateUrl: '/resources/iam/template/dashboard/home/home.html',
		        controller: 'HomeController',
		        controllerAs: 'home'
		      }
		    }
	}).state('user', {
		url : '/user/:id',
		views: {
		      'content' : {
		        templateUrl: '/resources/iam/template/dashboard/user/user.html',
		        controller: 'UserController',
		        controllerAs: 'userCtrl'
		      }
		    }
	}).state('group', {
		url : '/group/:id',
		views: {
		      'content' : {
		        templateUrl: '/resources/iam/template/dashboard/group/group.html',
		        controller: 'GroupController',
		        controllerAs: 'group'
		      }
		    }
	}).state('users', {
		url : '/users',
		views: {
		      'content' : {
		        templateUrl: '/resources/iam/template/dashboard/users/users.html',
		        controller: 'UsersController',
		        controllerAs: 'users'
		      }
		    }
	}).state('groups', {
		url : '/groups',
		views: {
		      'content' : {
		        templateUrl: '/resources/iam/template/dashboard/groups/groups.html',
		        controller: 'GroupsController',
		        controllerAs: 'gc'
		      }
		    }
	}).state('unauthorized', {
		url : '/unauthorized',
		views: {
		      'content' : {
		        templateUrl: '/resources/iam/template/dashboard/unauthorized.html',
		        controller: 'UnauthorizedController',
		        controllerAs: 'unauthCtrl'
		      }
		    }
	}).state('requests', {
		url : '/requests',
		views: {
		      'content' : {
		        templateUrl: '/resources/iam/template/dashboard/requests/management.html',
		        controller: 'RequestManagementController',
		        controllerAs: 'requests'
		      }
		    }
	});
});