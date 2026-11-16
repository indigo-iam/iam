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

angular.module('iamCsrf', [])
    .factory('csrfInterceptor', ['$document', '$window',
        function($document, $window) {
            return {
                request: function(config) {
                    var method = (config.method || 'GET').toUpperCase();

                    if (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method)) {
                        return config;
                    }

                    var document = $document[0];
                    var target = new $window.URL(config.url, document.baseURI);

                    // Never send CSRF tokens to different origins.
                    if (target.origin !== $window.location.origin) {
                        return config;
                    }

                    var token = document.querySelector('meta[name="_csrf"]');
                    var header = document.querySelector('meta[name="_csrf_header"]');

                    if (token && token.content && header && header.content) {
                        config.headers = config.headers || {};
                        if (!config.headers[header.content]) {
                            config.headers[header.content] = token.content;
                        }
                    }

                    return config;
                }
            };
        }
    ]);
