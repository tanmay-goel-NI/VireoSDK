(function (factory) {
    'use strict';

    const getGlobalObject = function () {
        /* eslint-disable no-undef */
        if (typeof window !== 'undefined') {
            return window;
        } else if (typeof self !== 'undefined') {
            return self;
        } else if (typeof global !== 'undefined') {
            return global;
        }
        /* eslint-enable no-undef */
        throw new Error('unable to locate global object');
    };

    // Modified UMD module export
    // The commonjs export provides the factory which requires a WebSocket implementation
    if (typeof module === 'object' && module.exports) {
        module.exports = factory;
    } else {
        const globalObject = getGlobalObject();
        globalObject.NationalInstrumentsHttp = factory(globalObject.XMLHttpRequest);
    }
}(function (XMLHttpRequest){

    'use strict';

    const no_error = '(0)';
    const invalidRefnum = 'The provided refnum is invalid.(-1967362020)';
    const mgArgErr = 'An input parameter is invalid. For example if the input is a path, the path might contain a character not allowed by the OS such as ? or @.(1)';
    const ncTimeOutErr = 'The network operation exceeded the user-specified or system time limit.(56)';
    const kNIHttpResultCouldNotConnect = 'Failed to connect to the specified hostname.  Be sure the specified hostname is correct, the server is running and configured to accept remote requests.(363500)';
    const kNIHttpResultAbortedByCallback = 'The request was aborted by the caller.(363508)';
    const kNIHttpResultRequestHeaderDoesNotExist = 'The specified request header does not exist.(363528)';
    const kNIHttpWebVINetworkError = 'A network error has occurred. Possible reasons for this error include Cross-Origin Resource Sharing (CORS) configuration issues between the client and the target server or that the client cannot reach the target server. Due to browser security restrictions, detailed information about the cause of the network error cannot be provided. You may find specific details about the cause of the network error in the browser development tools console or in the LabVIEW output window.(363650)';
    const kNIHttpWebVIHeaderInvalid = 'Setting a header or header value resulted in an error, possibly due to an invalid character in a header or header value. Verify that each header and header value contains only valid characters.(363651)';
    const kNIHttpResultInternalUndefinedError = 'he HTTP client produced an unknown error.(363798)';
 
    var RunningRequestsTracker;
    (function () {

        // Constructor Function
        RunningRequestsTracker = function () {
            // Public Instance Properties
            // None

            // Private Instance Properties
            this._runningRequests = [];
        };

         // Static Public Variables
        // None

        // Static Public Functions
        // None
        
        // Prototype creation
        var child = RunningRequestsTracker;
        var proto = child.prototype;

        // Public Prototype Methods
        proto.addRequest = function (request) {
            this._runningRequests.push(request);
        };

        proto.removeRequest = function (request) {
            var index = this._runningRequests.indexOf(request);
            if (index > -1) {
                this._runningRequests.splice(index, 1);
            }
        };

        proto.abortAllRunningRequests = function () {
            // Abort event handlers seem to run synchronously
            // So run on a copy to prevent mutating while aborting
            var runningRequestsCopy = this._runningRequests.slice();
            runningRequestsCopy.forEach(function (request) {
                request.abort();
            });
        };
    }());

    var HttpClientManager;
    (function () {
            // Static private reference aliases
            // None

            let _httpClients = new Map();

            // Constructor Function
            HttpClientManager = function () {
                // Public Instance Properties
                // None

                // Private Instance Properties
                this._runningRequestsTracker = new RunningRequestsTracker();

                if (typeof XMLHttpRequest === 'undefined') {
                    this._xmlHttpRequestImplementation = function () {
                        throw new Error('Vireo could not find a global implementation of XMLHttpRequest Level 2. Please provide one to vireo.httpClient.setXMLHttpRequestImplementation to use the Vireo HTTP Client');
                    };
                } else {
                    this._xmlHttpRequestImplementation = XMLHttpRequest;
                }
            };

            // Static Public Variables
            // None

            // Static Public Functions
            // None

            // Prototype creation
            var child = HttpClientManager;
            var proto = child.prototype;

            // Static Private Variables
            // None

            // Static Private Functions
            var createHandle = (function () {
                // A handle of zero implies an invalid handle
                var currentHandle = 1;

                return function () {
                    var handle = currentHandle;
                    currentHandle += 1;
                    return handle;
                };
            }());

            // Public Prototype Methods
            proto.create = function (username, password) {
                var httpClient = new HttpClient(username, password, this._runningRequestsTracker, this._xmlHttpRequestImplementation);
                var handle = createHandle();

                _httpClients.set(handle, httpClient);
                return handle;
            };

            proto.createHttpClientWithoutHandle = function (username, password) {
                var httpClient = new HttpClient(username, password, this._runningRequestsTracker, this._xmlHttpRequestImplementation);
                return httpClient;
            };

            proto.destroy = function (handle) {
                var httpClient = _httpClients.get(handle);
                if (httpClient === undefined) {
                    return;
                }

                // Currently we do not abort any existing requests that were made with this handle
                _httpClients.delete(handle);
            };

            proto.get = function (handle) {
                return _httpClients.get(handle);
            };

            proto.abortAllRunningRequests = function () {
                this._runningRequestsTracker.abortAllRunningRequests();
            };

            proto.setXMLHttpRequestImplementation = function (fn) {
                if (typeof fn !== 'function') {
                    throw new Error('A valid function must be provided');
                }

                // This does not have an effect on already instanced HttpClients or running requests, only on new HttpClient instances
                this._xmlHttpRequestImplementation = fn;
            };
    }());

    var HttpClient;
    (function () {
        // Static private reference aliases
        // None

        // Constructor Function
        HttpClient = function (username, password, requestTracker, xmlHttpRequestImplementation) {
            // Public Instance Properties
            // None

            // Private Instance Properties
            this._username = username;
            this._password = password;
            this._headers = new Map();
            this._includeCredentialsDuringCORS = false;
            this._requestTracker = requestTracker;
            this._xmlHttpRequestImplementation = xmlHttpRequestImplementation;
        };

        var child = HttpClient;
        var proto = child.prototype;

        proto.addHeader = function (header, value) {
            this._headers.set(header, value);
        };

        proto.removeHeader = function (header) {
            this._headers.delete(header);
        };

        // Returns the header with whitespace trimmed if found or undefined if not found
        proto.getHeaderValue = function (header) {
            var ret;

            if (this._headers.has(header)) {
                ret = this._headers.get(header).trim();
            }

            return ret;
        };

        proto.listHeaders = function () {
            var outputHeaders = [];

            this._headers.forEach(function (value, header) {
                outputHeaders.push(header.trim() + ': ' + value.trim());
            });

            // Avoid a trailing \r\n append
            return outputHeaders.join('\r\n');
        };
        
        proto.createRequest = function (requestData, cb) {
            var that = this;
            var XMLHttpRequestImplementation = that._xmlHttpRequestImplementation;
            var errorMessage;
            var emptyBody = new Uint8Array(0);
            var request = new XMLHttpRequestImplementation();

            // Save a reference to the request
            that._requestTracker.addRequest(request);

            // Create event listeners
            var eventListeners = {};

            // Even though we are rigorous with removing event listeners there is at least one case where completeRequest will be run twice
            // In legacy browsers if a bad url is provided the send() function will throw an error triggering a catch statement in addition to the error event handler
            // However, only in legacy browsers will the error event handler run before the catch statement
            // So while most browsers will completeRequest in the catch statement and remove the event handlers to prevent further triggers,
            // legacy browsers will run the error event handler first to completeRequest and then attempt to completeRequest again in the catch statement
            // So begrudgingly a requestCompleted flag is added to prevent multiple calls of completeRequest.
            // This flag is no longer required.
            var requestCompleted = false;

            var completeRequest = function (responseData) {
                // Make sure completeRequest is not called twice
                if (requestCompleted === true) {
                    return;
                }
                requestCompleted = true;

                // Unregister event listeners
                Object.keys(eventListeners).forEach(function (eventName) {
                    request.removeEventListener(eventName, eventListeners[eventName]);
                });

                // Remove reference to complete request
                that._requestTracker.removeRequest(request);
                var error =  responseData.error;
                cb(responseData, error);
            };

            // load, error, timeout, and abort are mutually exclusive and one will fire after send
            // See https://xhr.spec.whatwg.org/#suggested-names-for-events-using-the-progressevent-interface
            eventListeners.load = function () {
                // A status code of 0 is an invalid status code and indicative of a failure
                // So far only legacy browsers return a status codes of 0, so this check is no longer needed.
                if (request.status === 0) {
                    completeRequest({
                        header: '',
                        body: emptyBody,
                        status: 0,
                        error: kNIHttpResultInternalUndefinedError,
                        requestException: undefined
                    });
                    return;
                }
                // TODO mraj is there a way to get the HTTP version from the request?
                var httpVersion = 'HTTP/1.1';
                var statusLine = httpVersion + ' ' + request.status + ' ' + request.statusText + '\r\n';
                var allResponseHeaders = request.getAllResponseHeaders();

                var header = statusLine + allResponseHeaders;
                
                var body = new Uint8Array(request.response);
                completeRequest({
                    header: header,
                    body: body,
                    status: request.status,
                    error : no_error,
                    requestException: undefined
                });
            };

            eventListeners.error = function () {
                completeRequest({
                    header: '',
                    body: emptyBody,
                    status: 0,
                    error: kNIHttpWebVINetworkError,
                    requestException: undefined
                });
            };

            // Desktop does not try and return partial response data in timeout scenarios so do not attempt to here
            eventListeners.timeout = function () {
                completeRequest({
                    header: '',
                    body: emptyBody,
                    status: 0,
                    error: ncTimeOutErr,
                    requestException: undefined
                });
            };

            eventListeners.abort = function () {
                completeRequest({
                    header: '',
                    body: emptyBody,
                    status: 0,
                    error: kNIHttpResultAbortedByCallback,
                    requestException: undefined
                });
            };

            // Register event listeners
            Object.keys(eventListeners).forEach(function (eventName) {
                request.addEventListener(eventName, eventListeners[eventName]);
            });

            // Open request to set properties
            try {
                request.open(requestData.method, requestData.url, true, that._username, that._password);
            } catch (ex) {
                // Spec says open should throw SyntaxError but some browsers seem to throw DOMException.
                // Instead of trying to detect, always say invalid url and add message to source
                completeRequest({
                    header: '',
                    body: emptyBody,
                    status: 0,
                    error: kNIHttpResultCouldNotConnect,
                    requestException: ex
                });
                return removeHeader;
            }

            // Add request headers
            var currentHeaderName, currentHeaderValue;
            var hasContentType = false;

            try {
                that._headers.forEach(function (value, header) {
                    currentHeaderName = header;
                    currentHeaderValue = value;

                    request.setRequestHeader(header, value);

                    if (header.toLowerCase() === 'content-type') {
                        hasContentType = true;
                    }
                });
            } catch (ex) {
                errorMessage = kNIHttpWebVIHeaderInvalid + '\nheader:' + currentHeaderName + '\nvalue:' + currentHeaderValue;
                completeRequest({
                    header: '',
                    body: emptyBody,
                    status: 0,
                    error: errorMessage,
                    requestException: ex
                });
                return;
            }

            // Set the Content-Type to application/x-www-form-urlencoded to match the default on Desktop
            // User can add a Content-Type header to override this default
            // Only add the default Content-Type header to requests that include a buffer
            if (hasContentType === false && requestData.buffer !== undefined) {
                request.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
            }

            // withCredentials allows cookies (to be sent / set), HTTP Auth, and TLS Client certs when sending requests Cross Origin
            // See https://w3c.github.io/webappsec-cors-for-developers/#anonymous-requests-or-access-control-allow-origin
            request.withCredentials = that._includeCredentialsDuringCORS;

            // Receive the response as an ArrayBuffer. Relies on the server to send data as UTF-8 encoded text for text transmission.
            request.responseType = 'arraybuffer';

            // In legacy browsers timeout property may only be set after calling open and before calling send, no longer required
            request.timeout = requestData.xhrTimeout;

            // Send request
            // Legacy browsers throw on send() if an invalid url is provided. Spec compliant browsers throw on open() for invalid urls.
            // Not sure if this is the only reason for send to throw, so using more generic network error
            // The exception handling is likely no longer required.
            try {
                if (requestData.buffer === undefined) {
                    request.send();
                } else {
                    request.send(requestData.buffer);
                }
            } catch (ex) {
                completeRequest({
                    header: '',
                    body: emptyBody,
                    status: 0,
                    requestException: ex,
                    error: kNIHttpWebVINetworkError
                });
                return;
            }
        };

        proto.setIncludeCredentialsDuringCORS = function (includeCredentialsDuringCORS) {
            this._includeCredentialsDuringCORS = includeCredentialsDuringCORS;
        };
    }());


    var httpClientManager = new HttpClientManager();
    var httpClient = new HttpClient();

    var findhttpClientOrWriteError = function (handle) {
        var httpClient = httpClientManager.get(handle);
        if(httpClient==undefined){
            throw new Error(mgArgErr);
        }
        return httpClient;
    };

    var METHOD_NAMES = ['GET', 'HEAD', 'PUT', 'POST', 'DELETE'];
    var TIMEOUT_IMMEDIATELY_MS = 1;

    const jsHttpClientOpen = function (username, password) {
        var newHandle = httpClientManager.create(username, password);
        if (newHandle != null){
            return newHandle;
        }
        return 0;
    };

    const jsHttpClientClose = function(handle) {
        return new Promise((resolve, reject) => {
        var handleExists = httpClientManager.get(handle) !== undefined;

        httpClientManager.destroy(handle);
        if (handleExists === false) {
            reject(new Error(invalidRefnum));
        }
        resolve();
    })};

    const jsHttpClientMethod = function(methodId, clientHandle, url, timeout, buffer){

        var method = METHOD_NAMES[methodId];

        if (buffer !== NULL) {
            // Blob API does not exist in node.js
            if (typeof Blob !== 'undefined') {
                // TODO(mraj) would like to use the typed array in all browsers but not supported in iOS with XHR.send
                // Blob type property not set to determine Content-Type for XHR as Edge seem to ignore it.
                buffer = new Blob([buffer]);
            }
        }

        if (clientHandle === null) {
            httpClient = httpClientManager.createHttpClientWithoutHandle('', '');
        } else {
            httpClient = findhttpClientOrWriteError(clientHandle);
        }

        if(clientHandle === undefined){
            return;
        }

        var xhrTimeout;
        if (timeout < 0) {
            xhrTimeout = 0;
        } else if (timeout === 0) {
            xhrTimeout = TIMEOUT_IMMEDIATELY_MS;
        } else {
            xhrTimeout = timeout;
        }

        var requestData = {
            method: method,
            url: url,
            xhrTimeout: xhrTimeout,
            buffer: buffer
        };

        return new Promise((resolve, reject) => {
            httpClient.createRequest(requestData, function (responseData, error) {
                
                if(error != 0){
                    reject(new Error (error))                   
                }
                else{
                    resolve(responseData);
                }
            });
        });
    };

    const jsGetHeader = function(responseData){
        return responseData.header;
    };

    const jsGetStatus = function(responseData){
        return responseData.status;
    }

    const jsGetBody = function(responseData){
        return responseData.body;
    };

    const jsHttpClientConfigCORS = function (
        handle,
        includeCredentialsDuringCORS) {
        var httpClient = findhttpClientOrWriteError(handle);
        if (httpClient === undefined) {
            return;
        }
        httpClient.setIncludeCredentialsDuringCORS(includeCredentialsDuringCORS);
    };

    const jsHttpClientAddHeader = function (handle, header, value) {
        var httpClient = findhttpClientOrWriteError(handle);
        if (httpClient === undefined) {
            return;
        }

        httpClient.addHeader(header, value);
    };

    const jsHttpClientGetHeader = function (handle, header) {
        var httpClient = findhttpClientOrWriteError(handle);
        if (httpClient === undefined) {
            return;
        }
        return new Promise((resolve, reject) => {
            var value = httpClient.getHeaderValue(header);
            if (value === undefined) {
                reject(new Error (kNIHttpResultRequestHeaderDoesNotExist));
                return;
            }
            else{
                resolve(value);
            }
        });
    };

    const jsHttpClientHeaderExists = function (
        handle,
        header) {
        var httpClient = findhttpClientOrWriteError(handle);
        if (httpClient === undefined) {
            return;
        }

        var valueOrUndefined = httpClient.getHeaderValue(header);
        var headerExists = valueOrUndefined !== undefined;
        if (headerExists === false) {
            return;
        }

        return JSON.stringify({
            headerExists : TRUE,
            value : valueOrUndefined
        });
    };

    const jsHttpClientListHeaders = function (handle) {
        var httpClient = findhttpClientOrWriteError(handle);
        if (httpClient === undefined) {
            return;
        }

        var list = httpClient.listHeaders();
        return list;
    };

    const jsHttpClientRemoveHeader = function (handle, header) {
        var httpClient = findhttpClientOrWriteError(handle, errorValueRef);
        if (httpClient === undefined) {
            return;
        }

        httpClient.removeHeader(header);
    };

    return {
        jsHttpClientOpen,
        jsHttpClientMethod,
        jsHttpClientClose,
        jsGetHeader,
        jsGetStatus,
        jsGetBody,
        jsHttpClientConfigCORS,
        jsHttpClientAddHeader,
        jsHttpClientGetHeader,
        jsHttpClientHeaderExists,
        jsHttpClientListHeaders,
        jsHttpClientRemoveHeader
    };
}));