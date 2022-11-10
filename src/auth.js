/**
 * Copyright (c) 2014 Baidu.com, Inc. All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * @file src/auth.js
 * @author leeight
 */

/* eslint-env node */
/* eslint max-params:[0,10] */

var util = require('util');
var u = require('underscore');

var debug = require('debug')('bce-sdk:auth');

var H = require('./headers');
var strings = require('./strings');

/**
 * Auth
 *
 * @constructor
 * @param {string} ak The access key.
 * @param {string} sk The security key.
 */
function Auth(ak, sk) {
    this.ak = ak;
    this.sk = sk;
    // 全局变量
    this.g_signed_headers=''
}

/**
 * Generate the signature based on http://gollum.baidu.com/AuthenticationMechanism
 *
 * @param {string} method The http request method, such as GET, POST, DELETE, PUT, ...
 * @param {string} resource The request path.
 * @param {Object=} params The query strings.
 * @param {Object=} headers The http request headers.
 * @param {number=} timestamp Set the current timestamp.
 * @param {number=} expirationInSeconds The signature validation time.
 * @param {Array.<string>=} headersToSign The request headers list which will be used to calcualate the signature.
 *
 * @return {string} The signature.
 */
Auth.prototype.generateAuthorization = function (method, resource, params,
                                                 headers, timestamp, expirationInSeconds, headersToSign) {

    if (resource.includes('bos-share.baidubce.com')) {
        return this.generateIAMAuthorization({
            url:resource,
            params,
            method,
            headers,
            timestamp,
            expirationInSeconds,
            signedHeaders: headersToSign
        })
    }

    var now = this.getTimestamp(timestamp);
    var rawSessionKey = util.format('bce-auth-v1/%s/%s/%d',
        this.ak, now, expirationInSeconds || 1800);
    debug('rawSessionKey = %j', rawSessionKey);
    var sessionKey = this.hash(rawSessionKey, this.sk);

    var canonicalUri = this.uriCanonicalization(resource);
    var canonicalQueryString = this.queryStringCanonicalization(params || {});

    var rv = this.headersCanonicalization(headers || {}, headersToSign);
    var canonicalHeaders = rv[0];
    var signedHeaders = rv[1];
    debug('canonicalUri = %j', canonicalUri);
    debug('canonicalQueryString = %j', canonicalQueryString);
    debug('canonicalHeaders = %j', canonicalHeaders);
    debug('signedHeaders = %j', signedHeaders);

    var rawSignature = util.format('%s\n%s\n%s\n%s',
        method, canonicalUri, canonicalQueryString, canonicalHeaders);
    debug('rawSignature = %j', rawSignature);
    debug('sessionKey = %j', sessionKey);
    var signature = this.hash(rawSignature, sessionKey);

    if (signedHeaders.length) {
        return util.format('%s/%s/%s', rawSessionKey, signedHeaders.join(';'), signature);
    }

    return util.format('%s//%s', rawSessionKey, signature);
};

Auth.prototype.uriCanonicalization = function (uri) {
    return uri;
};

/**
 * Canonical the query strings.
 *
 * @see http://gollum.baidu.com/AuthenticationMechanism#生成CanonicalQueryString
 * @param {Object} params The query strings.
 * @return {string}
 */
Auth.prototype.queryStringCanonicalization = function (params) {
    var canonicalQueryString = [];
    Object.keys(params).forEach(function (key) {
        if (key.toLowerCase() === H.AUTHORIZATION.toLowerCase()) {
            return;
        }

        var value = params[key] == null ? '' : params[key];
        canonicalQueryString.push(key + '=' + strings.normalize(value));
    });

    canonicalQueryString.sort();

    return canonicalQueryString.join('&');
};

/**
 * Canonical the http request headers.
 *
 * @see http://gollum.baidu.com/AuthenticationMechanism#生成CanonicalHeaders
 * @param {Object} headers The http request headers.
 * @param {Array.<string>=} headersToSign The request headers list which will be used to calcualate the signature.
 * @return {*} canonicalHeaders and signedHeaders
 */
Auth.prototype.headersCanonicalization = function (headers, headersToSign) {
    if (!headersToSign || !headersToSign.length) {
        headersToSign = [H.HOST, H.CONTENT_MD5, H.CONTENT_LENGTH, H.CONTENT_TYPE];
    }
    debug('headers = %j, headersToSign = %j', headers, headersToSign);

    var headersMap = {};
    headersToSign.forEach(function (item) {
        headersMap[item.toLowerCase()] = true;
    });

    var canonicalHeaders = [];
    Object.keys(headers).forEach(function (key) {
        var value = headers[key];
        value = u.isString(value) ? strings.trim(value) : value;
        if (value == null || value === '') {
            return;
        }
        key = key.toLowerCase();
        if (/^x\-bce\-/.test(key) || headersMap[key] === true) {
            canonicalHeaders.push(util.format('%s:%s',
                // encodeURIComponent(key), encodeURIComponent(value)));
                strings.normalize(key), strings.normalize(value)));
        }
    });

    canonicalHeaders.sort();

    var signedHeaders = [];
    canonicalHeaders.forEach(function (item) {
        signedHeaders.push(item.split(':')[0]);
    });

    return [canonicalHeaders.join('\n'), signedHeaders];
};

Auth.prototype.hash = function (data, key) {
    var crypto = require('crypto');
    var sha256Hmac = crypto.createHmac('sha256', key);
    sha256Hmac.update(data);
    return sha256Hmac.digest('hex');
};


/* IAM 逻辑 */

Auth.prototype.getTimestamp = function getTimestamp(timestamp) {
    var now = timestamp ? new Date(timestamp * 1000) : new Date();
    return now.toISOString().replace(/\.\d+Z$/, 'Z');
}

Auth.prototype.normalize = function normalize(string, encodingSlash) {
    var kEscapedMap = {
        '!': '%21',
        '\'': '%27',
        '(': '%28',
        ')': '%29',
        '*': '%2A'
    };

    if (string === null) {
        return "";
    }
    var result = encodeURIComponent(string);
    result = result.replace(/[!'\(\)\*]/g, function ($1) {
        return kEscapedMap[$1];
    });

    if (encodingSlash === false) {
        result = result.replace(/%2F/gi, '/');
    }

    return result;
}

Auth.prototype.generateCanonicalUri = function generateCanonicalUri(url) {
    console.log(require('url').parse(url));
    var pathname = require('url').parse(url).pathname.trim();
    var resources = pathname.replace(/^\//,'').split('/')
    if (!resources) {
        return "";
    }
    var normalizedResourceStr = "";
    for (var i = 0; i < resources.length; i++) {
        normalizedResourceStr += "/" + this.normalize(resources[i]);
    }
    return normalizedResourceStr;
}

Auth.prototype.generateCanonicalQueryString = function generateCanonicalQueryString(params) {
    var queryList = Object.entries(params)
    var normalizedQueryList = []
    for (var i = 0; i < queryList.length; i++) {
        if (queryList[i][0].toLowerCase() == "authorization") {
            continue;
        }
        normalizedQueryList.push(this.normalize(queryList[i][0]) + "=" + this.normalize(queryList[i][1]));
    }
    normalizedQueryList.sort();
    return normalizedQueryList.join('&');
}

/**
 * 
 * @param {Record<string,string>} headers 
 * @param {string[] | undefined} signedHeaders 
 * @returns 
 */
Auth.prototype.generateCanonicalHeaders = function generateCanonicalHeaders(headers, url, signedHeaders) {
    var defaultHeaders = ["host", "content-length", "content-type", "content-md5"];
    var keyStrList = [];
    headerKeys = Object.keys(headers);
    if (!headerKeys.includes('host')) {
        headers['host'] = require('url').parse(url).hostname
    }

    if (!signedHeaders) {
        for (var i = 0; i < defaultHeaders.length; i++) {
            keyStrList.push(defaultHeaders[i]);
        }

        var headerListObj = Object.entries(headers);
        for (var i = 0; i < headerListObj.length; i++) {
            var key = headerListObj[i][0];
            if (key.toLowerCase().startsWith("x-bce-")) {
                keyStrList.push(key.toLowerCase());
            }
        }
    } else {
        keyStrList = signedHeaders;
        for (var i = 0; i < keyStrList.length; i++) {
            keyStrList[i] = keyStrList[i].toLowerCase();
        }
        if (!keyStrList.includes("host")) {
            keyStrList.push("host");
        }
    }
    var usedHeaderStrList = [];
    for (var i = 0; i < keyStrList.length; i++) {
        key = keyStrList[i];
        value = headers[key];
        if (!value || value === "") {
            continue;
        }
        key = key.toLowerCase();
        value = value.trim();
        usedHeaderStrList.push(this.normalize(key) + ":" + this.normalize(value));
    }

    usedHeaderStrList.sort();
    var usedHeaderKeys = [];
    usedHeaderStrList.forEach(function (item) {
        usedHeaderKeys.push(item.split(':')[0]);
    });
    var canonicalHeaderStr = usedHeaderStrList.join('\n');
    this.g_signed_headers = usedHeaderKeys.join(';');
    return canonicalHeaderStr;
}

/**
 * 
 * @param {{url:string,params:Record<string,any>,headers:Record<string,any>,timestamp?:number,expirationInSeconds?:string,signedHeaders?:string[]}} options 
 * @returns string
 */
Auth.prototype.generateIAMAuthorization = function generateAuthorization(options) {
    var timestamp = this.getTimestamp(options.timestamp);
    var signedHeaders = options.signedHeaders;
    var url = options.url;
    var params = options.params;
    var headers= options.headers;
    var authVersion = "1";
    var expirationInSeconds = options.expirationInSeconds || "1800";
    var accessKey = this.ak;
    var secretKey = this.sk;
    var method = options.method;

    signingKeyStr = "bce-auth-v" + authVersion + "/" + accessKey.trim() + "/" + timestamp + "/" + expirationInSeconds;
    signingKey = this.hash(signingKeyStr, secretKey.trim());

    canonicalUri = this.generateCanonicalUri(url);
    debug("Canonical Uri: %s", canonicalUri);

    canonicalQueryString = this.generateCanonicalQueryString(params);
    debug("Canonical Query string: %s", canonicalQueryString);

    canonicalHeaders = this.generateCanonicalHeaders(headers, url,signedHeaders);
    debug("Canonical Headers: \n %s", canonicalHeaders);

    canonicalRequest = method.toUpperCase() + "\n" + canonicalUri + "\n" + canonicalQueryString + "\n" + canonicalHeaders;
    debug("Canonical Request: \n %s", canonicalRequest);

    signature = this.hash(canonicalRequest, signingKey.toString());
    debug("Signature: %s", signature.toString());
    // console.log("Canonical Uri: " + canonicalUri);
    // console.log("Canonical Query string: " + canonicalQueryString);
    // console.log("Canonical Headers: \n" + canonicalHeaders);
    // console.log("Canonical Request: \n" + canonicalRequest);
    // console.log("Signature: " + signature.toString());

    var Authorization = signingKeyStr + "/" + this.g_signed_headers + "/" + signature.toString();

    return Authorization;
}

module.exports = Auth;

