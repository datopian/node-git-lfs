'use strict';

var AWS = require('aws-sdk');
var URL = require('url');
var ms = require('ms');

var Store = require('./index')
var S3Store = require('./s3_store');

const AWS_ALGORITHM = 'AWS4-HMAC-SHA256';
const AWS_SERVICE_NAME = 's3';
const AWS_EXPIRE_TIME = '15m';

class S3DirectStore extends S3Store {

    /**
     * Construct S3DirectStore instance
     * @param {Object} options, optional
     */
    constructor(options) {
        super(options);
        this._options = options || {};
    }


    getUploadAction(user, repo, oid, size) {
        var resource = this._getResource(user, repo, oid);

        var url = this._getURL(resource);

        var datetime = this._getDate();

        let storageClass = this._options.storage_class || 'STANDARD';

        var headers = {
            'Host': url.hostname,
            'X-Amz-Date': datetime,
            'Content-Type': 'application/octet-stream',
            'X-Amz-Content-Sha256': 'UNSIGNED-PAYLOAD',
            'X-Amz-Storage-Class': storageClass
        };

        this._addAuthorizationHeader(headers, 'PUT', resource);

        return {
            href: url.href,
            expires_at: S3DirectStore._getExpireTime(),
            header: headers
        };
    }

    getDownloadAction(user, repo, oid, size) {
        var resource = this._getResource(user, repo, oid);
        var url = this._getURL(resource);

        var datetime = this._getDate();

        var headers = {
            'Host': url.hostname,
            'X-Amz-Date': datetime,
            'X-Amz-Content-Sha256': 'UNSIGNED-PAYLOAD',
        };

        this._addAuthorizationHeader(headers, 'GET', resource);

        return {
            href: url.href,
            expires_at: S3DirectStore._getExpireTime(),
            header: headers
        };

    }

    _getResource(user, repo, oid) {
        var key = Store.transformKey(oid);
        return `/${this._options.bucket}/${user}/${repo}/${key}`;
    }

    _getEndpoint() {
        var endpoint = this._options.endpoint;
        if (endpoint) {
            return endpoint;
        }
        var region = this._options.region;
        if (!region || region.toLowerCase === 'us-east-1') {
            return 'https://s3.amazonaws.com';
        } else {
            return `https://s3-${region}.amazonaws.com`;
        }

    }

    _getURL(resource) {
        var endpoint = this._getEndpoint();
        var urlStr = endpoint;
        if (!urlStr.endsWith('/')) {
            urlStr = urlStr + '/';
        }
        urlStr = urlStr + resource.substring(1, resource.length);
        return URL.parse(urlStr);
    }

    _addAuthorizationHeader(headers, method, resource){

        var credString = this._getCredString(headers['X-Amz-Date']);

        var signedHeaders = this._getSignedHeaders(headers);

        var credentials = this._getCredentials(headers['X-Amz-Date']);

        var stringToSign = this._getStringToSign(headers, method, resource);

        var signature = this._getSignature(credentials, stringToSign);

        var parts = [];
        parts.push(AWS_ALGORITHM + ' Credential=' + this._options.access_key + '/' + credString);
        parts.push('SignedHeaders=' + signedHeaders);
        parts.push('Signature=' + signature);

        headers.Authorization = parts.join(', ');
    }

    _getCredString(datetime){
        var parts = [];

        parts.push(datetime.substr(0, 8));
        parts.push(this._options.region);
        parts.push(AWS_SERVICE_NAME);
        parts.push('aws4_request');

        return parts.join('/');
    }

    _getSignedHeaders(headers){
        var keys = [];
        AWS.util.each.call(this, headers, function (key) {
            key = key.toLowerCase();
            if (this._shouldBeSigned(key))
                keys.push(key);
        });
        return keys.sort().join(';');
    }

    _getCredentials(datetime){
        var date = datetime.substr(0, 8);

        var kSecret = this._options.secret_key;
        var kDate = AWS.util.crypto.hmac('AWS4' + kSecret, date, 'buffer');
        var kRegion = AWS.util.crypto.hmac(kDate, this._options.region, 'buffer');
        var kService = AWS.util.crypto.hmac(kRegion, AWS_SERVICE_NAME, 'buffer');
        var kCredentials = AWS.util.crypto.hmac(kService, 'aws4_request', 'buffer');

        return kCredentials
    }

    _getStringToSign(headers, method, canonicalizedResource){
        var parts = [];
        parts.push(AWS_ALGORITHM);
        parts.push(headers['X-Amz-Date']);
        parts.push(this._getCredString(headers['X-Amz-Date']));
        parts.push(this._getHexEncodedHash(this._getCanonicalizedString(headers, method, canonicalizedResource)));
        return parts.join('\n');
    }

    _getCanonicalizedString(headers, method, canonicalizedResource){
        var parts = [];
        parts.push(method);
        parts.push(canonicalizedResource);
        parts.push('');
        parts.push(this._getCanonicalizedAmzHeaders(headers));
        parts.push('');
        parts.push(this._getSignedHeaders(headers));
        parts.push(headers['X-Amz-Content-Sha256']);
        return parts.join('\n');
    }

    _getCanonicalizedAmzHeaders(headers){

        var amzHeaders = [];

        AWS.util.each.call(this, headers, function (name) {
            if (this._shouldBeSigned(name))
                amzHeaders.push(name);
        });

        amzHeaders.sort(function (a, b) {
            return a.toLowerCase() < b.toLowerCase() ? -1 : 1;
        });

        var parts = [];
        AWS.util.arrayEach.call(this, amzHeaders, function (name) {
            parts.push(name.toLowerCase() + ':' + String(headers[name]));
        });

        return parts.join('\n');
    }

    _getHexEncodedHash(string) {
        return AWS.util.crypto.sha256(string, 'hex');
    }

    _getSignature(credentials, stringToSign) {
        return AWS.util.crypto.hmac(credentials, stringToSign, 'hex');
    }

    _shouldBeSigned(key) {
        return key.match(/^x-amz-|^host$/i);
    }

    _getDate() {
        return new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');
    }

    static _getExpireTime() {
        return new Date(new Date().getTime() + ms(AWS_EXPIRE_TIME)).toISOString();
    }

}



module.exports = S3DirectStore;
