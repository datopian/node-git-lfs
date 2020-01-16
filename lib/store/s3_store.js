"use strict";

var AWS = require("aws-sdk");

var Store = require("./");

class S3Store extends Store {
  /**
   * Construct S3Store instance
   * @param {Object} options, optional
   */
  constructor(options) {
    super();
    this._options = options || {};

    let s3_config = {
      accessKeyId: this._options.access_key,
      secretAccessKey: this._options.secret_key
    };

    // optional S3 endpoint
    if (this._options.endpoint) {
      s3_config.endpoint = this._options.endpoint;
      s3_config.s3ForcePathStyle = true;
    }

        // optional S3 region
        if (this._options.region) {
            s3_config.region = this._options.region;
        }

        // optional signature version
        if (this._options.signature_version) {
            s3_config.signatureVersion = this._options.signature_version;
        }

    this._s3 = new AWS.S3(s3_config);
  }

  put(user, repo, oid, stream) {
    var self = this;
    return new Promise(function(resolve, reject) {
      let storageClass = self._options.storage_class || "STANDARD";
      let params = {
        Bucket: self._options.bucket,
        Key: S3Store._getKey(user, repo, oid),
        Body: stream,
        StorageClass: storageClass
      };
      self._s3.upload(params, function(err, data) {
        if (err) {
          return reject(err);
        }
        resolve(data);
      });
    });
  }

  get(user, repo, oid) {
    var self = this;
    return new Promise(function(resolve) {
      var params = {
        Bucket: self._options.bucket,
        Key: S3Store._getKey(user, repo, oid)
      };
      resolve(self._s3.getObject(params).createReadStream());
    });
  }

  getSize(user, repo, oid) {
    var self = this;
    return new Promise(function(resolve, reject) {
      var params = {
        Bucket: self._options.bucket,
        Key: S3Store._getKey(user, repo, oid)
      };
      var attempt;
      attempt = function(idx) {
        self._s3.headObject(params, function(err, data) {
          if (err) {
            if (err.statusCode === 404 || err.statusCode === 403) {
              return resolve(-1);
            }
            if (idx < 10) {
              return attempt(idx + 1);
            } else {
              return reject(err);
            }
          }
          if (data === null) {
            if (idx < 10) {
              return attempt(idx + 1);
            } else {
              return resolve(-1);
            }
          } else {
            return resolve(Number(data.ContentLength));
          }
        });
      };
      attempt(0);
    });
  }

    static _getKey(user, repo, oid) {
        var key = Store.transformKey(oid);
        return `${user}/${repo}/${key}`;
    }

}

module.exports = S3Store;
