'use strict';

const os = require('os');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs-extra');
const exec = require('child_process').execSync;
const request = require('request');
const config = path.join(os.homedir(), '.elfpm', 'config');
const privkey = path.join(config, 'priv.pem');
const token_path = path.join(config, '.token');
const uri = {
  reg: 'https://localhost.daplie.com:3217/register',
  reg_pubk: 'https://localhost.daplie.com:3217/register/pubk',
  login: 'https://localhost.daplie.com:3217/login'
};

/**
 * generate fresh keypair by executing openssl commands
 */

function gen_privkey() {
  try {
    exec(`openssl genrsa -out ${privkey} 2048`, {stdio: [0, 'pipe']});
  } catch(err) {
    throw err.toString();
  }
  return;
}

/**
 * generate self-signed public key. This is 
 * user's certificate ( self-signed public key)
 * in a pem encoded format.
 */

function gen_pubkey(user) {
  var pubkey_path = path.join(config, `${user}-key.pem`);

  try {
    exec(`openssl rsa -in ${privkey} -out ${pubkey_path} -outform PEM -pubout`, {stdio: [0, 'pipe']});
  } catch(err) {
    throw err.toString();
  }
  return;
}

/**
 * get private key in a pem formatted file
 */

function get_privkey() {
  try {
    return fs.readFileSync(privkey);
  } catch(err) {
    throw err.toString();
  }
}

/**
 * get public key from a pem formatted file
 */

function get_pubkey(user) {
  try {
    return fs.readFileSync(path.join(config, `${user}-key.pem`));
  } catch(err) {
    throw err.toString();
  }
}

/**
 * return base64 encoded public key
 */

function encode_pubkey(user) {
  try {
    return new Buffer(get_pubkey(user)).toString('base64');
  } catch(err) {
    throw err.toString();
  }
}

/**
 * save json web token locally for subsequent
 * authenticated requests
 */

function save_token(token, cb) {
  fs.outputFile(token_path, token, (err) => {
    if (err) {
      return cb(err.message);
    }
    console.log('token saved sucessfully.');
    return cb();
  });
}

/**
 * delete locally saved token
 */

function destroy_token(cb) {
  fs.remove(token_path, (err) => {
    if (err) {
      return cb(err.message);
    }
    return cb();
  });
}

/**
 * send user's base64 encoded public key to server,
 * after new account succssfully created
 */

function send_pubkey(username, token, cb) {
  var server_res = {};

  request.post({
    url: uri.reg_pubk,
    rejectUnauthorized: true,
    headers: {"authorization": token},
    form: {un: username, pubkey: encode_pubkey(username)}
  }, (error, res, body) => {
    if (error) {
      console.log(`request-err: ${error}`);
      return cb(error.message);
    }

    try {
      server_res = JSON.parse(body);
    } catch(err) {
      return cb(err.message);
    }
    if (server_res.err) {
      return cb(server_res.err);
    } else {
      return cb();
    }
  });
}

/**
 * make a post request to /register endpoint
 */

function register(username, passw, cb) {
  var server_res = {};
  var tok;

  request.post({
    url: uri.reg,
    rejectUnauthorized: true,
    form: {un: username, pw: passw}
  }, (error, res, body) => {
    if (error) {
      console.log(`request-err: ${error}`);
      return cb(error.message);
    }  
    try {
      server_res = JSON.parse(body);
    } catch(err) {
      return cb(err.message);
    }
    if (server_res.err) {
      return cb(server_res.err);
    }
    if (server_res.token) {
      tok = server_res.token;  
      try {
        fs.mkdirpSync(config);
        gen_privkey();
        gen_pubkey(username);
        send_pubkey(username, tok, (err) => {
          if (err) {
            console.log(err);
            return cb(err);
          }
          return cb();
        });
      } catch(er) {
        return cb(er);  
      }
    } else {
      return cb('err: no authorization token');
    }
  });
}

/**
 * sign password with user's private key before 
 * sending to server.
 *
 * @return base64 signature of the given password
 */

function sign_password(passw) {
  const sign = crypto.createSign('RSA-SHA256');
  sign.write(passw);
  sign.end();
  return sign.sign(get_privkey(), 'base64');
}

/**
 * make a post request to /login endpoint
 */

function login(usern, passw, cb) {
  var server_res = {};

  request.post({
    url: uri.login,
    rejectUnauthorized: true,
    form: {un: usern, pw: passw, pw_sig: sign_password(passw)}
  }, (error, res, body) => {
    if (error) {
      console.log(`request-err: ${error}`);
      return cb(error.message, null);
    }
    try {
      server_res = JSON.parse(body);
    } catch(err) {
      return cb(err.message);
    }
    if (server_res.err) {
      return cb(server_res.err, null);
    }

    // successful authentication, server responded with a token
    // save it locally for the current session subsequent requests
    if (server_res.token) {
      console.log(server_res);
      save_token(server_res.token, (err) => {
        if (err) {
          return cb(err);
        }
        return cb();
      });
    } else {
      return cb('err: no authorization token');
    }
  });
}

module.exports = {
  register: register,
  login: login,
  destroy_token: destroy_token
};

