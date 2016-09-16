'use strict';

const os = require('os');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs-extra');
const exec = require('child_process').execSync;
const request = require('request');
const conf = path.join(os.homedir(), '.elfpm');
const keys = path.join(conf, 'keys');
const pubkeys = path.join(conf, 'pubkeys.json');
const privkey = path.join(keys, 'priv.pem');
const token_path = path.join(conf, '.tok');
const uri = {
  reg: 'https://localhost.daplie.com:3019/register',
  reg_pubk: 'https://localhost.daplie.com:3019/register/auth_pubk',
  login: 'https://localhost.daplie.com:3019/login'
};

/**
 * generate fresh RSA key by executing openssl commands
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
 * calculate the actual client's public key from RSA key
 */

function gen_pubkey(user) {
  var pubkey_path = path.join(keys, `${user}-key.pem`);
  try {
    exec(`openssl rsa -in ${privkey} -out ${pubkey_path} -outform PEM -pubout`, {stdio: [0, 'pipe']});
  } catch(err) {
    throw err.toString();
  }
  return;
}

/**
 * get private key read in from a pem encoded file
 */

function get_privkey() {
  try {
    return fs.readFileSync(privkey);
  } catch(err) {
    throw err.toString();
  }
}

/**
 * get public key read in from a pem encoded file
 */

function get_pubkey(user) {
  try {
    return fs.readFileSync(path.join(keys, `${user}-key.pem`));
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
 * sign data with user's private key before sending to server.
 *
 * @return base64 signature of the given password
 */

function gen_sign(data) {
  const sign = crypto.createSign('RSA-SHA256');
  sign.write(data);
  sign.end();
  return sign.sign(get_privkey(), 'base64');
}

/**
 * get username
 */

function get_username() {
  try {
    fs.readdirSync(keys).forEach((f) => {
      if (f.includes('key')) {
        return f.split('-')[0];
      }
    });
  } catch(err) {
    throw err.message;
  }
}

/**
 * save json web token locally for subsequent
 * authenticated requests
 */

function save_token(tok, cb) {
  fs.outputFile(token_path, tok, (err) => {
    if (err) {
      return cb(err.message);
    }
    return cb();
  });
}

/**
 * return locally saved token
 */

function get_token() {
  try {
    return fs.readFileSync(token_path, 'utf8');
  } catch(err) {
    throw err.message;
  }
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
 * send user's base64 encoded signed public key 
 * to server, after new account succssfully created. It
 * is a protected route.
 */

function send_pubkey(username, token, cb) {
  var server_res = {};
  var pubkey, pubkey_sig;

  try {
    pubkey = encode_pubkey(username);
    pubkey_sig = gen_sign(pubkey);
  } catch(err) {
    return cb(err.toString());
  }

  request.post({
    url: uri.reg_pubk,
    rejectUnauthorized: true,
    headers: {"authorization": token},
    form: {un: username, pubkey: pubkey, sig: pubkey_sig}
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
        fs.removeSync(conf);
        fs.mkdirpSync(keys);
        fs.outputJsonSync(pubkeys, {});
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
 * make a post request to /login endpoint
 */

function login(usern, passw, cb) {
  var server_res = {};

  request.post({
    url: uri.login,
    rejectUnauthorized: true,
    form: {un: usern, pw: passw, pw_sig: gen_sign(passw)}
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

/**
 * save friend's verified public key and add it to the list of pubkeys
 */

function save_frd_pubkey(frd_username, pubkey, cb) {
  fs.readJson(pubkeys, (err, f) => {
    if (err) {
      return cb(err);
    }
    f = Object.assign(f, {[frd_username]: pubkey});
    fs.writeJson(pubkeys, f, (err) => {
      if (err) {
        return cb(err);
      }
      return cb();
    });
  });
}

/**
 * verify friend's public key received from server
 */

function verify_pubkey(pubkey, sig) {    
  const veri = crypto.createVerify('RSA-SHA256');
  veri.write(pubkey);
  veri.end();
  return veri.verify(new Buffer(pubkey, 'base64').toString(), sig, 'base64');
}

/**
 * get the client's friend list
 */

function get_frds() {
  try {
    return Object.keys(fs.readJsonSync(pubkeys));
  } catch(err) {
    return;
  }
}

module.exports = {
  register: register,
  login: login,
  destroy_token: destroy_token,
  verify_pubkey: verify_pubkey,
  save_frd_pubkey: save_frd_pubkey,
  get_frds: get_frds
};

