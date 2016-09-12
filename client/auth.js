'use strict';

const os = require('os');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs-extra');
const exec = require('child_process').execSync;
const request = require('request');
const conf_path = path.join(os.homedir(), '.elfpm');
const conf = path.join(conf_path, 'conf.json');
const keys = path.join(conf_path, 'keys');
const privkey = path.join(keys, 'priv.pem');
const uri = {
  reg: 'https://localhost.daplie.com:3217/register',
  reg_pubk: 'https://localhost.daplie.com:3217/register/auth_pubk',
  login: 'https://localhost.daplie.com:3217/login',
  add_frd: 'https://localhost.daplie.com:3217/auth/add_frd'
};

/**
 * update config file with given object
 */

function update_conf(obj, cb) {
  fs.readJson(conf, (err, f) => {
    if (err) {
      return cb(err.message);
    }
    f = Object.assign(f, obj);
    fs.writeJson(conf, f, (err) => {
      if (err) {
        return cb(err.message);
      }
      return cb();
    });
  });
}

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
 * calculate public key from RSA key
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
 * save json web token locally for subsequent
 * authenticated requests
 */

function save_token(tok, cb) {
  update_conf({token: tok}, (err) => {
    if (err) {
      return cb(err);
    }
    return cb();
  });
}

/**
 * return locally saved token
 */

function get_token() {
  try {
    return fs.readJsonSync(conf).token;
  } catch(err) {
    throw err.message;
  }
}

/**
 * delete locally saved token
 */

function destroy_token(cb) {
  update_conf({token: null}, (err) => {
    if (err) {
      return cb(err);
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
 * get username
 */

function get_username() {
  try {
    return fs.readJsonSync(conf).username;
  } catch(err) {
    throw err.message;
  }
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
        fs.mkdirpSync(keys);
        fs.outputJsonSync(conf, {username: username});
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
 * sign password with user's private key before sending to server.
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
 * add new friend's public key to the list of pubkeys
 */

function save_frd_pubkey(frd_username, pubkey, cb) {
  fs.readJson(conf, (err, f) => {
    if (err) {
      return cb(err);
    }
    if (f.pubkeys) {
      f.pubkeys = Object.assign(f.pubkeys, {[frd_username]: pubkey});
      fs.writeJson(conf, f, (err) => {
        if (err) {
          return cb(err);
        }
        return cb();
      });
    }
  });
}

/**
 * make a request to /auth/add_frd to add new friend.
 * it is a protected route. client needs to send the
 * returning token in the headers authorization
 */

function add_frd(frd_username, cb) {
  var server_res = {};
  var token, username;

  try {
    token = get_token();
    username = get_username();
  } catch(err) {
    return cb(err);
  }

  request.post({
    url: uri.add_frd,
    headers: {"authorization": token},
    rejectUnauthorized: true,
    form: {un: username, frd_un: frd_username}
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

    // successfully added new friend, server responded with
    // the friend's public key, save it locally
    if (server_res.pubkey) {
      save_frd_pubkey(frd_username, server_res.pubkey, (err) => {
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
  destroy_token: destroy_token,
  add_frd: add_frd
};

