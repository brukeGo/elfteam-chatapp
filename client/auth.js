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
  reg: 'https://localhost.daplie.com:3012/register',
  reg_pubk: 'https://localhost.daplie.com:3012/register/auth_pubk',
  login: 'https://localhost.daplie.com:3012/login',
  msg: 'https://localhost.daplie.com:3012/auth_msg',
  unread: 'https://localhost.daplie.com:3012/auth_unread'
};
const encoding = 'base64';
const alg = 'aes-256-cbc'; // encryption algorithm
const hmac_alg = 'sha256'; // hmac algorithm

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
    throw err;
  }
}

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
    return fs.readFileSync(privkey, 'utf8').trim();
  } catch(err) {
    throw err.message;
  }
}

/**
 * get public key read in from a pem encoded file
 */

function get_pubkey(user) {
  try {
    return fs.readFileSync(path.join(keys, `${user}-key.pem`), 'utf8').trim();
  } catch(err) {
    throw err.message;
  }
}

/**
 * sign data with user's private key before sending to server
 *
 * @return base64 signature of the given data
 */

function gen_sign(data) {
  const sign = crypto.createSign('RSA-SHA256');
  sign.write(data);
  sign.end();
  return sign.sign(get_privkey(), encoding);
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
    return fs.readFileSync(token_path, 'utf8').trim();
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
  var pubkey, pubkey_sig, server_res;

  try {
    pubkey = Buffer.from(get_pubkey(username)).toString(encoding);
    pubkey_sig = gen_sign(pubkey);
  } catch(err) {
    return cb('error found:' + err.toString());
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
  var server_res, tok;

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
  return veri.verify(Buffer.from(pubkey, encoding).toString(), sig, encoding);
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

/**
 * get friend's public key from friend list
 */

function get_frd_pubkey(frd_username) {
  var pubkeys;
  try {
    pubkeys = fs.readJsonSync(pubkeys);
    if (Object.keys(pubkeys).indexOf(frd_username) === -1) {
      throw `${frd_username} not found in friend list`;
    } else {
      return pubkeys[frd_username];
    }
  } catch(err) {
    throw `${frd_username} not found in friend list`;
  }
}

/**
 * encrypt a given message and return the cipher text
 */

function enc(msg, receiver) {
  var receiver_pubkey, msg_key, hmac_key, iv,
    hmac, tag, keys_encrypted, cipher, cipher_text;

  try {
    receiver_pubkey = get_frd_pubkey(receiver);
  } catch(err) {
    throw err;
  }
  msg_key = crypto.randomBytes(32);
  hmac_key = crypto.randomBytes(32);
  iv = crypto.randomBytes(16); // initialization vector 128 bits
  hmac = crypto.createHmac(hmac_alg, hmac_key);

  // encrypt the message with random iv
  cipher = crypto.createCipheriv(alg, msg_key, iv);
  cipher_text = cipher.update(msg, 'utf8', encoding);
  cipher_text += cipher.final(encoding);

  // make sure both the cipher text and
  // the iv are protected by hmac
  hmac.update(cipher_text);
  hmac.update(iv.toString(encoding));
  tag = hmac.digest(encoding);

  // encrypt concatenated msg and hmac keys with receiver's public key
  keys_encrypted = crypto.publicEncrypt(receiver_pubkey, Buffer.from(`${msg_key.toString(encoding)}&${hmac_key.toString(encoding)}`));

  // concatenate keys, cipher text, iv and hmac digest
  return `${keys_encrypted.toString(encoding)}#${cipher_text}#${iv.toString(encoding)}#${tag}`;
}

/**
 * decrypt a given cipher text and return the derived plaintext
 */

function dec(cipher_text) {
  var privkey, chunk, keys_encrypted, keys_dec, 
    ct, iv, tag, msg_key, hmac_key, hmac,
    computed_tag, decipher, decrypted;
  try {
    privkey = get_privkey();
    chunk = cipher_text.split('#');
    keys_encrypted = Buffer.from(chunk[0], encoding);
    ct = chunk[1];
    iv = Buffer.from(chunk[2], encoding);
    tag = chunk[3];
    keys_dec = crypto.privateDecrypt(privkey, keys_encrypted).toString('utf8').split('&');
    msg_key = Buffer.from(keys_dec[0], encoding);
    hmac_key = Buffer.from(keys_dec[1], encoding);

    hmac = crypto.createHmac(hmac_alg, hmac_key);
    hmac.update(ct);
    hmac.update(iv.toString(encoding));
    computed_tag = hmac.digest(encoding);
    if (computed_tag !== tag) {
      throw 'encrypted tag not valid';
    }
    decipher = crypto.createDecipheriv(alg, msg_key, iv);
    decrypted = decipher.update(ct, encoding, 'utf8');
    return decrypted += decipher.final('utf8');
  } catch(err) {
    throw err;
  }
}

/**
 * send encrypted message to the server
 */

function send_msg(msg, receiver, cb) {
  var username, token, enc_data, server_res;
  try {
    username = get_username();
    token = get_token();
    enc_data = enc(msg, receiver);
  } catch(err) {
    return cb(err);
  }
  request.post({
    url: uri.msg,
    rejectUnauthorized: true,
    headers: {"authorization": token},
    form: {sender: username, receiver: receiver, msg: enc_data}
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
 * parse list of unread messages object
 */

function parse_unread_list(unread_obj, cb) {
  try {
    
  } catch(err) {
    return cb(err, null);
  }
}

/**
 * request to get unread messages from server
 */

function get_unread(cb) {
  var username, token, server_res;
  try {
    username = get_username();
    token = get_token();
  } catch(err) {
    return cb(err, null);
  }
  request.post({
    url: uri.unread,
    rejectUnauthorized: true,
    headers: {"authorization": token},
    form: {un: username}
  }, (error, res, body) => {
    if (error) {
      console.log(`request-err: ${error}`);
      return cb(error.message, null);
    }
    try {
      server_res = JSON.parse(body);
    } catch(err) {
      return cb(err.message, null);
    }
    if (server_res.err) {
      return cb(server_res.err, null);
    }
    if (server_res.unread) {
      parse_unread_list(server_res.unread, (err, unread) => {
        if (err) {
          return cb(err, null);
        }
        if (unread) {
          return cb(null, unread);
        }
      });
    } else {
      return cb();
    }
  });
}

module.exports = {
  register: register,
  login: login,
  destroy_token: destroy_token,
  verify_pubkey: verify_pubkey,
  save_frd_pubkey: save_frd_pubkey,
  get_frds: get_frds,
  send_msg: send_msg,
  get_unread: get_unread
};

