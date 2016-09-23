'use strict';

const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const exec = require('child_process').execSync;
const request = require('request');
const levelup = require('levelup');
const async = require('async');
const rm = require('rimraf');
const mkdirp = require('mkdirp');
const tmp = path.join(__dirname, 'tmp');
const privkey_path = path.join(tmp, 'priv.pem');
const pubkey_path = path.join(tmp, 'pub.pem');
const uri = {
  reg: 'https://localhost.daplie.com:3761/register',
  reg_pubk: 'https://localhost.daplie.com:3761/register/auth/pubk',
  login: 'https://localhost.daplie.com:3761/login',
  msg: 'https://localhost.daplie.com:3761/auth/msg',
  unread: 'https://localhost.daplie.com:3761/auth/unread',
  clear_unread: 'https://localhost.daplie.com:3761/auth/clear_unread',
  logout: 'https://localhost.daplie.com:3761/auth/logout'
};
const encoding = 'base64'; // data encoding
const alg = 'aes-256-cbc'; // encryption algorithm
const hmac_alg = 'sha256'; // hmac algorithm

// client's local storage
var db = levelup(path.join(__dirname, 'db'));

/**
 * generate fresh RSA key by executing openssl commands
 */

function gen_privkey() {
  try {
    exec(`openssl genrsa -out ${privkey_path} 2048`, {stdio: [0, 'pipe']});
  } catch(err) {
    throw err.message;
  }
  return;
}

/**
 * calculate client's public key from RSA key
 */

function gen_pubkey() {
  try {
    exec(`openssl rsa -in ${privkey_path} -out ${pubkey_path} -outform PEM -pubout`, {stdio: [0, 'pipe']});
  } catch(err) {
    throw err.message;
  }
  return;
}

/**
 * get private key read in from a pem encoded file
 */

function get_privkey() {
  try {
    return fs.readFileSync(privkey_path, 'utf8').trim();
  } catch(err) {
    throw err.message;
  }
}

/**
 * get public key read in from a pem encoded file
 */

function get_pubkey() {
  try {
    return fs.readFileSync(pubkey_path, 'utf8').trim();
  } catch(err) {
    throw err.message;
  }
}

/**
 * sign data with user's private key before sending to server
 *
 * @return base64 signature of the given data
 */

function gen_sign(data, cb) {
  var sign;
  db.get('priv', (err, privkey) => {
    if (err) {
      return cb(err.message, null);
    }
    sign = crypto.createSign('RSA-SHA256');
    sign.write(data);
    sign.end();
    return cb(null, sign.sign(privkey, encoding));
  });
}

/**
 * return locally saved token for sending to server
 */

function get_tok(cb) {
  db.get('name', (err, username) => {
    if (err) {
      return cb(err.message);
    } else {
      db.get('tok', (err, token) => {
        if (err) {
          return cb();
        } else {
          return cb(null, {un: username, tok: token});
        }
      });
    }
  });
}

/**
 * make a post request with a given options obj and return server response
 */

function req(opts, cb) {
  var server_res;  
  opts = Object.assign(opts, {rejectUnauthorized: true});
  request.post(opts, (error, res, body) => {
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
    } else {
      return cb(null, server_res);
    }
  });
}

/**
 * send user's base64 encoded signed public key 
 * to server, after new account succssfully created. It
 * is a protected route.
 */

function send_pubkey(username, token, cb) {
  db.get('pub', (err, pubkey) => {
    if (err) {
      return cb(err.message);
    }
    gen_sign(pubkey, (err, pubkey_sig) => {
      if (err) {
        return cb(err.message);
      }
      req({
        url: uri.reg_pubk,
        headers: {authorization: token},
        form: {un: username, pubkey: Buffer.from(pubkey).toString(encoding), sig: pubkey_sig}
      }, (err) => {
        if (err) {
          return cb(err);
        } else {
          rm.sync(tmp);
          return cb();
        }
      });
    });
  });
}

/**
 * make a post request to /register endpoint.
 * after successfully registered, save user data
 * to local db
 */

function register(username, passw, cb) {
  req({url: uri.reg, form: {un: username, pw: passw}}, (err, res) => {
    if (err) {
      return cb(err);
    }
    if (res.token) { 
      try {
        rm.sync(tmp);
        mkdirp.sync(tmp);
        gen_privkey();
        gen_pubkey();
        db.batch()
          .put('name', username)
          .put('priv', get_privkey())
          .put('pub', get_pubkey())
          .put('frd', JSON.stringify({ls: []}))
          .put('unread', JSON.stringify({ls: []}))
          .write(() => {
            console.log(`${username} saved to db successfully`);
            send_pubkey(username, res.token, (err) => {
              if (err) {
                console.log(err);
                return cb(err);
              }
              return cb();
            });
          });
      } catch(er) {
        return cb(er.message);  
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
  gen_sign(passw, (err, sig) => {
    if (err) {
      return cb(err);
    }
    req({url: uri.login, form: {un: usern, pw: passw, pw_sig: sig}}, (err, res) => {
      if (err) {
        return cb(err);
      }
      // successful authentication, server responded with a token
      // save it locally for the current session subsequent requests
      if (res.token) {
        db.put('tok', res.token, (err) => {
          if (err) {
            return cb(err.message);
          } else {
            return cb();
          }
        });
      } else {
        return cb('err: no authorization token');
      }
    });
  });
}

/**
 * add friend's data to local db
 */

function add_frd(frd_username, pubkey, cb) {
  var frds;
  db.get('frd', (err, val) => {
    if (err) {
      return cb(err.message);
    }
    try {
      frds = JSON.parse(val);
    } catch(er) {
      return cb(er.message);
    }
    frds.ls.push({name: frd_username, pubkey: pubkey});
    db.put('frd', JSON.stringify(frds), (err) => {
      if (err) {
        return cb(err.message);
      }
      return cb();
    });
  });
}

/**
 * verify friend's public key
 */

function verify_pubkey(pubkey, sig) {
  const veri = crypto.createVerify('RSA-SHA256');
  var pk = Buffer.from(pubkey, encoding).toString();
  veri.write(pk);
  veri.end();
  return veri.verify(pk, sig, encoding);
}

/**
 * get the client's friend list
 */

function get_frds(cb) {
  var frds;
  db.get('frd', (err, val) => {
    if (err) {
      return cb();
    }
    try {
      frds = JSON.parse(val);
    } catch(er) {
      return cb(er.message, null);
    }
    if (frds.ls.length > 0) {
      return cb(null, frds.ls);
    } else {
      return cb();
    }
  });
}

/**
 * get friend's public key from friend list
 */

function get_frd_pubkey(frd_username, cb) {
  var frd_pubkey;
  get_frds((err, frds) => {
    if (err) {
      return cb(err, null);
    }
    frds.forEach((frd) => {
      if (frd.pubkey && frd.name === frd_username) {
        frd_pubkey = Buffer.from(frd.pubkey, encoding).toString();
      }
    });
    return cb(null, frd_pubkey);
  });
}

/**
 * encrypt a given message with receiver's pubkey 
 * and return the cipher text
 */

function enc(msg, receiver, cb) {
  var msg_key, hmac_key, iv,
    hmac, tag, keys_encrypted, cipher, cipher_text;

  get_frd_pubkey(receiver, (err, rec_pubkey) => {
    if (err) {
      return cb(err, null);
    }
    if (rec_pubkey) {
      // we have receiver's pubkey, try to
      // encrypt the message
      try {
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
        keys_encrypted = crypto.publicEncrypt(rec_pubkey, Buffer.from(`${msg_key.toString(encoding)}&${hmac_key.toString(encoding)}`));
        // concatenate keys, cipher text, iv and hmac digest
        return cb(null, `${keys_encrypted.toString(encoding)}#${cipher_text}#${iv.toString(encoding)}#${tag}`);
      } catch(err) {
        return cb(err.message, null);
      } 
    }
  });
}

/**
 * decrypt a given cipher text and return the derived plaintext
 */

function dec(cipher_text, cb) {
  var chunk, keys_encrypted, keys_dec, 
    ct, iv, tag, msg_key, hmac_key, hmac,
    computed_tag, decipher, decrypted;

  db.get('priv', (err, privkey) => {
    if (err) {
      return cb(err.message, null);
      //throw err.message;
    }
    try {
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
        return cb('integrity tag not valid', null);
      }
      decipher = crypto.createDecipheriv(alg, msg_key, iv);
      decrypted = decipher.update(ct, encoding, 'utf8');
      decrypted += decipher.final('utf8');
      return cb(null, decrypted);
    } catch(err) {
      return cb(err.message, null);
    }
  });
}

/**
 * send encrypted message to the server
 */

function send_msg(msg, receiver, cb) {
  var d;
  get_tok((err, res) => {
    if (err) {
      return cb(err, null);
    }  
    enc(msg, receiver, (err, enc_dat) => {
      if (err) {
        return cb(err, null);
      }
      req({
        url: uri.msg,
        headers: {authorization: res.tok},
        form: {sender: res.un, rec: receiver, msg: enc_dat}
      }, (err) => {
        if (err) {
          return cb(err, null);
        } else {
          d = new Date();
          return cb(null, {un: res.un, time: `${d.getHours()}:${d.getMinutes()}`});
        }
      });
    });
  });
}

/**
 * decrypt unread messages and store decrypted data in local db
 * for showing on frond-end. this data will be removed after client
 * logs out or closes the application by another function
 */

function dec_and_save_unread(unread_msgs, cb) {
  var msgs;
  db.get('unread', (err, val) => {
    if (err) {
      return cb();
    }
    try {
      msgs = JSON.parse(val);
    } catch(err) {
      return cb(err.message);
    }
    async.each(unread_msgs, (unread, callback) => {
      if (!unread.sender || !unread.msg) {
        return callback('invalid unread message');
      } else {
        dec(unread.msg, (err, decrypted) => {
          if (err) {
            return callback(err);
          } else {
            msgs.ls.push({sender: unread.sender, msg: decrypted, time: unread.time});
            db.put('unread', JSON.stringify(msgs), (err) => {
              if (err) {
                return callback(err.message);
              } else {
                return callback();
              }
            });
          }
        });
      }
    }, (err) => {
      if (err) {
        return cb(err);
      } else {
        return cb();
      }
    });
  });
}

/**
 * request to get unread messages from server
 */

function fetch_unread(cb) {
  get_tok((err, res) => {
    if (err) {
      return cb(err);
    }
    req({url: uri.unread, headers: {authorization: res.tok}, form: {un: res.un}}, (err, server_res) => {
      if (err) {
        return cb(err);
      }
      if (server_res.unread) {
        dec_and_save_unread(server_res.unread, (err) => {
          if (err) {
            return cb(err);
          } else {
            return cb();
          }
        });
      } else {
        return cb();
      }
    });
  });
}

/**
 * return an array of decrypted unread messages
 */

function get_unread(cb) {
  db.get('unread', (err, val) => {
    var msgs;
    if (err) {
      return cb();
    }
    try {
      msgs = JSON.parse(val);
    } catch(err) {
      return cb(err.message, null);
    }
    if (msgs.ls.length > 0) {
      return cb(null, msgs.ls);
    } else {
      return cb();
    }
  });
}

/**
 * remove unread messages from local db after showing to the client
 */

function clear_unread(cb) {
  get_tok((err, res) => {
    if (err) {
      return cb(err);
    }
    if (res && res.tok && res.un) {
      req({url: uri.clear_unread, headers: {authorization: res.tok}, form: {un: res.un}}, (err) => {
        if (err) {
          return cb(err);
        } else {
          db.get('unread', (err, val) => {
            var msgs;
            if (err) {
              return cb();
            }
            try {
              msgs = JSON.parse(val);
            } catch(err) {
              return cb(err.message, null);
            }
            if (msgs.ls.length > 0) {
              msgs.ls.splice(0, msgs.ls.length);
              db.put('unread', JSON.stringify(msgs), (err) => {
                if (err) {
                  return cb(err.message);
                }
                return cb();
              });
            } else {
              return cb();
            }
          });
        }
      });
    } else {
      return cb();
    }
  });  
}

/**
 * log out of current session, token is removed
 * from both server and local db
 */

function logout(cb) {
  get_tok((err, res) => {
    if (err) {
      return cb(err);
    }
    if (res && res.tok && res.un) {
      req({url: uri.logout, headers: {authorization: res.tok}, form: {un: res.un}}, (err) => {
        if (err) {
          return cb(err);
        } else {
          db.del('tok', (err) => {
            if (err) {
              return cb();
            }
            return cb();
          });
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
  verify_pubkey: verify_pubkey,
  add_frd: add_frd,
  get_frds: get_frds,
  send_msg: send_msg,
  fetch_unread: fetch_unread,
  get_unread: get_unread,
  clear_unread: clear_unread,
  logout: logout
};

