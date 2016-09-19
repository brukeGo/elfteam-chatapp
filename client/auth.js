'use strict';

const path = require('path');
const crypto = require('crypto');
const fs = require('fs-extra');
const exec = require('child_process').execSync;
const request = require('request');
const levelup = require('levelup');
const tmp = path.join(__dirname, 'tmp');
const privkey_path = path.join(tmp, 'priv.pem');
const pubkey_path = path.join(tmp, 'pub.pem');
const uri = {
  reg: 'https://localhost.daplie.com:3761/register',
  reg_pubk: 'https://localhost.daplie.com:3761/register/auth_pubk',
  login: 'https://localhost.daplie.com:3761/login',
  msg: 'https://localhost.daplie.com:3761/auth_msg',
  unread: 'https://localhost.daplie.com:3761/auth_unread'
};
const encoding = 'base64';
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
 * delete locally saved token
 */

function destroy_token(cb) {
  db.del('tok', (err) => {
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
  var server_res;

  db.get('pub', (err, pubkey) => {
    if (err) {
      return cb(err.message);
    }
    gen_sign(pubkey, (err, pubkey_sig) => {
      if (err) {
        return cb(err.message);
      }
      request.post({
        url: uri.reg_pubk,
        rejectUnauthorized: true,
        headers: {authorization: token},
        form: {un: username, pubkey: Buffer.from(pubkey).toString(encoding), sig: pubkey_sig}
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
        fs.removeSync(tmp);
        return cb();
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
  var server_res;
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
      try {
        fs.removeSync(tmp);
        fs.mkdirpSync(tmp);
        gen_privkey();
        gen_pubkey();
        db.batch()
          .put('name', username)
          .put('priv', get_privkey())
          .put('pub', get_pubkey())
          .put('frd', JSON.stringify({ls: []}))
          .write(() => {
            console.log(`${username} saved to db successfully`);
            send_pubkey(username, server_res.token, (err) => {
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
  var server_res;
  gen_sign(passw, (err, sig) => {
    if (err) {
      return cb(err);
    }
    request.post({
      url: uri.login,
      rejectUnauthorized: true,
      form: {un: usern, pw: passw, pw_sig: sig}
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
        db.put('tok', server_res.token, (err) => {
          if (err) {
            return cb(err.message);
          }
          return cb();
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
    frds.ls.push({name: frd_username, pubkey: pubkey, msgs: []});
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
  var result = [];
  db.get('frd', (err, val) => {
    if (err) {
      return cb(null, null);
    }
    try {
      frds = JSON.parse(val);
    } catch(er) {
      return cb(er.message, null);
    }
    if (frds.ls.length > 0) {
      frds.ls.forEach((frd) => {
        result.push({name: frd.name, msgs: frd.msgs});
      });
    }  
    return cb(null, result);
  });
}

/**
 * get friend's public key from friend list
 */

function get_frd_pubkey(frd_username, cb) {
  var frds;
  db.get('frd', (err, val) => {
    if (err) {
      return cb(err.message, null);
    }
    try {
      frds = JSON.parse(val);
    } catch(er) {
      return cb(er.message, null);
    }
    frds.ls.forEach((frd) => {
      if (frd.name === frd_username && frd.pubkey) {
        return cb(null, Buffer.from(frd.pubkey, encoding).toString());
      }
    });
    return cb(null, null);
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
  var d, server_res;
  db.get('name', (err, username) => {
    if (err) {
      return cb(err.message);
    }
    db.get('tok', (err, token) => {
      if (err) {
        return cb(err.message);
      }
      enc(msg, receiver, (err, enc_dat) => {
        if (err) {
          return cb(err);
        }
        request.post({
          url: uri.msg,
          rejectUnauthorized: true,
          headers: {authorization: token},
          form: {sender: username, rec: receiver, msg: enc_dat}
        }, (error, res, body) => {
          if (error) {
            console.log(`request-err: ${error}`);
            return cb(error.message, null, null);
          }
          try {
            server_res = JSON.parse(body);
          } catch(err) {
            return cb(err.message, null, null);
          }
          if (server_res.err) {
            return cb(server_res.err, null, null);
          } else {
            d = new Date();
            return cb(null, {un: username, time: `${d.getHours()}:${d.getMinutes()}`});
          }
        });
      });
    });
  });
}

/**
 * parse list of unread messages
 */

function save_unread_list(unread_msgs, cb) {
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
    frds.ls.forEach((frd) => {
      unread_msgs.forEach((unread_msg) => {
        if (unread_msg.sender === frd.name) {
          frd.msgs.push({msg: unread_msg.msg, time: unread_msg.time});
        }
      });
    });
    db.put('frd', JSON.stringify(frds), (err) => {
      if (err) {
        return cb(err.message);
      }
      return cb();
    });
  });
}

/**
 * request to get unread messages from server
 */

function check_unread(cb) {
  var server_res;
  db.get('name', (err, username) => {
    if (err) {
      return cb(err.message);
    }
    db.get('tok', (err, token) => {
      if (err) {
        return cb(err.message);
      }
      request.post({
        url: uri.unread,
        rejectUnauthorized: true,
        headers: {authorization: token},
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
          save_unread_list(server_res.unread, (err) => {
            if (err) {
              return cb(err, null);
            }
            return cb();
          });
        }
      });

    });
  });
}

/**
 * send friend's decrypted messages to ipc renderer 
 * for showing on frond-end
 */

function show_msg(frd_username, cb) {
  var dec_msgs = [];
  var frds;
  db.get('frd', (err, val) => {
    if (err) {
      return cb(err.message, null);
    }
    try {
      frds = JSON.parse(val);
    } catch(er) {
      return cb(er.message, null);
    }
    frds.ls.forEach((frd) => {
      if (frd.name === frd_username && frd.msgs.length > 0) {
        frd.msgs.forEach((message) => {
          dec(message.msg, (err, decrypted) => {
            if (err) {
              return cb(err, null);
            }
            dec_msgs.push({msg: decrypted, time: message.time});
          });
        });
      }
    });
    return cb(null, dec_msgs);
  });
}

module.exports = {
  register: register,
  login: login,
  destroy_token: destroy_token,
  verify_pubkey: verify_pubkey,
  add_frd: add_frd,
  get_frds: get_frds,
  send_msg: send_msg,
  check_unread: check_unread,
  show_msg: show_msg
};

