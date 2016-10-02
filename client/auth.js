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
const assign = require('deep-assign');
const jwt = require('jsonwebtoken');
const tmp = path.join(__dirname, 'tmp');
const privkey_path = path.join(tmp, 'priv.pem');
const pubkey_path = path.join(tmp, 'pub.pem');
const uri = {
  login: 'https://localhost.daplie.com:3761/login',
  send_frd_req: 'https://localhost.daplie.com:3761/auth/send_frd_req',
  get_frd_req: 'https://localhost.daplie.com:3761/auth/get_frd_req',
  get_frd_rej: 'https://localhost.daplie.com:3761/auth/get_frd_rej',
  rej_frd_req: 'https://localhost.daplie.com:3761/auth/rej_frd_req',
  clear_frd_req: 'https://localhost.daplie.com:3761/auth/clear_frd_req',
  clear_frd_rej: 'https://localhost.daplie.com:3761/auth/clear_frd_rej',
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
 * return locally saved token for sending to the server
 */

function get_user_tok(cb) {
  db.get('name', (err, username) => {
    if (err) {
      return cb(err.message);
    } else {
      db.get('tok', (err, token) => {
        if (err) {
          return cb(err.message);
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
  get_user_tok((err, res) => {
    if (err) {
      return cb(err.message);
    }
    opts = assign(opts, {headers: {authorization: res.tok}, rejectUnauthorized: true, form: {sen: res.un}});
    request.post(opts, (error, res, body) => {
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
        return cb(null, server_res);
      }
    });
  });
}

/**
 * make a post request to /register endpoint.
 * after successfully registered, save user data
 * to local db
 */

function login(username, passw, cb) {
  var server_res;
  request.post({url: uri.login, form: {un: username, pw: passw}}, (err, res, body) => {
    if (err) {
      return cb(err.message);
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
      db.put('tok', server_res.token, (err) => {
        if (err) {
          return cb(err.message);
        } else {
          // check if user already created RSA key
          db.get('pub', (err) => {
            if (err) {
              // it is the first time user logs in
              // generate user's keys and save it
              // user's local db

              try {
                rm.sync(tmp);
                mkdirp.sync(tmp);
                gen_privkey();
                gen_pubkey();
                db.batch()
                  .put('name', username)
                  .put('priv', get_privkey())
                  .put('pub', get_pubkey())
                  .put('frds', JSON.stringify({ls: []}))
                  .write(() => {
                    console.log(`${username} saved to db successfully`);
                    rm.sync(tmp);
                    return cb();
                  });
              } catch(er) {
                return cb(er.message);  
              }
            } else {
              return cb();
            }
          });
        }
      });
    } else {
      return cb('no authorization token');
    }
  });
}

/**
 * add friend's data to local db
 */

function add_frd(frd_username, pubkey, sec, cb) {
  var frds;
  db.get('frds', (err, val) => {
    if (err) {
      return cb(err.message);
    }
    try {
      frds = JSON.parse(val);
    } catch(er) {
      return cb(er.message);
    }
    frds.ls.push({name: frd_username, pubkey: pubkey, sec: sec});
    db.put('frds', JSON.stringify(frds), (err) => {
      if (err) {
        return cb(err.message);
      } else {
        return cb();
      }
    });
  });
}

/**
 * get the user's friend list
 */

function get_frds(cb) {
  var frds;
  db.get('frds', (err, val) => {
    if (err) {
      return cb(err.message);
    }
    try {
      frds = JSON.parse(val);
    } catch(err) {
      return cb(err.message);
    }
    if (frds.ls.length > 0) {
      return cb(null, frds.ls);
    } else {
      return cb();
    }  
  });
}
/**
 * put user public key in a token and sign it
 * with user/friend shared secret
 */

function gen_frd_tok(frd_name, sec, cb) {
  var tok;
  db.get('name', (err, usern) => {
    if (err) {
      return cb(err.message);
    }
    db.get('pub', (err, pubkey) => {
      if (err) {
        return cb(err.message);
      }
      // sign jwt symmetric with user/friend shared secret
      tok = jwt.sign({
        iat: new Date().getTime(),
        exp: Math.floor(new Date().getTime()/1000) + 60*60,
        iss: usern,
        sub: frd_name,
        pub: Buffer.from(pubkey).toString(encoding)
      }, sec, {algorithm: 'HS256'});
      return cb(null, tok);
    });   
  });
}

function get_frd_sec(frd_username, cb) {
  var sec;
  get_frds((err, frds) => {
    if (err) {
      return cb(err);
    }
    if (frds) {
      frds.forEach((frd) => {
        if (frd.sec && frd.name === frd_username) {
          sec = frd.sec;
        }
      });
      return cb(null, sec);
    } else {
      return cb();
    }
  });
}

/**
 * generate a message token and sign it with user/friend shared secret
 */

function gen_msg_tok(enc_dat, receiver, cb) {
  var tok;
  db.get('name', (err, usern) => {
    if (err) {
      return cb(err.message);
    }
    get_frd_sec(receiver, (err, sec) => {
      if (err) {
        return cb(err);
      }
      // sign jwt symmetric with user/friend shared secret
      tok = jwt.sign({
        iat: new Date().getTime(),
        exp: Math.floor(new Date().getTime()/1000) + 60*60,
        iss: usern,
        sub: receiver,
        msg: enc_dat
      }, sec, {algorithm: 'HS256'});
      return cb(null, tok);
    });
  });
}

/**
 * verify a message token
 */

function verify_msg_tok(frd, tok, cb) {
  get_frd_sec(frd, (err, sec) => {
    if (err) {
      return cb(err);
    }
    jwt.verify(tok, sec, {algorithms: 'HS256'}, (err, decod) => {
      if (err) {
        return cb(err.message);
      }
      db.get('name', (err, usern) => {
        if (err) {
          return cb(err.message);
        }
        if (decod.iss === frd && decod.sub === usern && decod.msg) {
          return cb(null, decod);
        } else {
          return cb('invalid message token');
        }
      });
    });
  });
}

/**
 * verify friend token
 */

function verify_frd_tok(frd_name, tok, sec, cb) {
  // verify jwt symmetric with user/friend shared secret
  jwt.verify(tok, sec, {algorithms: 'HS256'}, (err, decod) => {
    if (err) {
      return cb(err.message);
    }
    db.get('name', (err, usern) => {
      if (err) {
        return cb(err.message);
      }
      if (decod.iss === frd_name && decod.sub === usern && decod.pub) {
        return cb(null, decod);
      } else {
        return cb('invalid token');
      }
    });
  });
}

function clear_frd_req(cb) {      
  req({url: uri.clear_frd_req}, (err) => {
    if (err) {
      return cb(err);
    } else {
      return cb();
    }
  });
}

function verify_frd_req(frd, sec, cb) {
  var req;
  db.get('frd_req', (err, val) => {
    if (err) {
      return cb(err.message);
    }
    try {
      req = JSON.parse(val);
    } catch(err) {
      return cb(err.message);
    }
    if (!req.sen || !req.tok) {
      return cb('invalid friend request');
    } else {
      if (req.sen === frd) {
        verify_frd_tok(req.sen, req.tok, sec, (err, decod) => {
          if (err) {
            return cb(err);
          } else {
            add_frd(frd, Buffer.from(decod.pub, encoding).toString(), sec, (err) => {
              if (err) {
                return cb(err);
              } else {
                db.del('frd_req', (err) => {
                  if (err) {
                    return cb(err.message);
                  }
                  return cb();
                });
              }
            });
          }
        });
      } else {
        return cb('invalid token');
      }
    }
  });
}

/**
 * send a friend request
 */

function send_frd_req(frd_un, sec, cb) {
  gen_frd_tok(frd_un, sec, (err, tok) => {
    if (err) {
      return cb(err);
    } else {
      req({url: uri.send_frd_req, form: {rec: frd_un, tok: tok}}, (err) => {
        if (err) {
          return cb(err);
        }
        return cb();
      });
    }
  });
}

function send_frd_rej(frd, cb) {
  req({url: uri.rej_frd_req, form: {frd: frd}}, (err) => {
    if (err) {
      return cb(err);
    }
    return cb();
  });
}

/**
 * fetch friend requests
 */

function fetch_frd_req(cb) {
  req({url: uri.get_frd_req}, (err, res) => {
    if (err) {
      return cb(err);
    }
    if (res && res.frd_req.tok) {
      db.put('frd_req', JSON.stringify(res.frd_req), (err) => {
        if (err) {
          return cb(err.message);
        } else {
          clear_frd_req((err) => {
            if (err) {
              return cb(err);
            }
            return cb(null, true);
          });
        }
      });
    } else {
      return cb();
    }
  });
}

function get_frd_req(cb) {
  var req;
  db.get('frd_req', (err, val) => {
    if (err) {
      return cb(err.message);
    }
    try {
      req = JSON.parse(val);
    } catch(err) {
      return cb(err.message);
    }
    return cb(null, req);
  });
}

function clear_frd_rej(cb) {
  req({url: uri.clear_frd_rej}, (err) => {
    if (err) {
      return cb(err);
    } else {
      return cb();
    }
  });
}

function fetch_frd_rej(cb) {
  req({url: uri.get_frd_rej}, (err, res) => {
    if (err) {
      return cb(err);
    }
    if (res.frd_rej) {
      db.put('frd_rej', res.frd_rej, (err) => {
        if (err) {
          return cb(err.message);
        }
        clear_frd_rej((err) => {
          if (err) {
            return cb(err);
          }
          return cb(null, true);
        });
      });
    } else {
      return cb();
    }
  });
}

function clear_frd_rej_loc(cb) {
  db.del('frd_rej', (err) => {
    if (err) {
      return cb(err.message);
    }
    return cb();
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
        frd_pubkey = frd.pubkey;
      }
    });
    return cb(null, frd_pubkey);
  });
}

/**
 * encrypt a given message with receiver's pubkey 
 * and return the cipher text
 */

function encrypt(msg, receiver, cb) {
  var msg_key, hmac_key, iv,
    hmac, tag, keys_encrypted, cipher, cipher_text;

  get_frd_pubkey(receiver, (err, rec_pubkey) => {
    if (err) {
      return cb(err, null);
    }
    if (rec_pubkey) {
      // we have receiver's pubkey, try to encrypt the message
      try {
        msg_key = crypto.randomBytes(32);
        hmac_key = crypto.randomBytes(32);
        iv = crypto.randomBytes(16); // 128 bits initialization vector
        hmac = crypto.createHmac(hmac_alg, hmac_key);

        // encrypt the message with random iv
        cipher = crypto.createCipheriv(alg, msg_key, iv);
        cipher_text = cipher.update(msg, 'utf8', encoding);
        cipher_text += cipher.final(encoding);

        // make sure both the cipher text and the iv are protected by hmac
        hmac.update(cipher_text);
        hmac.update(iv.toString(encoding));
        tag = hmac.digest(encoding);

        // encrypt concatenated msg and hmac keys with receiver's public key
        keys_encrypted = crypto.publicEncrypt(rec_pubkey, Buffer.from(`${msg_key.toString(encoding)}&${hmac_key.toString(encoding)}`));
        // concatenate keys, cipher text, iv and hmac digest
        return cb(null, `${keys_encrypted.toString(encoding)}#${cipher_text}#${iv.toString(encoding)}#${tag}`);
      } catch(err) {
        return cb(err.message);
      } 
    } else {
      return cb('friend\'s public key not found');
    }
  });
}

/**
 * decrypt a given cipher text and return the derived plaintext
 */

function decrypt(cipher_text, cb) {
  var chunk, keys_encrypted, keys_dec, 
    ct, iv, tag, msg_key, hmac_key, hmac,
    computed_tag, decipher, decrypted;

  db.get('priv', (err, privkey) => {
    if (err) {
      return cb(err.message);
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
        return cb('invalid integrity tag');
      }
      decipher = crypto.createDecipheriv(alg, msg_key, iv);
      decrypted = decipher.update(ct, encoding, 'utf8');
      decrypted += decipher.final('utf8');
      return cb(null, decrypted);
    } catch(err) {
      return cb(err.message);
    }
  });
}

/**
 * send encrypted message to the server
 */

function send_msg(msg, receiver, cb) {
  var d; 
  encrypt(msg, receiver, (err, enc_dat) => {
    if (err) {
      return cb(err);
    }
    gen_msg_tok(enc_dat, receiver, (err, tok) => {
      if (err) {
        return cb(err);
      }
      req({url: uri.msg, form: {rec: receiver, tok: tok}}, (err) => {
        if (err) {
          return cb(err);
        } else {
          db.get('name', (err, un) => {
            if (err) {
              return cb(err.message);
            }
            d = new Date();
            return cb(null, {un: un, time: `${d.getHours()}:${d.getMinutes()}`});
          });
        }
      });
    });
  });
}

/**
 * decrypt unread messages
 */

function decrypt_unread(unread_msgs, cb) {    
  var msgs = [];
  async.each(unread_msgs, (unread, callback) => {
    if (!unread.sen || !unread.tok || !unread.time) {
      return callback('invalid message token');
    } else {
      verify_msg_tok(unread.sen, unread.tok, (err, decod) => {
        if (err) {
          return callback(err);
        }
        decrypt(decod.msg, (err, decrypted) => {
          if (err) {
            return callback(err);
          } else {
            msgs.push({sen: unread.sen, msg: decrypted, time: unread.time});
            return callback();
          }
        });
      });
    }
  }, (err) => {
    if (err) {
      return cb(err);
    } else {
      return cb(null, msgs);
    }
  });
}

/**
 * remove unread messages from server db
 */

function clear_unread(cb) {
  req({url: uri.clear_unread}, (err) => {
    if (err) {
      return cb(err);
    } else {
      return cb();
    }
  });
}

/**
 * request to get unread messages from server
 */

function fetch_unread(cb) {
  req({url: uri.unread}, (err, res) => {
    if (err) {
      return cb(err);
    }
    if (res.unread) {
      decrypt_unread(res.unread, (err, msgs) => {
        if (err) {
          return cb(err);
        } else {
          clear_unread((err) => {
            if (err) {
              return cb(err);
            }
            return cb(null, msgs);
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
  req({url: uri.logout}, (err) => {
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
}

module.exports = {
  login: login,
  verify_frd_req: verify_frd_req,
  send_frd_req: send_frd_req,
  send_frd_rej: send_frd_rej,
  fetch_frd_req: fetch_frd_req,
  fetch_frd_rej: fetch_frd_rej,
  add_frd: add_frd,
  get_frds: get_frds,
  send_msg: send_msg,
  fetch_unread: fetch_unread,
  logout: logout,
  get_frd_req: get_frd_req,
  clear_frd_rej_loc: clear_frd_rej_loc,
};
