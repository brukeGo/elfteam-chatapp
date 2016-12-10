'use strict';

const path = require('path');
const crypto = require('crypto');
const request = require('request');
const levelup = require('levelup');
const async = require('async');
const gen_rsakey = require('keypair');
const assign = require('deep-assign');
const uri = {
  init_reg: 'https://elfocrypt.me/init_reg',
  reg: 'https://elfocrypt.me/reg',
  init_login: 'https://elfocrypt.me/init_login',
  login: 'https://elfocrypt.me/login',
  send_frd_req: 'https://elfocrypt.me/send_frd_req',
  send_frd_rej: 'https://elfocrypt.me/send_frd_rej',
  fetch_frd_req: 'https://elfocrypt.me/fetch_frd_req',
  fetch_frd_rej: 'https://elfocrypt.me/fetch_frd_rej',
  msg: 'https://elfocrypt.me/msg',
  g_msg: 'https://elfocrypt.me/g_msg',
  unread: 'https://elfocrypt.me/unread',
  check_gchat: 'https://elfocrypt.me/check_gchat',
  create_gchat: 'https://elfocrypt.me/create_gchat',
  del_gchat: 'https://elfocrypt.me/del_gchat',
  fetch_gchat_req: 'https://elfocrypt.me/fetch_gchat_req',
  fetch_gchat_rej: 'https://elfocrypt.me/fetch_gchat_rej',
  fetch_gchat_del: 'https://elfocrypt.me/fetch_gchat_del',
};
const encod = 'base64';
const alg = 'aes-256-cbc';
const hmac_alg = 'sha256';
const client_key = require(path.join(__dirname, 'package.json')).clientkey;
var db = levelup(path.join(__dirname, '.db'), {valueEncoding: 'binary'});

function gen_rsakey() {
  try {
    exec(`openssl genrsa -out ${privkey_path} 2048`, {stdio: [0, 'pipe']});
  } catch(er) {
    throw er;
  }
  return;
}

function compute_pubkey() {
  try {
    exec(`openssl rsa -in ${privkey_path} -out ${pubkey_path} -outform PEM -pubout`, {stdio: [0, 'pipe']});
  } catch(er) {
    throw er;
  }
  return;
}

function get_privkey() {
  try {
    return fs.readFileSync(privkey_path);
  } catch(er) {
    throw er;
  }
}

function get_pubkey() {
  try {
    return fs.readFileSync(pubkey_path);
  } catch(er) {
    throw er;
  }
}

function request_reg(url, dat, cb) {
  var server_res;
  request.post({url: url, headers: {authorization: client_key}, rejectUnauthorized: true, form: dat}, (er, res, body) => {
    if (er) return cb(er);
    try {
      server_res = JSON.parse(body);
    } catch(er) {
      return cb(er);
    }
    if (server_res.err) return cb(new Error(server_res.err));
    return cb(null, server_res);
  });
}

function encrypt_challenge(challenge, cb) {
  async.waterfall([
    function(callback) {
      db.get('privkey', (er, privkey) => {
        if (er) return callback(er);
        return callback(null, privkey);
      }); 
    },
    function(privkey, callback) {
      var enc_challenge, tag, hmac, hmac_key, enc_hmac_key;
      try {
        hmac_key = crypto.randomBytes(32);
        hmac = crypto.createHmac(hmac_alg, hmac_key);
        enc_challenge = crypto.privateEncrypt(privkey.toString(), Buffer.from(challenge, encod));
        enc_hmac_key = crypto.privateEncrypt(privkey.toString(), hmac_key);
        hmac.update(enc_challenge);
        tag = hmac.digest();
        return callback(null, `${enc_hmac_key.toString(encod)}&${tag.toString(encod)}&${enc_challenge.toString(encod)}`);
      } catch(er) {
        return callback(er);
      }
    }
  ], (er, enc_dat) => {
    if (er) return cb(er);
    return cb(null, enc_dat);
  });
}

function register(usern, cb) {
  async.series([
    function(callback) {
      request_reg(uri.init_reg, {usern: usern}, (er, res) => {
        if (er) return callback(er);
        if (res.info && res.info === 'ok') {
          return callback();
        } else {
          return callback(new Error('no proper response received from the server'));
        }
      });
    },
    function(callback) {
      try {
        rm.sync(tmp);
        rm.sync(cache);
        mkdirp.sync(tmp);
        mkdirp.sync(cache);
        gen_rsakey();
        compute_pubkey();
        return callback();
      } catch(er) {
        return callback(er);
      }
    },
    function(callback) {
      db.put('privkey', get_privkey(), (er) => {
        if (er) return callback(er);
        return callback();
      });
    },
    function(callback) {
      request_reg(uri.reg, {usern: usern, pub: get_pubkey().toString(encod)}, (er, res) => {
        if (er) return callback(er);
        if (res.info && res.info === 'ok') {
          return callback();
        } else {
          return callback(new Error('no proper response received from the server'));
        }
      });
    },
    function(callback) {
      try {
        rm.sync(tmp);
        mkdirp.sync(tmp);
        gen_rsakey();
        compute_pubkey();
        return callback();
      } catch(er) {
        return callback(er);
      } 
    },
    function(callback) {
      var frds = [];
      db.batch()
        .put('name', Buffer.from(usern))
        .put('priv', get_privkey())
        .put('pub', get_pubkey())
        .put('frds', Buffer.from(JSON.stringify(frds)))
        .write((er) => {
          if (er) return callback(er);
          rm.sync(tmp);
          console.log(`${usern} saved to local db successfully`);
          return callback();
        });
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function login(usern, cb) {
  async.waterfall([
    function(callback) {
      request_reg(uri.init_login, {usern: usern}, (er, res) => {
        if (er) return callback(er);
        if (res.challenge) {
          return callback(null, res.challenge);
        } else {
          return callback(new Error('no proper response received from the server'));
        }
      });
    },
    function(challenge, callback) {
      encrypt_challenge(challenge, (er, enc_challenge) => {
        if (er) return callback(er);
        return callback(null, enc_challenge);
      });
    },
    function(enc_challenge, callback) {
      request_reg(uri.login, {usern: usern, challenge_back: enc_challenge}, (er, res) => {
        if (er) return callback(er);
        if (res.token) {
          return callback(null, res.token);
        } else {
          return callback(new Error('no proper response received from the server'));
        }
      });
    },
    function(token, callback) {
      db.put('tok', Buffer.from(token), (er) => {
        if (er) return callback(er);
        return callback();
      });
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function req(opts, cb) {
  async.waterfall([
    function(callback) {
      db.get('tok', (er, tok) => {
        if (er) return callback(er);
        return callback(null, tok);
      });
    },
    function(tok, callback) {
      var server_res;
      opts = assign(opts, {headers: {authorization: Buffer.from(tok).toString().trim()}, rejectUnauthorized: true});
      request.post(opts, (er, res, body) => {
        if (er) return callback(er);
        try {
          server_res = JSON.parse(body);
        } catch(er) {
          return callback(er);
        }
        if (server_res.err) return callback(new Error(server_res.err));
        return callback(null, server_res);
      });
    }
  ], (er, server_res) => {
    if (er) return cb(er);
    return cb(null, server_res);
  });
}

function add_frd(frd_username, frd_key, cb) {
  var frds;
  db.get('frds', (er, buf) => {
    if (er) return cb(er);
    try {
      frds = JSON.parse(buf);
    } catch(er) {
      return cb(er);
    }
    frds.push({name: frd_username, key: frd_key});
    db.put('frds', Buffer.from(JSON.stringify(frds)), (er) => {
      if (er) return cb(er);
      return cb();
    });
  });
}

function get_frds(cb) {
  var frds;
  db.get('frds', (er, buf) => {
    if (er) return cb(er);
    try {
      frds = JSON.parse(buf);
    } catch(er) {
      return cb(er);
    }
    if (frds.length > 0) {
      return cb(null, frds);
    } else {
      return cb();
    }
  });
}

function get_frd_pubkey(frd_username, cb) {
  var frd_pubkey;
  get_frds((er, frds) => {
    if (er) return cb(er);
    frds.forEach((frd) => {
      if (frd.key && frd.name === frd_username) {
        frd_pubkey = frd.key;
      }
    });
    return cb(null, frd_pubkey);
  });
}

function verify_frd_req(frd, sec, cb) {
  async.waterfall([
    function(callback) {
      db.get('frd_req', (er, buf) => {
        var req;
        if (er) return callback(er);
        try {
          req = JSON.parse(buf);
        } catch(er) {
          return callback(er);
        }
        return callback(null, req);
      });
    },
    function(req, callback) {
      if (!req.sen || !req.pubtag) {
        return callback(new Error('invalid friend request'));
      } else {
        if (req.sen !== frd) {
          return callback(new Error('invalid friend request'));
        } else {
          return callback(null, req);
        }
      }
    },
    function(req, callback) {
      var chunk, frd_pubkey, hash, hmac, hmac_key, computed_tag, tag;
      try {
        hash = crypto.createHash('sha256');
        hash.update(sec);
        hmac_key = hash.digest();
        hmac = crypto.createHmac(hmac_alg, hmac_key);
        chunk = req.pubtag.split('&');
        tag = Buffer.from(chunk[0], encod);
        frd_pubkey = Buffer.from(chunk[1], encod);
        hmac.update(frd_pubkey);
        computed_tag = hmac.digest();
        if (!crypto.timingSafeEqual(computed_tag, tag)) {
          return callback(new Error('invalid signature'));
        } else {
          return callback(null, chunk[1]);
        }
      } catch(er) {
        return callback(er);
      }
    },
    function(frd_pubkey, callback) {
      add_frd(frd, frd_pubkey, (er) => {
        if (er) return callback(er);
        db.del('frd_req', (er) => {
          if (er) return callback(er);
          return callback();
        });
      });
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function send_frd_req(frd_un, sec, cb) {
  async.waterfall([
    function(callback) {
      db.get('name', (er, usern) => {
        if (er) return callback(er);
        return callback(null, usern);
      });
    },
    function(usern, callback) {
      db.get('pub', (er, pubkey) => {
        if (er) return callback(er);
        return callback(null, usern, pubkey);
      });
    },
    function(usern, pubkey, callback) {
      var hash, hmac, hmac_key, tag;
      try {
        hash = crypto.createHash('sha256');
        hash.update(sec);
        hmac_key = hash.digest();
        hmac = crypto.createHmac(hmac_alg, hmac_key);
        hmac.update(pubkey);
        tag = hmac.digest();
        return callback(null, `${tag.toString(encod)}&${pubkey.toString(encod)}`);
      } catch(er) {
        return callback(er);
      }
    },
    function(pubtag, callback) {
      req({url: uri.send_frd_req, form: {rec: frd_un, pubtag: pubtag}}, (er, res) => {
        if (er) return callback(er);
        if (res.info && res.info === 'ok') {
          return callback();
        } else {
          return callback(new Error('no proper response received from the server'));
        }
      });
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function send_frd_rej(rec, cb) {    
  req({url: uri.send_frd_rej, form: {rec: rec}}, (er, res) => {
    if (er) return cb(er);
    if (res.info && res.info === 'ok') {
      return cb();
    } else {
      return cb(new Error('no proper response received from the server'));
    }
  });
}

function fetch_frd_req(cb) {
  async.waterfall([
    function(callback) {
      req({url: uri.fetch_frd_req}, (er, res) => {
        if (er) return callback(er);
        return callback(null, res);
      });
    },
    function(res, callback) {
      if (res && res.frd_req && res.frd_req.sen && res.frd_req.pubtag) {
        db.put('frd_req', Buffer.from(JSON.stringify(res.frd_req)), (er) => {
          if (er) return callback(er);
          return callback(null, res.frd_req.sen);
        });
      } else {
        return callback();
      }
    }
  ], (er, sen) => {
    if (er) return cb(er);
    return cb(null, sen);
  });
}

function fetch_frd_rej(cb) {
  req({url: uri.fetch_frd_rej}, (er, res) => {
    if (er) return cb(er);
    if (res && res.frd_rej) {
      return cb(null, res.frd_rej);
    } else {
      return cb();
    }
  });
}

function encrypt(dat, rec, cb) { 
  async.waterfall([
    function(callback) {
      get_frd_pubkey(rec, (er, frdkey) => {
        if (er) return callback(er);
        return callback(null, frdkey);
      });
    },
    function(frdkey, callback) {
      var dat_key, hmac_key, iv, hmac, tag, keys_encrypted, cipher, cipher_dat;
      try {
        dat_key = crypto.randomBytes(32);
        hmac_key = crypto.randomBytes(32);
        iv = crypto.randomBytes(16);
        hmac = crypto.createHmac(hmac_alg, hmac_key);

        cipher = crypto.createCipheriv(alg, dat_key, iv);
        cipher_dat = Buffer.concat([cipher.update(dat), cipher.final()]);
        keys_encrypted = crypto.publicEncrypt(Buffer.from(frdkey, encod).toString(), Buffer.from(`${dat_key.toString(encod)}#${hmac_key.toString(encod)}`));

        hmac.update(keys_encrypted);
        hmac.update(cipher_dat);
        hmac.update(iv);
        tag = hmac.digest();
        return callback(null, `${keys_encrypted.toString(encod)}#${cipher_dat.toString(encod)}#${iv.toString(encod)}#${tag.toString(encod)}`);
      } catch(er) {
        return callback(er);
      }
    }
  ], (er, enc_dat) => {
    if (er) return cb(er);
    return cb(null, enc_dat);
  });
}

function decrypt(cipher_chunk, cb) {
  async.waterfall([
    function(callback) {
      db.get('priv', (er, privkey) => {
        if (er) return callback(er);
        return callback(null, privkey);
      });
    },
    function(privkey, callback) {
      var chunk, keys_encrypted, keys_dec, cdat, iv, tag, dat_key, hmac_key, hmac, computed_tag, decipher, decrypted;
      try {
        chunk = cipher_chunk.split('#');
        keys_encrypted = Buffer.from(chunk[0], encod);
        cdat = Buffer.from(chunk[1], encod);
        iv = Buffer.from(chunk[2], encod);
        tag = chunk[3];

        keys_dec = crypto.privateDecrypt(privkey.toString().trim(), keys_encrypted).toString().split('#');
        dat_key = Buffer.from(keys_dec[0], encod);
        hmac_key = Buffer.from(keys_dec[1], encod);

        hmac = crypto.createHmac(hmac_alg, hmac_key);
        hmac.update(keys_encrypted);
        hmac.update(cdat);
        hmac.update(iv);
        computed_tag = hmac.digest(encod);
        if (computed_tag !== tag) {
          return callback(new Error('invalid integrity tag'));
        } else {
          decipher = crypto.createDecipheriv(alg, dat_key, iv);
          decrypted = Buffer.concat([decipher.update(cdat), decipher.final()]);
          return callback(null, decrypted);
        }
      } catch(er) {
        return callback(er);
      }
    }
  ], (er, decrypted) => {
    if (er) return cb(er);
    return cb(null, decrypted) ;
  });
}

function send_msg(msg, receiver, cb) {
  async.waterfall([
    function(callback) {        
      encrypt(Buffer.from(msg), receiver, (er, enc_msg) => {
        if (er) return callback(er);
        return callback(null, enc_msg);
      });
    },
    function(enc_msg, callback) {
      db.get('name', (er, usern) => {
        if (er) return callback(er);
        return callback(null, enc_msg, usern);
      });
    },
    function(enc_msg, usern, callback) {
      var d = new Date();
      req({url: uri.msg, form: {rec: receiver, msg: enc_msg, time: `${d.getFullYear()}/${d.getMonth()}/${d.getDate()} ${d.getHours()}:${d.getMinutes()}`}}, (er, res) => {
        if (er) return callback(er);
        if (res.info && res.info === 'ok') {
          return callback(null, {sen: usern.toString(), msg: msg, time: `${d.getHours()}:${d.getMinutes()}`});
        } else {
          return callback(new Error('no proper response received from the server'));
        }
      });
    }
  ], (er, msg) => {
    if (er) return cb(er);
    return cb(null, msg);
  });
}

function decrypt_unread(unread_msgs, cb) {
  var msgs = [];
  async.each(unread_msgs, (unread, callback) => {
    if (!unread.sen || !unread.msg || !unread.time) {
      return callback(new Error('invalid message token'));
    } else {    
      decrypt(Buffer.from(unread.msg, encod).toString(), (er, decrypted_msg) => {
        if (er) return callback(er);
        msgs.push({sen: unread.sen, msg: decrypted_msg.toString(), time: unread.time});
        return callback();
      }); 
    }
  }, (er) => {
    if (er) return cb(er);
    return cb(null, msgs);
  });
}

function fetch_unread(cb) {
  async.waterfall([
    function(callback) {
      req({url: uri.unread}, (er, res) => {
        if (er) return callback(er);
        return callback(null, res);
      });
    },
    function(res, callback) {
      if (res.unread && res.unread.length > 0) {
        decrypt_unread(res.unread, (er, msgs) => {
          if (er) return callback(er);
          return callback(null, msgs);
        });
      } else {
        return callback();
      }
    }
  ], (er, msgs) => {
    if (er) return cb(er);
    return cb(null, msgs);
  });
}

function is_reg_user(cb) {
  db.get('name', (er) => {
    if (er) return cb(false);
    return cb(true);
  });
}

function logout(cb) {
  async.series([
    function(callback) {
      req({url: uri.logout}, (er) => {
        if (er) return callback(er);
        return callback();
      });
    },
    function(callback) {
      db.del('tok', () => {
        return callback();
      });
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

module.exports = {
  register: register,
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
  is_reg_user: is_reg_user,
  logout: logout
};
