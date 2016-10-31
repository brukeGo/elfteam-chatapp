'use strict';

//const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const levelup = require('levelup');
const crypto = require('crypto');
const async = require('async');
const encod = 'base64';

// for testing and dev, load keys from package.json
// for production, these keys will be loaded from process.env
const prox_key = require('./package.json').prox_key;
const jwtkey = require('./package.json').jwt_key;
const hmac_key = require('./package.json').hmac_key;
const client_tag = require('./package.json').client_tag;
const reg_key = require('./package.json').reg_key;

var db = levelup(path.join(__dirname, '.db'), {valueEncoding: 'json'});

function verify_client_tag(tag, cb) {  
  const hmac = crypto.createHmac('sha256', hmac_key);
  var computed_tag;
  if (!tag) {
    return cb(new Error('invalid client tag'));
  } else {
    hmac.update(tag, encod);
    computed_tag = hmac.digest(encod);
    if (!crypto.timingSafeEqual(Buffer.from(computed_tag, encod), Buffer.from(client_tag, encod))) {
      return cb(new Error('invalid client tag'));
    } else {
      return cb();
    }
  }
}

function create_tok(username, cb) { 
  jwt.sign({
    iat: new Date().getTime(),
    exp: Math.floor(new Date().getTime()/1000)+(60*30),
    iss: 'elfocrypt-server',
    sub: username,
    val: true
  }, jwtkey, {algorithm: 'HS256'}, (er, tok) => {
    if (er) return cb(er);
    return cb(null, tok);
  });
}

function verify_tok(token, cb) {
  async.waterfall([
    function(callback) {
      jwt.verify(token, jwtkey, {algorithms: ['HS256']}, (er, decod) => {
        if (er) return callback(er);
        return callback(null, decod);
      });
    },
    function(decod, callback) {
      if (decod && decod.iss && decod.iss === 'elfocrypt-server' && decod.sub && decod.val) {
        db.get(decod.sub, (er) => {
          if (er) return callback(er);
          return callback(null, decod);
        });
      } else {
        return callback(new Error('invalid token'));
      }
    }
  ], (er, decod) => {
    if (er) return cb(er);
    return cb(null, decod);
  });
}

function verify_dat_tok(usern, tok, cb) {
  async.waterfall([
    function(callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(er);
        return callback(null, user);
      });
    },
    function(user, callback) {
      jwt.verify(tok, Buffer.from(user.appkey, encod), {algorithms: ['RS256']}, (er, decod) => {
        if (er) return callback(er);
        if (decod.iss === usern && decod.sub === 'elfocrypt-server') {
          return callback(null, decod);
        } else {
          return callback(new Error('invalid data token'));
        }
      });
    }
  ], (er, decod) => {
    if (er) return cb(er);
    return cb(null, decod);
  });
}

function verify_reg_tok(tok, cb) {    
  jwt.verify(tok, Buffer.from(reg_key, encod), {algorithms: ['RS256']}, (er, decod) => {
    if (er) return cb(er);
    if (decod && decod.iss === 'elfocrypt.me' && decod.sub === 'elfocrypt-server') {
      return cb(null, decod);
    } else {
      return cb(new Error('invalid register token'));
    }
  });
}

function init_register(tok, cb) {
  async.waterfall([
    function(callback) {
      verify_reg_tok(tok, (er, decod) => {
        if (er) return callback(er);
        return callback(null, decod);
      });
    },
    function(decod, callback) {
      db.get(decod.un, (er) => {
        if (!er) {
          return callback(new Error(`'${decod.un}' already taken. Please choose another one`));
        } else {
          return callback();
        }
      });
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function register(tok, cb) {
  async.waterfall([
    function(callback) {
      verify_reg_tok(tok, (er, decod) => {
        if (er) return callback(er);
        return callback(null, decod);
      });
    },
    function(decod, callback) {
      if (decod.un && decod.pub) {
        db.put(decod.un, {pub: decod.pub, unread: []}, (er) => {
          if (er) return callback(er);
          console.log(`${decod.un} saved to db successfully`);
          return callback();
        });
      } else {
        return callback(new Error('invalid register token'));
      }
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function init_login(tok, cb) {
  async.waterfall([
    function(callback) {
      verify_reg_tok(tok, (er, decod) => {
        if (er) return callback(er);
        return callback(null, decod);
      });
    },
    function(decod, callback) {
      db.get(decod.un, (er, user) => {
        if (er) return callback(new Error(`'${decod.un}' not found`));
        return callback(null, decod.un, user);
      });
    },
    function(usern, user, callback) {
      var challenge = crypto.randomBytes(32).toString(encod);
      user.challenge = challenge;
      db.put(usern, user, (er) => {
        if (er) return callback(er);
        return callback(null, challenge);
      });
    }
  ], (er, challenge) => {
    if (er) return cb(er);
    return cb(null, challenge);
  });
}

function login(tok, cb) { 
  async.waterfall([
    function(callback) {
      verify_reg_tok(tok, (er, decod) => {
        if (er) return callback(er);
        return callback(null, decod);
      });
    },
    function(decod, callback) {
      db.get(decod.un, (er, user) => {
        if (er) return callback(new Error(`'${decod.un}' not found`));
        return callback(null, decod, user);
      });
    },
    function(decod, user, callback) {
      var dec_challenge;
      try {
        dec_challenge = crypto.publicDecrypt(Buffer.from(user.pub, encod).toString(), Buffer.from(decod.cha, encod));
      } catch(er) {
        return callback(er);
      }
      if (!crypto.timingSafeEqual(Buffer.from(user.challenge, encod), dec_challenge)) {
        return callback(new Error(`'${decod.un}' not verified`));
      } else {
        user.challenge = null;
        db.put(decod.un, user, (er) => {
          if (er) return callback(er);
          return callback(null, decod.un);
        });
      }
    },
    function(usern, callback) {
      create_tok(usern, (er, tok) => {
        if (er) return callback(er);
        return callback(null, tok);
      });
    }
  ], (er, tok) => {
    if (er) return cb(er);
    return cb(null, tok);
  });
}

function send_frd_req(sender, tok, cb) {
  async.waterfall([
    function(callback) {
      verify_dat_tok(sender, tok, (er, decod) => {
        if (er) return callback(er);
        return callback(null, decod);
      });
    },
    function(decod, callback) {
      db.get(decod.rec, (er, user) => {
        if (er) return callback(er);
        user.frd_req = {sen: decod.iss, tok: decod.tok};
        db.put(decod.rec, user, (er) => {
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

function send_frd_rej(usern, tok, cb) { 
  async.waterfall([
    function(callback) {
      verify_dat_tok(usern, tok, (er, decod) => {
        if (er) return callback(er);
        return callback(null, decod);
      });
    },
    function(decod, callback) {
      db.get(decod.frd, (er, user) => {
        if (er) return callback(er);
        user.frd_rej = decod.iss;
        db.put(decod.frd, user, (er) => {   
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

function fetch_frd_req(usern, cb) {
  async.waterfall([
    function(callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(er);
        return callback(null, user.frd_req);
      });
    },
    function(frd_req, callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(er);
        user.frd_req = {};  
        db.put(usern, user, (er) => {
          if (er) return callback(er);
          return callback(null, frd_req);
        });
      });
    }
  ], (er, frd_req) => {
    if (er) return cb(er);
    return cb(null, frd_req);
  });
}

function fetch_frd_rej(usern, cb) {
  async.waterfall([
    function(callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(er);
        return callback(null, user.frd_rej);
      });
    },
    function(frd_rej, callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(er);
        user.frd_rej = '';  
        db.put(usern, user, (er) => {
          if (er) return callback(er);
          return callback(null, frd_rej);
        });
      });
    }
  ], (er, frd_rej) => {
    if (er) return cb(er);
    return cb(null, frd_rej);
  });
}

function handle_msg(sender, tok, cb) {
  async.waterfall([
    function(callback) {
      verify_dat_tok(sender, tok, (er, decod) => {
        if (er) return callback(er);
        return callback(null, decod);
      });
    },
    function(decod, callback) {
      db.get(decod.rec, (er, user) => {
        if (er) return callback(er);
        user.unread.push({sen: decod.iss, tok: decod.tok, time: decod.time});
        db.put(decod.rec, user, (er) => {   
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

function fetch_unread(usern, cb) {
  async.waterfall([
    function(callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(er);
        return callback(null, user.unread);
      });
    },
    function(unread, callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(er);
        user.unread.splice(0, user.unread.length);
        db.put(usern, user, (er) => {
          if (er) return callback(er);
          return callback(null, unread);
        });
      });
    }
  ], (er, unread) => {
    if (er) return cb(er);
    return cb(null, unread);
  });
}

function logout(decod, cb) { 
  decod.val = false;
  return cb();
}

module.exports = {
  verify_prox_tok: verify_prox_tok,
  verify_client_tag: verify_client_tag,
  verify_tok: verify_tok,
  init_register: init_register,
  register: register,
  init_login: init_login,
  login: login,
  send_frd_req: send_frd_req,
  send_frd_rej: send_frd_rej,
  fetch_frd_req: fetch_frd_req,
  fetch_frd_rej: fetch_frd_rej,
  handle_msg: handle_msg,
  fetch_unread: fetch_unread,
  logout: logout
};
