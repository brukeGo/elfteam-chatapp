'use strict';

const path = require('path');
const jwt = require('jsonwebtoken');
const levelup = require('levelup');
const crypto = require('crypto');
const async = require('async');
const encod = 'base64';
//const jwtkey = process.env.JWT_KEY;
//const hmac_key = process.env.HMAC_KEY;
//const pw_key = process.env.PW_KEY;
//const client_tag = process.env.CLIENT_TAG;

// these keys are used for testing and development
const jwtkey = require('./package.json').jwt_key;
const hmac_key = require('./package.json').hmac_key;
const pw_key = require('./package.json').pw_key;
const client_tag = require('./package.json').client_tag;
var db = levelup(path.join(__dirname, '.db'), {valueEncoding: 'json'});

function log(info) {
  console.log('elfocrypt-server: ', info);
}

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

function create_tok(username) { 
  return jwt.sign({
    iat: new Date().getTime(),
    exp: Math.floor(new Date().getTime()/1000) + 60*60,
    nam: username
  }, jwtkey, {algorithm: 'HS256'});
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
      if (decod && decod.nam) {
        db.get(decod.nam, (er, user) => {
          if (er) return callback(er);
          if (user.token && user.token === token) {
            return callback(null, decod);
          } else {
            return callback(new Error('invalid user token'));
          }
        });
      } else {
        return callback(new Error('invalid request token'));
      }
    }
  ], (er, decod) => {
    if (er) return cb(er);
    return cb(null, decod);
  });
}

function encrypt_pw(pw, cb) {
  var cipher, enc_pw, tag;
  const enc_alg = 'aes-256-gcm';
  const iv = crypto.randomBytes(16);
  try {
    cipher = crypto.createCipheriv(enc_alg, Buffer.from(pw_key, encod), iv);
    enc_pw = cipher.update(pw, encod, encod);
    enc_pw += cipher.final(encod);
    tag = cipher.getAuthTag();
    return cb(null, `${iv.toString(encod)}&${enc_pw}&${tag.toString(encod)}`);
  } catch(er) {
    return cb(er);
  }
}

function decrypt_pw(enc_dat, cb) {
  var chunk, iv, decipher,enc_pw, dec_pw, tag;
  const enc_alg = 'aes-256-gcm';
  try {
    chunk = enc_dat.split('&');
    iv = Buffer.from(chunk[0], encod);
    enc_pw = chunk[1];
    tag = Buffer.from(chunk[2], encod);
    decipher = crypto.createDecipheriv(enc_alg, Buffer.from(pw_key, encod), iv);
    decipher.setAuthTag(tag);
    dec_pw = decipher.update(enc_pw, encod, encod);
    dec_pw += decipher.final(encod);
    return cb(null, dec_pw);
  } catch(er) {
    return cb(er);
  }
}

function register(usern, pasw, cb) {
  db.get(usern, (er) => {    
    if (er) {    
      encrypt_pw(pasw, (er, enc_pw) => {
        if (er) return cb(er);
        db.put(usern, {
          pw: enc_pw,
          unread: [],
        }, (er) => {
          if (er) return cb(er);
          log(`${usern} saved to db successfully`);
          return cb();
        });
      });
    } else {
      return cb(new Error(`'${usern}' already taken. Please choose another one`));
    }
  });
}

function login(usern, pasw, cb) { 
  async.waterfall([
    function(callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(er);
        return callback(null, user);
      });
    },
    function(user, callback) {
      decrypt_pw(user.pw, (er, dec_pw) => {
        if (er) return callback(er);
        return callback(null, user, dec_pw);
      });
    },
    function(user, dec_pw, callback) {
      var tok;
      if (dec_pw !== pasw) {
        return callback(new Error('invalid password'));
      } else {
        tok = create_tok(usern);
        user = Object.assign(user, {token: tok});
        db.put(usern, user, (er) => {
          if (er) return callback(er);
          return callback(null, tok);
        });
      }
    }
  ], (er, tok) => {
    if (er) return cb(er);
    return cb(null, tok);
  });
}

function send_frd_req(sen, rec, frd_tok, cb) {
  db.get(rec, (er, user) => {
    if (er) return cb(er);
    user.frd_req = {sen: sen, tok: frd_tok};
    db.put(rec, user, (er) => {
      if (er) return cb(er);
      return cb();
    });
  });
}

function send_frd_rej(usern, frd, cb) {
  db.get(frd, (er, user) => {
    if (er) return cb(er);
    user.frd_rej = usern;
    db.put(frd, user, (er) => {   
      if (er) return cb(er);
      return cb();
    });
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

function handle_msg(sender, receiver, msg_tok, time, cb) {
  db.get(receiver, (er, user) => {
    if (er) return cb(er);
    user.unread.push({sen: sender, tok: msg_tok, time: time});
    db.put(receiver, user, (er) => {   
      if (er) return cb(er);
      return cb();
    });
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

function logout(usern, cb) {
  db.get(usern, (er, user) => {
    if (er) return cb(er);
    user = Object.assign(user, {token: null});
    db.put(usern, user, (er) => {  
      if (er) return cb(er);
      return cb();
    });
  });
}

module.exports = {
  verify_client_tag: verify_client_tag,
  verify_tok: verify_tok,
  register: register,
  login: login,
  send_frd_req: send_frd_req,
  send_frd_rej: send_frd_rej,
  fetch_frd_req: fetch_frd_req,
  fetch_frd_rej: fetch_frd_rej,
  handle_msg: handle_msg,
  fetch_unread: fetch_unread,
  logout: logout
};
