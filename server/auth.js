'use strict';

//const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const levelup = require('levelup');
const crypto = require('crypto');
const async = require('async');
const encod = 'base64';

// for testing and dev, load keys from package.json
const jwtkey = require('./package.json').jwt_key;
const hmac_key = require('./package.json').hmac_key;
const client_tag = require('./package.json').client_tag;

var db = levelup(path.join(__dirname, '.db'), {valueEncoding: 'json'});

function verify_client_tag(tag, cb) {  
  const hmac = crypto.createHmac('sha256', hmackey);
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

function init_register(usern, cb) {  
  db.get(usern, (er) => {
    if (!er) {
      return cb(new Error(`'${usern}' already taken. Please choose another one.`));
    } else {
      return cb();
    }
  });
}

function register(usern, user_pubkey, cb) {
  async.waterfall([
    function(callback) {
      init_register(usern, (er) => {
        if (er) return callback(er);
        return callback();
      });
    },
    function(callback) {  
      db.put(usern, {pub: user_pubkey, unread: []}, (er) => {
        if (er) return callback(er);
        console.log(`${usern} saved to db successfully`);
        return callback();
      });
    }
  ], (er) => {
    if (er) return cb(er);
    return cb();
  });
}

function init_login(usern, cb) {
  async.waterfall([
    function(callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(new Error(`'${usern}' not found`));
        return callback(null, user);
      });
    },
    function(user, callback) {
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

function login(usern, challenge_back, cb) { 
  async.waterfall([
    function(callback) {
      db.get(usern, (er, user) => {
        if (er) return callback(new Error(`'${usern}' not found`));
        return callback(null, user);
      });
    },
    function(user, callback) {
      var chunk, dec_challenge, hmac, hmac_key, tag, computed_tag, enc_challenge;
      try {
        chunk = challenge_back.split('&');
        hmac_key = crypto.publicDecrypt(Buffer.from(user.pub, encod).toString(), Buffer.from(chunk[0], encod));
        hmac = crypto.createHmac(hmac_alg, hmac_key);
        tag = Buffer.from(chunk[1], encod);
        enc_challenge = Buffer.from(chunk[2], encod);
        hmac.update(enc_challenge);
        computed_tag = hmac.digest();
        if (!crypto.timingSafeEqual(computed_tag, tag)) {
          return callback(new Error(`'${usern}' not verified. Invalid tag.`));
        } else {
          dec_challenge = crypto.publicDecrypt(Buffer.from(user.pub, encod).toString(), enc_challenge);
          if (!crypto.timingSafeEqual(dec_challenge, Buffer.from(user.challenge, encod))) {
            return callback(new Error(`'${usern}' not verified. Invalid challenge handshake.`));
          } else {
            user.challenge = null;
            db.put(usern, user, (er) => {
              if (er) return callback(er);
              return callback();
            });
          }
        }
      } catch(er) {
        return callback(er);
      }
    },
    function(callback) {
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

function send_frd_req(sender, rec, pubtag, cb) {
  async.waterfall([
    function(callback) {
      db.get(rec, (er, user) => {
        if (er) return callback(er);
        user.frd_req = {sen: sender, pubtag: pubtag};
        db.put(rec, user, (er) => {
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

function send_frd_rej(usern, rec, cb) {
  async.waterfall([
    function(callback) {
      db.get(rec, (er, user) => {
        if (er) return callback(er);
        user.frd_rej = usern;
        db.put(rec, user, (er) => {   
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
        return callback(null, user, user.frd_req);
      });
    },
    function(user, frd_req, callback) {
      user.frd_req = {};
      db.put(usern, user, (er) => {
        if (er) return callback(er);
        return callback(null, frd_req);
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
        return callback(null, user, user.frd_rej);
      });
    },
    function(user, frd_rej, callback) {
      user.frd_rej = '';  
      db.put(usern, user, (er) => {
        if (er) return callback(er);
        return callback(null, frd_rej);
      });
    }
  ], (er, frd_rej) => {
    if (er) return cb(er);
    return cb(null, frd_rej);
  });
}

function handle_msg(sender, dat, cb) {
  async.waterfall([
    function(callback) {
      db.get(dat.rec, (er, user) => {
        if (er) return callback(er);
        user.unread.push({sen: sender, msg: dat.msg, files: dat.files, time: dat.time});
        db.put(dat.rec, user, (er) => {
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
        return callback(null, user, user.unread);
      });
    },
    function(user, unread_msgs, callback) {
      user.unread.splice(0, user.unread.length);
      db.put(usern, user, (er) => {
        if (er) return callback(er);
        return callback(null, unread_msgs);
      });
    }
  ], (er, unread_msgs) => {
    if (er) return cb(er);
    return cb(null, unread_msgs);
  });
}

function logout(decod, cb) { 
  decod.val = false;
  return cb();
}

module.exports = {
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
