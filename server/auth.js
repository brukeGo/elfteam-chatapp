/**
 * handle authentication and database operations
 */

'use strict';

const path = require('path');
const jwt = require('jsonwebtoken');
const levelup = require('levelup');
const crypto = require('crypto');
const encoding = 'base64';
const jwtkey = crypto.randomBytes(256).toString(encoding);

var db = levelup(path.join(__dirname, 'db'), {valueEncoding: 'json'});

function log(info) {
  console.log(`elfocrypt-server: ${info}`);
}

/**
 * search for a given username and return public key
 * and its signature if found, otherwise return not found err
 */

function search(username, cb) {
  db.get(username, (err, user) => {
    if (err) {
      return cb(err.message);
    }
    if (user.pubkey && user.sig) {
      return cb(null, {
        pubkey: user.pubkey,
        sig: user.sig
      });
    } else {
      return cb(`'${username} not found.'`);
    }
  });
}

/*
 * create json web token for a given username,
 * sign it with server's jwtkey and return
 * the generated token.
 */

function gen_jwt(username) {
  // by default, expire the token after 24 hours (time is in secs)
  const expire_def = Math.floor(new Date().getTime()/1000) + 60*1440;
  return jwt.sign({
    nam: username,
    iat: new Date().getTime(),
    exp: expire_def
  }, jwtkey);
}

/**
 * verify a given json web token and return
 * the payload if no error found; otherwise
 * return false
 */

function verify_jwt(token) {
  var decoded = false;
  try {
    decoded = jwt.verify(token, jwtkey, {algorithms: ['HS256']});
  } catch(err) {
    decoded = false; // still false
  }
  return decoded;
}

/**
 * validate json web token for a given username
 */

function validate_token(token, username, cb) {
  var decoded;
  decoded = verify_jwt(token);
  if (!decoded || !decoded.nam) {    
    return cb('token not valid', false);
  } else {
    db.get(username, (err, user) => {
      if (err) {
        return cb(err.message);
      }
      // check if user's stored token matches the sent one from client
      // and also username matches token's payload name
      return cb(null, username === decoded.nam && user.token === token);
    });
  }
}

/**
 * register new user, generate a fresh json web token
 * for the current session, save it to db and return
 * the token to send to the client for subsequent
 * authenticated requests
 */

function register(username, passw, cb) {
  var tok;
  // make sure username is unique
  db.get(username, (err) => {
    if (err) {
      // username is unique, generate jwt for register
      // authentication and save it to db
      tok = gen_jwt(username);
      db.put(username, {
        password: passw,
        token: tok,
        unread: []
      }, (err) => {
        if (err) {
          log(err.message);
          return cb(err.message, null);
        }
        log(`${username} saved to db successfully`);
        return cb(null, tok);
      });
    } else {
      return cb(`'${username}' already taken. Please choose another one`, null);
    }
  });
}

/**
 * validate register jwt and store user's public key in db
 */

function save_pubkey(token, username, pubkey, sig, cb) {
  // validate the token received from client
  validate_token(token, username, (err, valid) => {
    if (err) {
      return cb(err);
    }
    // if jwt is valid, delete register token (for login we generate new token),
    // then save user's public key and its signature to db
    if (valid) {
      db.get(username, (err, user) => {
        if (err) {
          return cb(err.message);
        }
        user = Object.assign(user, {token: null, pubkey: pubkey, sig: sig});
        db.put(username, user, (err) => {
          if (err) {
            return cb(err.message);
          }
          return cb();
        });
      });
    } else {
      return cb('username/token not valid');
    }
  });
}

/**
 * authenticate a returning user (login api route)
 */

function login(username, passw, passw_sig, cb) {
  const veri = crypto.createVerify('RSA-SHA256');
  var tok, valid;
  db.get(username, (err, user) => {
    if (err) {
      return cb(err.message);
    }
    if (user.password === passw && user.pubkey) {
      try {
        veri.write(passw);
        veri.end();
        // verify password and its signature, if successful
        // generate jwt, save it to db and send it to client
        valid = veri.verify(Buffer.from(user.pubkey, encoding).toString(), passw_sig, encoding);
      } catch(err) {
        return cb(err.message, null);
      }
      if (valid) {
        tok = gen_jwt(username);
        user = Object.assign(user, {token: tok});
        db.put(username, user, (err) => {
          if (err) {
            log(err);
            return cb(err.message, null);
          }
          return cb(null, tok);
        });
      } else {
        return cb('error: password/signature not valid', null);
      }
    } else {  
      return cb('err: password/signature not valid', null);
    }
  });
}

/**
 * handle getting a message from a client to send it to other client
 */

function handle_msg(tok, sender, receiver, msg, cb) {
  var d;
  validate_token(tok, sender, (err, valid) => {
    if (err) {
      return cb(err);
    }
    if (valid) {
      db.get(receiver, (err, user) => {
        if (err) {
          return cb(err.message);
        }
        d = new Date(); 
        user.unread.push({sender: sender, msg: msg, time: `${d.getHours()}:${d.getMinutes()}`});
        db.put(receiver, user, (err) => {   
          if (err) {
            log(err);
            return cb(err.message);
          }
          return cb();
        });
      });
    } else {
      return cb('username/token not valid');
    }
  });
}

/**
 * check client's unread messages
 */

function get_unread(token, username, cb) {
  validate_token(token, username, (err, valid) => {
    if (err) {
      return cb(err, null);
    }
    if (valid) {
      db.get(username, (err, user) => {
        if (err) {
          return cb(err.message, null);
        }
        if (user.unread && user.unread.length > 0) {
          return cb(null, user.unread);
        } else {
          return cb();
        }
      });
    } else {
      return cb('username/token not valid');
    }
  });
}

/**
 * clear client's list of unread messages
 */

function clear_unread(token, username, cb) {
  validate_token(token, username, (err, valid) => {
    if (err) {
      return cb(err);
    }
    if (valid) {
      db.get(username, (err, user) => {
        if (err) {
          return cb(err.message);
        }
        if (user.unread && user.unread.length > 0) {
          user.unread.splice(0, user.unread.length);
          db.put(username, user, (err) => {
            if (err) {
              log(err);
              return cb(err);
            }
            return cb();
          });
        } else {
          return cb();
        }
      });
    } else {
      return cb('username/token not valid');
    }
  });
}

/**
 * log out and remove user's token from db
 */

function logout(token, username, cb) {
  validate_token(token, username, (err, valid) => {
    if (err) {
      return cb(err);
    }
    if (valid) {
      db.get(username, (err, user) => {
        if (err) {
          return cb(err.message);
        }
        user = Object.assign(user, {token: null});
        db.put(username, user, (err) => {  
          if (err) {
            log(err);
            return cb(err.message);
          }
          return cb();
        });
      });
    } else {
      return cb('username/token not valid');
    }
  });
}

module.exports = {
  jwtkey: jwtkey,
  register: register,
  save_pubkey: save_pubkey,
  login: login,
  search: search,
  handle_msg: handle_msg,
  get_unread: get_unread,
  clear_unread: clear_unread,
  logout: logout
};
