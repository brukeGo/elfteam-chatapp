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

/*
 * create json web token for a given username,
 * sign it with server's jwtkey and return
 * the generated token.
 */

function gen_jwt(username) {
  // by default, expire the token after 60 mins (time is in secs)
  const expire_def = Math.floor(new Date().getTime()/1000) + 60*60;
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
  // make sure username is unique
  db.get(username, (err) => {
    if (err) {
      // username is unique, save it to db
      db.put(username, {
        pw: passw,
        unread: [],
        frd_req: {},
        frd_rej: ''
      }, (err) => {
        if (err) {
          log(err.message);
          return cb(err.message);
        }
        log(`${username} saved to db successfully`);
        return cb();
      });
    } else {
      return cb(`'${username}' already taken. Please choose another one`);
    }
  });
}

/**
 * authenticate a returning user (login api route)
 */

function login(username, passw, cb) {
  db.get(username, (err, user) => {
    var tok;
    if (err) {
      return cb(err.message);
    }
    if (user.pw === passw) {  
      tok = gen_jwt(username);
      user = Object.assign(user, {token: tok});
      db.put(username, user, (err) => {
        if (err) {
          log(err);
          return cb(err.message);
        }
        return cb(null, tok);
      });
    } else {
      return cb('invalid password');
    }
  });
}

function send_frd_req(tok, sen, rec, frd_tok, cb) {
  validate_token(tok, sen, (err, valid) => {
    if (err) {
      return cb(err);
    }
    if (valid) {
      db.get(rec, (err, user) => {
        if (err) {
          return cb(err.message);
        }
        user.frd_req = {sen: sen, tok: frd_tok};
        db.put(rec, user, (err) => {
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

function get_frd_req(tok, un, cb) {
  validate_token(tok, un, (err, valid) => {
    if (err) {
      return cb(err);
    }
    if (valid) {
      db.get(un, (err, user) => {
        if (err) {
          return cb(err.message);
        }
        return cb(null, user.frd_req);
      });
    } else {
      return cb('invalid token');
    }
  });
}

function get_frd_rej(tok, un, cb) {
  validate_token(tok, un, (err, valid) => {
    if (err) {
      return cb(err);
    }
    if (valid) {
      db.get(un, (err, user) => {
        if (err) {
          return cb(err.message);
        }
        return cb(null, user.frd_rej);
      });
    } else {
      return cb('invalid token');
    }
  });
}

function rej_frd_req(tok, un, frd, cb) {
  validate_token(tok, un, (err, valid) => {
    if (err) {
      return cb(err);
    }
    if (valid) {
      db.get(frd, (err, user) => {
        if (err) {
          return cb(err.message);
        }
        user.frd_rej = un;
        db.put(frd, user, (err) => {   
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

function clear_frd_req(token, username, cb) {
  validate_token(token, username, (err, valid) => {
    if (err) {
      return cb(err);
    }
    if (valid) {
      db.get(username, (err, user) => {
        if (err) {
          return cb(err.message);
        }
        user.frd_req = {};  
        db.put(username, user, (err) => {
          if (err) {
            log(err);
            return cb(err);
          }
          return cb();
        });
      });
    } else {
      return cb('username/token not valid');
    }
  });
}

function clear_frd_rej(token, username, cb) {
  validate_token(token, username, (err, valid) => {
    if (err) {
      return cb(err);
    }
    if (valid) {
      db.get(username, (err, user) => {
        if (err) {
          return cb(err.message);
        }
        user.frd_rej = '';
        db.put(username, user, (err) => {
          if (err) {
            log(err);
            return cb(err);
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
 * handle getting a message from a client to send it to other client
 */

function handle_msg(tok, sender, receiver, msg_tok, cb) {
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
        user.unread.push({sen: sender, tok: msg_tok, time: `${d.getHours()}:${d.getMinutes()}`});
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
  login: login,
  send_frd_req: send_frd_req,
  get_frd_req: get_frd_req,
  get_frd_rej: get_frd_rej,
  rej_frd_req: rej_frd_req,
  clear_frd_req: clear_frd_req,
  clear_frd_rej: clear_frd_rej,
  handle_msg: handle_msg,
  get_unread: get_unread,
  clear_unread: clear_unread,
  logout: logout
};
