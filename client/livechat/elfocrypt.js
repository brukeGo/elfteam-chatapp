#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const levelup = require('levelup');
const read = require('read');
const readline = require('readline');
const io = require('socket.io-client');
const jwt = require('jsonwebtoken');
const col = require('chalk');
const exec = require('child_process').execSync;
const rm = require('rimraf');
const mkdirp = require('mkdirp');
const tmp = path.join(__dirname, 'tmp');
const privkey_path = path.join(tmp, 'priv.pem');
const pubkey_path = path.join(tmp, 'pub.pem');
const encoding = 'base64';
const alg = 'aes-256-cbc';
const hmac_alg = 'sha256';
const arg = process.argv[2];
const frd = process.argv[3];
const sock = io.connect('https://localhost.daplie.com:3761/live/auth');
var db = levelup(path.resolve('..', 'db'));

function exit(code) {
  sock.disconnect();
  process.exit(code);
}

function er(error) {
  console.error(col.italic.red(`\nerror: ${error}`));
  exit(1);
}

function log(info) {
  console.log(`${info}`);
}

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

function gen_sign(data, cb) {
  var sign;
  db.get('priv', (err, privkey) => {
    if (err) {
      return cb(err.message);
    }
    sign = crypto.createSign('RSA-SHA256');
    sign.write(data);
    sign.end();
    return cb(null, sign.sign(privkey, encoding));
  });
}

function get_frds(cb) {
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
    if (frds.ls.length > 0) {
      return cb(null, frds.ls);
    } else {
      return cb();
    }
  });
}

function get_frd_pubkey(frd_username, cb) {
  var frd_pubkey;
  get_frds((err, frds) => {
    if (err) {
      return cb(err);
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
 * encrypt a private message with receiver's public key
 */

function encrypt(msg, receiver, cb) {
  var hmac_key, iv, hmac, tag, key_encrypted, cipher, cipher_text;

  get_frd_pubkey(receiver, (err, rec_pubkey) => {
    if (err) {
      return cb(err);
    }
    if (rec_pubkey) {
      db.get('dh_sec', (err, dh_sec) => {
        if (err) {
          return cb(err.message);
        }
        try {
          hmac_key = crypto.randomBytes(32);
          iv = crypto.randomBytes(16); // initialization vector 128 bits
          hmac = crypto.createHmac(hmac_alg, hmac_key);

          // encrypt the message with dh secret and random iv
          cipher = crypto.createCipheriv(alg, Buffer.from(dh_sec, encoding), iv);
          cipher_text = cipher.update(msg, 'utf8', encoding);
          cipher_text += cipher.final(encoding);

          hmac.update(cipher_text);
          hmac.update(iv.toString(encoding));
          tag = hmac.digest(encoding);

          // encrypt the hmac key with receiver's public key
          key_encrypted = crypto.publicEncrypt(rec_pubkey, Buffer.from(hmac_key));

          // concatenate key, cipher text, iv and hmac digest
          return cb(null, `${key_encrypted.toString(encoding)}#${cipher_text}#${iv.toString(encoding)}#${tag}`);
        } catch(err) {
          return cb(err.message);
        } 

      });
    } else {
      return cb('friend\'s public key not found');
    }
  });
}

/**
 * decrypt a private message with client's private key
 */
function decrypt(cipher_text, cb) {
  var chunk, key_encrypted, ct, iv, tag,hmac_key, 
    hmac, computed_tag, decipher, decrypted;

  db.get('priv', (err, privkey) => {
    if (err) {
      return cb(err.message);
    }
    db.get('dh_sec', (err, dh_sec) => {
      if (err) {
        return cb(err.message);
      }
      try {
        chunk = cipher_text.split('#');
        key_encrypted = Buffer.from(chunk[0], encoding);
        ct = chunk[1];
        iv = Buffer.from(chunk[2], encoding);
        tag = chunk[3];
        hmac_key = crypto.privateDecrypt(privkey, key_encrypted);

        hmac = crypto.createHmac(hmac_alg, Buffer.from(hmac_key));
        hmac.update(ct);
        hmac.update(iv.toString(encoding));
        computed_tag = hmac.digest(encoding);
        if (computed_tag !== tag) {
          return cb('integrity tag not valid');
        }
        decipher = crypto.createDecipheriv(alg, Buffer.from(dh_sec, encoding), iv);
        decrypted = decipher.update(ct, encoding, 'utf8');
        decrypted += decipher.final('utf8');
        return cb(null, decrypted);
      } catch(err) {
        return cb(err.message);
      }
    });
  });
}

/**
 * encrypt group chat message with group public key
 */

function encrypt_g(msg, cb) {
  var msg_key, hmac_key, iv, hmac, tag, keys_encrypted, cipher, cipher_text;
  db.get('gpub', (err, gpubkey) => {
    if (err) {
      return cb(err.message);
    }  
    try {
      msg_key = crypto.randomBytes(32);
      hmac_key = crypto.randomBytes(32);
      iv = crypto.randomBytes(16); // 128 bits initialization vector
      hmac = crypto.createHmac(hmac_alg, hmac_key);

      // encrypt the message with random key and iv
      cipher = crypto.createCipheriv(alg, msg_key, iv);
      cipher_text = cipher.update(msg, 'utf8', encoding);
      cipher_text += cipher.final(encoding);

      // make sure both the cipher text and
      // the iv are protected by hmac
      hmac.update(cipher_text);
      hmac.update(iv.toString(encoding));
      tag = hmac.digest(encoding);

      // encrypt concatenated msg and hmac keys with group public key
      keys_encrypted = crypto.publicEncrypt(gpubkey, Buffer.from(`${msg_key.toString(encoding)}&${hmac_key.toString(encoding)}`));
      // concatenate keys, cipher text, iv and hmac digest
      return cb(null, `${keys_encrypted.toString(encoding)}#${cipher_text}#${iv.toString(encoding)}#${tag}`);
    } catch(err) {
      return cb(err.message);
    }
  });
}

/**
 * decrypt a group message with group private key
 */

function decrypt_g(cipher_text, cb) {
  var chunk, keys_encrypted, keys_dec, 
    ct, iv, tag, msg_key, hmac_key, hmac,
    computed_tag, decipher, decrypted;

  db.get('gpriv', (err, gprivkey) => {
    if (err) {
      return cb(err.message);
    }
    try {
      chunk = cipher_text.split('#');
      keys_encrypted = Buffer.from(chunk[0], encoding);
      ct = chunk[1];
      iv = Buffer.from(chunk[2], encoding);
      tag = chunk[3];
      keys_dec = crypto.privateDecrypt(gprivkey, keys_encrypted).toString('utf8').split('&');
      msg_key = Buffer.from(keys_dec[0], encoding);
      hmac_key = Buffer.from(keys_dec[1], encoding);

      hmac = crypto.createHmac(hmac_alg, hmac_key);
      hmac.update(ct);
      hmac.update(iv.toString(encoding));
      computed_tag = hmac.digest(encoding);
      if (computed_tag !== tag) {
        return cb('integrity tag not valid');
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

function logout(cb) {  
  db.get('tok', (err, tok) => {
    if (err) {
      er(err.message);
      return cb(err.message);
    }
    sock.emit('logout', {token: tok}).on('logout-err', (err) => {
      er(err);
      return cb(err);
    }).on('logout-success', (dat) => {
      db.batch().del('tok').del('dh_sec').del('room').del('groom').del('gpriv').del('gpub').write(() => {
        log(`\n${dat}`);
        return cb();
      });
    });  
  });
}

function login(usern, passw, cb) {
  const login_sock = io.connect('https://localhost.daplie.com:3761/live/login');
  gen_sign(passw, (err, sig) => {  
    if (err) {
      login_sock.disconnect();
      return cb(err);
    }
    login_sock.emit('login', {un: usern, pw: passw, pw_sig: sig}).on('login-err', (err) => {  
      login_sock.disconnect();
      return cb(err);
    }).on('login-success', (dat) => {  
      if (dat.token) {
        db.put('tok', dat.token, (err) => {
          if (err) {    
            login_sock.disconnect();
            return cb(err.message);
          } else {    
            log('logged in successfully');
            login_sock.disconnect();
            return cb();
          }
        });
      } else {  
        er('server-err: no authorization token');
        login_sock.disconnect();
        return cb('server-err: no authorization token');
      }
    });
  });
}

function gen_jwt(dat, cb) {
  var tok;
  db.get('priv', (err, privkey) => {
    if (err) {
      return cb(err.message);
    }
    dat = Object.assign(dat, {iat: new Date().getTime(), exp: Math.floor(new Date().getTime()/1000) + 60*60});
    // sign jwt asymmetric with RSA SHA256
    tok = jwt.sign(dat, privkey, {algorithm: 'RS256'});
    return cb(null, tok);
  });
}

function verify_tok(token, frd, cb) {
  get_frd_pubkey(frd, (err, frd_pubkey) => {
    if (err) {
      return cb(err);
    }
    // verify jwt asymmetric with friend's public key
    jwt.verify(token, frd_pubkey, {algorithms: 'RS256'}, (err, decod) => {
      if (err) {
        return cb(err.message);
      } else {
        return cb(null, decod);
      }
    });
  });
}

process.on('SIGINT', () => {
  logout((err) => {
    if (err) {
      er(err);
    }
    exit(0);
  });
});

if (arg === 'login') {
  console.log();
  read({prompt: 'username: '}, (err, usern) => {
    if (err) {
      er(err);
    }
    read({prompt: 'password: ', silent: true}, (err, passw) => {
      if (err) {
        er(err);
      }
      login(usern, passw, (err) => {
        if (err) {
          er(err);
        } else {
          exit(0);
        }
      });
    });
  });
} else if (arg === 'ls') {
  get_frds((err, frds) => {
    var ls = [];
    if (err) {
      er(err);
    }
    if (frds.length > 0) {
      frds.forEach((frd) => {
        if (ls.indexOf(frd.name) === -1) {
          ls.push(frd.name);
        }
      });
      console.log(ls);
      exit(0);
    } else {
      log('no friend found');
      exit(0);
    }
  });
} else {
  db.get('name', (err, username) => {
    if (err) {
      er(err.message);
    }
    db.get('tok', (err, tok) => {
      if (err) {
        er(err);
      }
      sock.emit('authenticate', {token: tok}).on('authenticated', () => {
        // once authenticated, create an elliptic curve Diffie-Hellman key exchange for
        // this chat session and generate the client dh public key to send to the other client
        const client_dh = crypto.createECDH('secp256k1');
        const clientkey = client_dh.generateKeys(encoding);

        var rl = readline.createInterface({input: process.stdin, output: process.stdout});
        if (arg === '-p' && frd !== undefined && frd !== '') {
          log(col.italic(`a private chat request sent to ${col.magenta(frd)}, waiting for a response..`));
          // send a private chat request to a friend
          sock.emit('req-chat', {sender: username, receiver: frd}).on('req-chat-reject', (dat) => {  
            log(`${col.magenta(dat.receiver)} rejected the offer`);
            logout((err) => {
              if (err) {
                er(err);
              }
              exit(0);
            });
          });
        } else if (arg === '-g') {
          var frds = process.argv.slice(3, process.argv.length);
          try {
            rm.sync(tmp);
            mkdirp.sync(tmp);
            gen_privkey();
            gen_pubkey();
            db.batch().put('groom', username).put('gpriv', get_privkey()).put('gpub', get_pubkey()).write(() => {  
              gen_jwt({priv: Buffer.from(get_privkey()).toString(encoding), pub: Buffer.from(get_pubkey()).toString(encoding)}, (err, tok) => {
                if (err) {
                  er(err);
                }
                sock.emit('req-group-chat', {room: username, receivers: frds, token: tok});
                log(col.italic(`a group chat request sent to your friends, waiting for a response..`));
                rm.sync(tmp);
              });
            });
          } catch(er) {
            er(er.message);
          }
        } else if (arg === undefined || arg === '') {
          log(col.italic('Your friends chat requests will be shown up here..'));
        }
        sock.on('priv-chat-accept', (dat) => {  
          var dh_sec;
          verify_tok(dat.token, dat.receiver, (err, decod) => {
            if (err) {
              er(err);
            }
            if (decod && decod.dh) {
              dh_sec = client_dh.computeSecret(decod.dh, encoding, encoding);
              db.put('dh_sec', dh_sec, (err) => {
                if (err) {
                  er(err.message);
                }
                gen_jwt({dh: clientkey}, (err, tok) => {
                  if (err) {
                    er(err);
                  }
                  dat = Object.assign(dat, {token: tok});
                  sock.emit('priv-chat-sender-key', dat);
                });
              });
            } else {
              er('token not valid');
            }
          });
        }).on('req-priv-chat', (dat) => {
          // receive a private chat request from a friend
          rl.question(col.italic.cyan(`\n${col.magenta(dat.sender)} wants to have a private conversation. Do you accept? [y/n] `), (ans) => {
            if (ans.match(/^y(es)?$/i)) {  
              gen_jwt({dh: clientkey}, (err, tok) => {
                if (err) {
                  er(err);
                }
                dat = Object.assign(dat, {token: tok});
                sock.emit('req-priv-chat-accept', dat);
              });
            } else {
              sock.emit('req-priv-chat-reject', dat);
              log(col.italic(`a reject response sent to ${col.magenta(dat.sender)}`));
            }
          });
        }).on('priv-chat-sender-pubkey', (dat) => {  
          var dh_sec;
          verify_tok(dat.token, dat.sender, (err, decod) => {
            if (err) {
              er(err);
            }
            if (decod && decod.dh) {
              dh_sec = client_dh.computeSecret(decod.dh, encoding, encoding);
              db.put('dh_sec', dh_sec, (err) => {
                if (err) {
                  er(err);
                }
                sock.emit('priv-chat-key-exchanged', {
                  room: dat.room,
                  sender: dat.sender,
                  receiver: dat.receiver
                });
              });
            } else {
              er('token not valid');
            }
          });
        }).on('priv-chat-ready', (dat) => {
          db.put('room', dat.room, (err) => {
            if (err) {
              er(err.message);
            } else {
              log(col.italic.green(`${dat.sender} and ${dat.receiver} are ready to have a private conversation`));
              rl.setPrompt(col.gray(`${username}: `));
              rl.prompt();
            }
          });
        }).on('priv-msg', (dat) => {
          // verify token and decrypt the message
          verify_tok(dat.token, dat.sender, (err, decod) => {
            if (err) {
              er(err);
            }
            if (decod && decod.msg) {
              decrypt(decod.msg, (err, decrypted) => {
                if (err) {
                  er(err);
                }
                log(`${col.magenta(dat.sender)}: ${decrypted}`);
                rl.prompt();
              });
            } else {
              er('token not valid');
            }
          }); 
        }).on('group-chat', (dat) => {
          verify_tok(dat.token, dat.room, (err, decod) => {
            if (err) {
              er(err);
            }
            if (decod && decod.priv && decod.pub) {
              log(col.italic.cyan(`${col.magenta(dat.room)} wants to add you to a group conversation.`));
              log(col.italic.yellow(`members: ${dat.receivers}`));
              dat = Object.assign(dat, {member: username});
              rl.question(`Do you accept? [y/n] `, (ans) => {
                if (ans.match(/^y(es)?$/i)) {
                  db.batch().put('groom', dat.room).put('gpriv', Buffer.from(decod.priv, encoding).toString()).put('gpub', Buffer.from(decod.pub, encoding).toString()).write(() => {
                    sock.emit('group-chat-accept', dat);
                    rl.setPrompt(col.gray(`${username}: `));
                    rl.prompt();
                  });
                } else {
                  sock.emit('group-chat-reject', dat);
                  log(col.italic(`a reject response sent to ${col.magenta(dat.room)}`));
                }
              });
            } else {
              er('token not valid');
            }
          });
        }).on('group-chat-reject', (dat) => {
          log(col.italic(`\n${col.magenta(dat.member)} rejected the offer`));
          if (arg === '-g') {
            rl.setPrompt(col.gray(`${username}: `));
            rl.prompt();
          }
          if (dat.member !== username) {
            rl.setPrompt(col.gray(`${username}: `));
            rl.prompt();
          }
        }).on('group-chat-accept', (dat) => {    
          log(col.italic.green(`\n${col.magenta(dat.member)} joined the group conversation`));    
          rl.setPrompt(col.gray(`${username}: `));
          rl.prompt();
        }).on('g-msg', (dat) => {
          verify_tok(dat.token, dat.sender, (err, decod) => {
            if (err) {
              er(err);
            }
            if (decod && decod.msg) {
              decrypt_g(decod.msg, (err, decrypted) => {
                if (err) {
                  er(err);
                }
                log(`\n${col.magenta(dat.sender)}: ${decrypted}`);
                rl.prompt();
              });
            } else {
              er('token not valid');
            }
          });
        });

        rl.on('line', (msg) => {
          var sen, rec;
          db.get('room', (err, room) => {
            if (err) {
              // app running on a group chat mode
              // encrypt the group chat message
              db.get('groom', (err, groom) => {
                if (err) {
                  // user rejected the offer
                  // there is no groom in db, do nothing 
                } else {
                  // encrypt a group chat message
                  encrypt_g(msg, (err, enc_dat) => {
                    if (err) {
                      er(err);
                    }
                    // generate jwt with encrypted data
                    gen_jwt({msg: enc_dat}, (err, tok) => {
                      if (err) {
                        er(err);
                      }
                      sock.emit('g-msg', {room: groom, sender: username, token: tok});
                      rl.prompt();
                    });
                  });
                }
              });
            } else {
              if (arg === '-p') {
                rec = frd;
                sen = username;
              } else if (arg === undefined || arg === '') {
                rec = room.split('-')[0];
                sen = username;
              }
              // encrypt a private message and sign the message token
              encrypt(msg, rec, (err, enc_dat) => {
                if (err) {
                  er(err);
                }
                gen_jwt({msg: enc_dat}, (err, tok) => {
                  if (err) {
                    er(err);
                  }
                  sock.emit('priv-msg', {room: room, sender: sen, token: tok});
                  rl.prompt();
                });
              });
            }
          });
        }).on('close', () => {
          logout((err) => {
            if (err) {
              er(err);
            }
            exit(0);
          });
        });
      }).on('unauthorized', (msg) => {
        er(`socket unauthorized: ${JSON.stringify(msg.data)} [err-type: msg.data.type]`);
      }); 
    });
  });
}

