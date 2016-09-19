'use strict';

/**
 * app dependencies and consts
 */

const path = require('path');
const electron = require('electron');
const {app, BrowserWindow, dialog, ipcMain} = electron;
const iconpath = path.join(__dirname, 'resources', 'icon.png');
const auth = require('./auth.js');

/**
 * view files paths
 */

const reg_index = `file://${__dirname}/views/register.html`;
const login_index = `file://${__dirname}/views/login.html`;
const chat_index = `file://${__dirname}/views/chat.html`;
const addfrd_index = `file://${__dirname}/views/addfrd.html`;

/**
 * keep the reference to the main window.
 * otherwise, it will be dereferenced by the
 * javascript garbage collector.
 */

var reg_win = null;
var login_win = null;
var chat_win = null;
var addfrd_win = null;

/**
 * show error message
 */

function showerr(err) {
  dialog.showMessageBox({
    type: 'error',
    title: 'elfpm error',
    message: `\n${err}`,
    buttons: ['ok']
  });
}

/**
 * show info message
 */

function showinfo(info) {
  dialog.showMessageBox({
    type: 'info',
    title: 'elfpm',
    message: `\n${info}`,
    buttons: ['ok']
  });
}

/**
 * create windows
 */

function create_win() {
  // login window
  login_win = new BrowserWindow({
    width: 600,
    height: 400,
    'min-width': 400,
    'min-height': 200,
    icon: iconpath
  });

  // by default, load login window
  login_win.loadURL(login_index);

  // open devtool for debugging
  login_win.webContents.openDevTools();

  // dereference window when it is closed
  login_win.on('closed', () => {
    login_win = null;
  });

  // register window
  reg_win = new BrowserWindow({
    width: 600,
    height: 400,
    'min-width': 400,
    'min-height': 200,
    icon: iconpath,
    show: false
  });
  reg_win.loadURL(reg_index);
  reg_win.webContents.openDevTools();
  reg_win.on('closed', () => {
    reg_win = null;
  });

  // add friend window
  addfrd_win = new BrowserWindow({
    width: 700,
    height: 500,
    'min-width': 400,
    'min-height': 200,
    icon: iconpath,
    show: false
  });
  addfrd_win.loadURL(addfrd_index);
  addfrd_win.webContents.openDevTools();
  addfrd_win.on('closed', () => {
    addfrd_win = null;
  });

  // chat window, authenticated route
  chat_win = new BrowserWindow({
    width: 1000,
    height: 700,
    'min-width': 400,
    'min-height': 200,
    icon: iconpath,
    show: false
  });
  chat_win.loadURL(chat_index);
  chat_win.webContents.openDevTools();
  chat_win.on('closed', () => {
    if (addfrd_win !== null) {
      addfrd_win.close();
    }
    auth.destroy_token((err) => {
      if (err) {
        console.log('destroy-tok-err: ', err);
        showerr(err);
      }
      chat_win = null;
      app.quit();
    });
  });  
}

app.on('ready', create_win);

/**
 * when all windows are closed, quit the app
 */

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {  
    app.quit();
  }
});

app.on('activate', () => {
  if (login_win === null) {
    create_win();
  }
});

/**
 * reload register window on error
 */

ipcMain.on('reg-err', (event, err) => {
  showerr(err);
  reg_win.reload();
});

/**
 * reload login window on error
 */

ipcMain.on('login-err', (event, err) => {
  showerr(err);
  login_win.reload();
});

/**
 * reload chat window on I/O error
 */

ipcMain.on('chat-err', (event, err) => {
  showerr(err);
  chat_win.reload();
});

/**
 * load register (create account) window
 */

ipcMain.on('load-reg', () => {
  reg_win.show();
});

/**
 * make a request to /register endpoint
 * if successful, load login window
 */

ipcMain.on('request-reg', (ev, dat) => {
  if (dat.usern && dat.passw) {
    auth.register(dat.usern, dat.passw, (err) => {
      if (err) {
        showerr(err);
        reg_win.reload();
      } else {
        showinfo('Your keys and account created successfully. You can login now');
        if (reg_win !== null) {
          reg_win.close();
        }
        login_win.focus();
      }
    });
  } else {
    showerr('username/password not valid');
  }
});

/**
 * make a request to /login endpoint
 * if successful, load chat window
 */

ipcMain.on('request-login', (ev, dat) => {
  if (dat.usern && dat.passw) {
    auth.login(dat.usern, dat.passw, (err) => {
      if (err) {
        showerr(err);
        login_win.reload();
      } else {
        auth.check_unread((err) => {
          if (err) {
            showerr(err);
            login_win.reload();
          } else {
            if (login_win !== null) {
              login_win.close();
            }
            chat_win.show();
          }
        });
      }
    });
  } else {
    showerr('username/password not valid');
  }
});

ipcMain.on('load-addfrd', () => {
  addfrd_win.show();
});

/**
 * add new friend event
 */

ipcMain.on('add-frd', (ev, dat) => {
  if (dat.frd_usern && dat.frd_pubkey && dat.frd_sig) {  
    if (!auth.verify_pubkey(dat.frd_pubkey, dat.frd_sig)) {
      showerr('Public key/signature not verified');
      addfrd_win.reload();
    } else {
      auth.add_frd(dat.frd_usern, dat.frd_pubkey, (err) => {
        if (err) {
          showerr(err);
          addfrd_win.reload();
        } else {
          showinfo('Public key verified and added successfully');
          if (addfrd_win !== null) {
            addfrd_win.hide();
          }
          ev.sender.send('add-frd-success');
          chat_win.reload();
        }
      });
    }
  }
});

/**
 * send friend list to ipc renderer event
 */

ipcMain.on('frd-ls', (ev, arg) => {
  auth.get_frds((err, frds) => {
    if (err) {
      showerr(err);
      if (chat_win !== null) {
        chat_win.reload();
      }
    }
    if (frds && frds.length > 0) {
      ev.sender.send('frd-ls-success', frds);
    }
  });
});

/**
 * send message event
 */

ipcMain.on('send-msg', (ev, arg) => {
  if (arg.msg && arg.receiver) {
    auth.send_msg(arg.msg, arg.receiver, (err, res) => {
      if (err) {
        showerr(err);
        if (chat_win !== null) {
          chat_win.reload();
        }
      }
      if (res.un && res.time) {
        console.log('message sent successfully');
        ev.sender.send('send-msg-success', {
          un: res.un,
          msg: arg.msg,
          time: res.time
        });
      }
    });
  }
});

ipcMain.on('show-msg', (ev, frd_username) => {
  if (frd_username) {
    auth.show_msg(frd_username, (err, res) => {
      if (err) {
        showerr(err);
        chat_win.reload();
      }
      if (res && res.length > 0) {
        ev.sender.send('show-msg-success', {sender: frd_username, msgs: res});
      }
    });
  }
});

/**
 * if something unexpected happens, show the error
 */

process.on('uncaughtException', (err) => {
  console.log(`something unexpected happened: ${err}`);
  showerr(err.message);
});

