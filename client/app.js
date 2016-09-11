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

/**
 * keep the reference to the main window.
 * otherwise, it will be dereferenced by the
 * javascript garbage collector.
 */

var reg_win = null;
var login_win = null;
var chat_win = null;

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

  // chat window, authenticated route
  chat_win = new BrowserWindow({
    width: 800,
    height: 600,
    'min-width': 400,
    'min-height': 200,
    icon: iconpath,
    show: false
  });

  chat_win.loadURL(chat_index);
  chat_win.webContents.openDevTools();
  chat_win.on('closed', () => {
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

app.on('before-quit', () => {  
  auth.destroy_token((err) => {
    if (err) {
      console.log('before-quit-err: ', err);
      showerr(err);
    }
  });
});

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

ipcMain.on('reg-err', () => {
  reg_win.reload();
});

/**
 * reload login window on error
 */

ipcMain.on('login-err', () => {
  login_win.reload();
});

/**
 * reload chat window on I/O error
 */

ipcMain.on('chat-err', () => {
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

ipcMain.on('request-reg', (event, dat) => {
  if (dat.usern && dat.passw) {
    auth.register(dat.usern, dat.passw, (err) => {
      if (err) {
        showerr(err);
        reg_win.reload();
      } else {
        dialog.showMessageBox({
          type: 'info',
          title: 'elfpm',
          message: '\nYour account created successfully. You can login now',
          buttons: ['ok']
        });
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

ipcMain.on('request-login', (event, dat) => {
  if (dat.usern && dat.passw) {
    auth.login(dat.usern, dat.passw, (err) => {
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
  } else {
    showerr('username/password not valid');
  }
});

/**
 * if something unexpected happens, reload the login page.
 */

process.on('uncaughtException', (err) => {
  console.log(`something unexpected happened: ${err}`);
  showerr(err.message);
});

