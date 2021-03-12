// config.js
module.exports = {
    NODE_ENV: process.env.NODE_ENV || 'development',
    HOST: process.env.HOST || '127.0.0.1',
    PORT: process.env.PORT || 3003,
    DB_USER: process.env.DB_USER || 'pablojordan',
    DB_NAME: process.env.DB_NAME || 'psoftBD',
    llave_token: "907093e3b629339ea0984bebe62dd9d60a8240fe4f46c2526d8ac2d7108bcb2555101b69ee5b8d4cf8387d620cb5575fc1ee6c0e3f42c01a8bb947325ef6b130"
  }

  //la llave_token se ha calculado haciendo:
  //const crypto = require('crypto');
  //console.log(crypto.RandomBytes(64).toString('hex))