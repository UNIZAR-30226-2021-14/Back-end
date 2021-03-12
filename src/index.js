const fs = require('fs');
const https = require('https');
const express = require('express');
const config = require('../env/config');
const app = express();

//defino los middlewares
//cuando el cliente me envíe un objeto json, la API lo entenderá y lo convertirá a javascript
//que es el tipo del fichero que estoy construyendo
app.use(express.json());

//me puede enviar un dato en forma de formulario
//lo de extended es para decirle que tb puedo recibir imagenes y tal
app.use(express.urlencoded({extended: true}));

//rutas
app.use(require('./routes/index'));

//app.listen(PORT);
//console.log('Server on port ' + PORT);

https.createServer({
    key: fs.readFileSync('my_cert.key'),
    cert: fs.readFileSync('my_cert.crt')
  }, app).listen(config.PORT, function(){
    console.log("My HTTPS server listening on port " + config.PORT + "...");
  });
