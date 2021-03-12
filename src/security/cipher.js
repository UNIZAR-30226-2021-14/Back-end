/*
const crypto = require('crypto');
const algorithm = 'aes-256-cbc';
const secretKey = crypto.randomBytes(32); 
const iv = crypto.randomBytes(16);

function encrypt(text) {
    //creamos el cipher con el algoritmo arriba descrito, la clave secreta y el iv
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    //encriptamos el texto 
    const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);

    return {
        iv: iv.toString('hex'),
        content: encrypted.toString('hex')
    };
} 

function decrypt (hash) {
    const decipher = crypto.createDecipheriv(algorithm, secretKey, Buffer.from(hash.iv, 'hex'));

    const decrpyted = Buffer.concat([decipher.update(Buffer.from(hash.content, 'hex')), decipher.final()]);

    return decrpyted.toString();
}

// unas pruebecillas...

    var aux = encrypt("hola buenas!!")
    console.log(aux);

   var aux = aux.iv + aux.content;
   console.log(aux);

   aux = aux.toString();

   var ivvv = aux.substr(0, 32);
   var contentttt = aux.substr(32,64);

   console.log(ivvv+'\n'+contentttt);

   var final = {
       iv: ivvv,
       content: contentttt
    };

    console.log(final);

    console.log(decrypt(final))



module.exports = {
    encrypt,
    decrypt
}
*/