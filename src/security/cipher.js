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
/*
    var aux = encrypt("hola buenas!!")
    console.log(aux.content);

    var msjOriginal = decrypt(aux);
    console.log(msjOriginal);
*/


module.exports = {
    encrypt,
    decrypt
}