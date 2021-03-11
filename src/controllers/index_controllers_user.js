const { json } = require('express');

const Cryptr = require('cryptr');
const cryptr = new Cryptr('ahsj174693=&%%$DGHSV');

const bcrypt = require('bcrypt');
const saltRounds = 10;

//importo las funciones de encriptar y desencriptar
const {encrypt,decrypt} = require('../security/cipher');

//en este ficherito me defino todas las funciones que necesito.
//en este caso, aquí podría definir todo lo relacionado con el usuario.
const { Pool } = require('pg');

//Pool de conexiones a la BD para poder conectarme a psoftBD y coger los datos
const conexion = new Pool ({
    host: 'localhost',
    user: 'pablojordan',
    password: '',
    database: 'psoftBD'
})

const pruebilla = async (req,res) => {
    //INSERTO contraseña y la intento descifrar
    //cojo el nombre y la pw del JSON que me envían (del usuario que hay q meter en BD)
    const {persona,pw } = req.body;
    

    //saco y descifro
    const resp = await conexion.query('SELECT pw from prueba where persona=$1',[persona]);

    console.log(resp.rows[0].pw);

    var pwDesc = decrypt(resp.rows[0].pw);


};

//obtengo información de la BD.
//si me mandan un GET de los usuarios de la BD, les muestro lo siguiente.
const getUsers = async (req,res) => {
    const usuarios = await conexion.query('Select * from usuarios');
    res.status(200).json(usuarios.rows);
    console.log(usuarios.rows);
};

//guardo info en la BD
//si me mandan un POST deberé guardar usuarios en BD (por ej: alguien se registra)
//recojo el json que me pasen con el user y la pass y lo meto en bd
//AQUÍ TENDRÍA QUE MANDARLE A FRONT EL JWT DEL USUARIO X
const addUser = async (req,res) => {
    //cojo el nombre y la pw del JSON que me envían (del usuario que hay q meter en BD)
    const { nombre,password } = req.body;
    
    //hasheo la password del usuario
    let hash = bcrypt.hashSync(password, saltRounds);
    
    //inserto el usuario junto a su contraseña cifrada en la base de datos
    const resp = await conexion.query('INSERT INTO usuarios (nombre,password) VALUES ($1,$2)', [nombre,hash]);
    

    //envío al cliente otro JSON, con un msj y el user creado.
    res.json({
        message: 'Usuario introducido correctamente',
        body: {
            userBefore: {nombre,password},
            userAfter: {nombre, hash}
        }

    })
    //saco por pantalla el resultado del INSERT
    console.log(resp);

};

//elimino a un usuario de la BD. 
//Al eliminarse, se eliminan tb sus contraseñas (por el DELETE on CASCADE)
const removeUser = async (req,res) => {
    //me pasan el JSON del usuario, me quedo con su nombre (clave primaria)
    const nombre = req.body.nombre;

    //inserto en la el nombre y la pw del usuario que me han pasado
    const resp = await conexion.query('DELETE FROM usuarios WHERE nombre=$1', [nombre]);

    //si resp.rowCount es cero es que no ha deleteado ninguna row (el user no existe)
    if (resp.rowCount==0) {
        res.json({
            message: 'Usuario no existe en BD'
        })
    }
    else {
    //envío al cliente JSON con un msj de ACK (ha ido ok)
        res.json({
            message: 'Usuario deleteado correctamente'
        })
    }

};

//solamente añade un simple par usuario-contraseña asociado a un 
//usuario de la BD. Las pruebas se hacen con loco@hotmail.com
//se comprueba que el tío no meta dos contraseñas iguales (con igual nombre)
//si quiere tener dos de github pues la primera tendrá de nombre github pero la segunda tendrá de nombre github2
//porque en bd ya hay una que se llama github.
const addpwtoUser = async (req,res) => {
    //cojo el par user-pass concreto y el dominio (fb,twitter,amazon...)
    const {usuarioPrincipal,concreteuser,concretepasswd,dominio,fechacreacion,fechacaducidad,nombre,categoria} = req.body;
    const tipo = "usuario-passwd"
    const fichero = "NULL"

    //miro si ya existe un par usuario-passwd con mismo nombre que el que quiere el usuario
    const aux = await conexion.query('select nombre from contrasenya where (email=$1 and nombre=$2)',[usuarioPrincipal,nombre]);

    console.log(aux.rows);
    
    //se puede añadir
    if (aux.rows==0) {
        //ciframos la contraseña con un cifrado simétrico (para poderla recuperar luegoo)
        //var encrypted_passwd = encrypt(concretepasswd);
        
        //concateno el iv y el contenido y para almacenarlo en BD
        //encrypted_passwd = encrypted_passwd.iv + encrypted_passwd.content; 

        const encrypted_passwd = cryptr.encrypt(concretepasswd);

        //inserto en la BD el nombre y la pw del usuario que me han pasado
        const resp = 
        await conexion.query('INSERT INTO contrasenya (email,tipo,concreteuser,concretepasswd,dominio,fichero,categoria,fechacreacion,fechacaducidad,nombre) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)', 
            [usuarioPrincipal,tipo,concreteuser,encrypted_passwd,dominio,fichero,categoria,fechacreacion,fechacaducidad,nombre]);
    
        //envío al cliente otro JSON, con un msj y el user creado.
        res.json({
            message: 'Contraseña introducida correctamente',
        })
        //saco por pantalla el resultado del INSERT
        console.log("contraseña añadida al usuario");
    }
    else {
        //ya hay una contraseña para él con ese nombre
        res.json({
            message: 'Ya tiene una contraseña con ese nombre',
        })
    }
};

//obtengo todas las contraseñas del usuario X
//le doy al front solamente el nombre de la contraseña y el dominio
const getPasswdsUser = async (req,res) => {
    //cojo el par user-pass concreto y el dominio (fb,twitter,amazon...)
    const {usuarioPrincipal} = req.body;

    //pregunto por las passwds de este usuario
    const resp = 
    await conexion.query('SELECT dominio,nombre from contrasenya where email=$1',[usuarioPrincipal]);
    
    //envío al cliente otro JSON, con un msj y el user creado.
    res.status(200).json(resp.rows);
    console.log(resp.rows);
    //saco por pantalla el resultado del INSERT
    console.log("\nSacamos contraseñas del usuario");

};

//verifico que el usuario X esté en Base de datos
//AQUÍ TENDRÍA QUE MANDARLE A FRONT EL JWT DEL USUARIO X
const verifyUser = async (req,res) => {
    //cojo el usuario y su pass
    const {nombre, password} = req.body;

    //miro si el usuario está en bd y si está, obtengo su password (estará cifrada claro)
    const resp1 = await conexion.query('SELECT password from usuarios where nombre=$1',[nombre]);

    //si no has podido seleccionar ninguna row (no hay user con ese nombre)...
    if (resp1.rowCount==0) {
        //el usuario ni está en bd porque no lo encuentro en bd
        res.json({
            message: 'Usuario no está en base de datos',
            codigo: '0'
        })
    }
    else{
        //comparo con esta funcioncita la password que me envían del front
        //(con la que el user quiere hacer log in) con la que tiene ese user en bd
        if (bcrypt.compareSync(password, resp1.rows[0].password)) {
            // Passwords match
            res.json({
                message: 'Usuario + password correctas',
                codigo: '1'
            })
        } 
        else {
            // Passwords don't match
            res.json({
                message: 'Password incorrecta',
                codigo: '0'
            })
        }
    }


};

//saca los detalles de la contraseña en específico (par,fichero ó imagen)
const detailsPasswd = async (req,res) => {
    //me pasan el nombre de la contraseña del usuario
    const {nombreUsuario, nombrePassword} = req.body;
    //selecciono el tipo de contraseña que es
    const resp1 = await conexion.query('SELECT tipo from contrasenya where (email=$1 and nombre=$2)',[nombreUsuario,nombrePassword]);
    // ** COMPROBAR ANTES QUE TENGA UNA QUE SE LLAME ASÍ **
    // if resp1.rowCount es 0 --> json: ERROR
    //cogemos el tipo de contraseña que es
    var tipo = resp1.rows[0].tipo;

    switch(tipo) {
        case "usuario-passwd":
            //me quedo con los detalles que me interesan de este tipo de contraseña
            const resp2 = await conexion.query('SELECT concreteuser,concretepasswd,dominio,categoria,fechacreacion,fechacaducidad from contrasenya where (email=$1 and nombre=$2)',[nombreUsuario,nombrePassword]);
            //antes de enviar a front, debo descifrar la contraseña
            var passCifrada = resp2.rows[0].concretepasswd;
            console.log("PasswordCifrada : " + passCifrada);

            //var auxIV = passCifrada.substr(0, 32);
            //auxIV = auxIV.toString('hex');

            //var auxC = passCifrada.substr(32, 64);
            //auxC = auxC.toString('hex');            

            //creamos el JSON para pasarselo al método decrypt con el iv y content (32 bits y 32 bits) que he cogido de la pass
            //var passwordJson = {
            //    iv: auxIV,
            //    content: auxC
            //};
            //console.log("JSON: " + passwordJson.iv + ", " + passwordJson.content);
            
            //descifro la contraseña que he almacenado en BD
            const plainTextPasswd = cryptr.decrypt(passCifrada);
            //actualizo el campo de la passwd con lo que me ha salido y envío a front
            var respuesta = {
                concreteuser : resp2.rows[0].concreteuser,
                concretpasswd : plainTextPasswd,
                dominio : resp2.rows[0].dominio,
                categoria : resp2.rows[0].categoria,
                fechacreacion : resp2.rows[0].fechacreacion,
                fechacaducidad : resp2.rows[0].fechacaducidad
            };
            //enviamos
            res.send(respuesta);
        break;
        
        case "fichero":
            res.send("ficherito - no implementado aun");
        break;

        case "imagen":
            res.send("imagen - no implementado aun");
        break;

    }
    
};






//aquí simplemente digo que exporto las funciones aquí definidas para que
//se puedan usar en el módulo de index.js (routes)
module.exports = {
    getUsers,
    addUser,
    removeUser,
    pruebilla,
    addpwtoUser,
    getPasswdsUser,
    verifyUser,
    detailsPasswd
}