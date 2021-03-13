//propio servidor express para recibir peticiones
const { json } = require('express');
//autenticar usuarios a través de token
const jwt = require('jsonwebtoken')
//importamos variables de entorno
const config = require('../../env/config')

//cifra con aes-256-gcm
const Cryptr = require('cryptr');
const cryptr = new Cryptr('ahsj174693=&%%$DGHSV');

//para hashear las contraseñas maestras
const bcrypt = require('bcrypt');
const saltRounds = 10;

//importo las funciones de encriptar y desencriptar
const {encrypt,decrypt} = require('../security/cipher');

//en este ficherito me defino todas las funciones que necesito.
//en este caso, aquí podría definir todo lo relacionado con el usuario.
const { Pool } = require('pg');

//Pool de conexiones a la BD para poder conectarme a psoftBD y coger los datos
const conexion = new Pool ({
    host: config.HOST,
    user: config.DB_USER,
    password: '',
    database: config.DB_NAME
})

const pruebilla = async (req,res) => {
    //pruebo situacion: usuario manda peticion con token.
    //la funcion de middleware me validará el token.
    //yo llegaré aquí sólo si es válido.
    //Si ok -> imprimo por pantalla el nombre del usuario que me ha hecho la peti.

    //en la funcion de middleware, he dejado en req.usuario el mail de la persona
    //que me ha enviado el token. Lo cojo.
    res.send(req.usuario);
    
};

//obtengo información de la BD.
//si me mandan un GET de los usuarios de la BD, les muestro lo siguiente.
const getUsers = async (req,res) => {
    const usuarios = await conexion.query('Select * from usuarios');
    res.status(200).json(usuarios.rows);
    console.log(usuarios.rows);
};


//registro en BD. Aquí ya sé que el ususario no está en BD, lo tengo que añadir. 
//Envío también el JWT al usuario para saber que es él en sucesivas comunicaciones.
const addUser = async (req,res) => {
    //cojo el nombre y la pw del JSON que me envían (del usuario que hay q meter en BD)
    const {nombre,password} = req.body;

    //comprobamos que no esté en BD ya
    const resp1 = await conexion.query('SELECT * from usuarios where nombre=$1',[nombre]);
    
    if (resp1.rowCount>0) {
        //ya hay un usuario en BD con ese nombre
        res.status(404).json({
            message: 'User already exists',
            codigo: '0'
        })
    }
    else {
        //el usuario no está en BD -> lo añado
        //hasheo la password del usuario
        let hash = bcrypt.hashSync(password, saltRounds);
        
        //inserto el usuario junto a su contraseña cifrada en la base de datos
        const resp = await conexion.query('INSERT INTO usuarios (nombre,password) VALUES ($1,$2)', [nombre,hash]);
        
        //genero el token para el usuario, meto su nombre de user en el token y lo cifro con la clave.
        const accessToken = jwt.sign({ username: nombre}, config.llave_token, {
            expiresIn: 60 * 60 * 24 // expires in 24 hours
        });

        //envío al cliente otro JSON, con un msj y el token de autenticación.
        res.json({
            message: 'Usuario introducido correctamente',
            token: accessToken
        })
    }

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
    const {concreteuser,concretepasswd,dominio,fechacreacion,fechacaducidad,nombre,categoria} = req.body;
    const tipo = "usuario-passwd"
    const fichero = "NULL"
    //cojo el nombre de usuario del token que me han pasado
    const usuarioPrincipal = req.usuario;

    //miro si ya existe un par usuario-passwd con mismo nombre que el que quiere el usuario
    const aux = await conexion.query('select nombre from contrasenya where (email=$1 and nombre=$2)',[usuarioPrincipal,nombre]);

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
            message: 'Contraseña introducida correctamente'
        })
    }
    else {
        //ya hay una contraseña para él con ese nombre
        res.status(404).json({
            message: 'Ya tiene una contraseña con ese nombre'
        })
    }
};

//obtengo todas las contraseñas del usuario X
//le doy al front solamente el nombre de la contraseña y el dominio
const getPasswdsUser = async (req,res) => {
    //cojo nombre del usuario del token que me pasa.
    const usuarioPrincipal = req.usuario;

    //pregunto por las passwds de este usuario
    const resp = 
    await conexion.query('SELECT dominio,nombre from contrasenya where email=$1',[usuarioPrincipal]);
    
    //envío al cliente otro JSON, con un msj y el user creado.
    res.status(200).json(resp.rows);
};


//si usuario está en BD -> le mando token
//si ha puesto mal la passwd (pero el email existe) -> le mando error (passwd incorrecta)
//si ni siquiera existe el mail -> le mando error y que se registre o algo
const verifyUser = async (req,res) => {
    //cojo el usuario y su pass
    const {nombre, password} = req.body;

    //miro si el usuario está en bd y si está, obtengo su password (estará cifrada claro)
    const resp1 = await conexion.query('SELECT password from usuarios where nombre=$1',[nombre]);

    //si no has podido seleccionar ninguna row (no hay user con ese nombre)...
    if (resp1.rowCount==0) {
        //el usuario ni está en bd porque no lo encuentro en bd
        res.status(404).json({
            message: 'User not in DB',
            codigo: '0'
        })
    }
    else{
        //comparo con esta funcioncita la password que me envían del front
        //(con la que el user quiere hacer log in) con la que tiene ese user en bd
        if (bcrypt.compareSync(password, resp1.rows[0].password)) {
            // Passwords match, generate JWT and send info to user.
            const accessToken = jwt.sign({ username: nombre}, config.llave_token, {
                expiresIn: 60 * 60 * 24 // expires in 24 hours
            });

            res.json({
                message: 'User OK',
                codigo: '1',
                token: accessToken
            })
        } 
        else {
            // Passwords don't match
            res.status(404).json({
                message: 'Password NOT OK',
                codigo: '0'
            })
        }
    }


};

//saca los detalles de la contraseña en específico (par,fichero ó imagen)
const detailsPasswd = async (req,res) => {
    //nombre de la contraseña en específico
    const {nombrePassword} = req.body;
    //nombre del usuario que ha creado la contraseña. Lo saco del token.
    const nombreUsuario = req.usuario;
    //selecciono el tipo de contraseña que es
    const resp1 = await conexion.query('SELECT tipo from contrasenya where (email=$1 and nombre=$2)',[nombreUsuario,nombrePassword]);
    
    // ** COMPROBAR ANTES QUE TENGA UNA QUE SE LLAME ASÍ **
    if (resp1.rowCount==0) {
        res.status(404).json({
            message: 'No password with that name'
        })
    }
    else {
        //cogemos el tipo de contraseña que es
        var tipo = resp1.rows[0].tipo;

        switch(tipo) {
            case "usuario-passwd":
                //me quedo con los detalles que me interesan de este tipo de contraseña
                const resp2 = await conexion.query('SELECT concreteuser,concretepasswd,dominio,categoria,fechacreacion,fechacaducidad from contrasenya where (email=$1 and nombre=$2)',[nombreUsuario,nombrePassword]);
                //antes de enviar a front, debo descifrar la contraseña
                var passCifrada = resp2.rows[0].concretepasswd;

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