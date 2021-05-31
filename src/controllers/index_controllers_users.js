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

//importo las funciones de encriptar y desencriptar ficheros (imagenes/ficheros al uso)
const {encryptFile,decryptFile} = require('../security/cipher')
const fs = require('fs')
const path = require('path')

//en este ficherito me defino todas las funciones que necesito.
//en este caso, aquí podría definir todo lo relacionado con el usuario.
const { Pool } = require('pg');

//Pool de conexiones a la BD para poder conectarme a psoftBD y coger los datos
const conexion = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false
    }
});

const pruebilla = async (req,res) => {
    //pruebo situacion: usuario manda peticion con token.
    //la funcion de middleware me validará el token.
    //yo llegaré aquí sólo si es válido.
    //Si ok -> imprimo por pantalla el nombre del usuario que me ha hecho la peti.

    //en la funcion de middleware, he dejado en req.usuario el mail de la persona
    //que me ha enviado el token. Lo cojo.
    res.send(req.usuario);

};

// -------------- USERS --------------

//LOG IN. (return token if user valid)
const userLogin = async (req,res) => {
    //cojo el usuario y su pass
    const {nombre, password} = req.body;
    //miro si el usuario está en bd y si está, obtengo su password (estará cifrada claro)
    const resp1 = await conexion.query('SELECT password from usuarios where nombre=$1',[nombre]);

    //si no has podido seleccionar ninguna row (no hay user con ese nombre)...
    if (resp1.rowCount==0) {
        //el usuario ni está en bd porque no lo encuentro en bd
        res.status(404).json({
            message: 'User does not exist',
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

//SIGNIN.
const userSignin = async (req,res) => {
    //cojo el nombre y la pw del JSON que me envían (del usuario que hay q meter en BD)
    const {nombre,password} = req.body;
    //comprobamos que no esté en BD ya
    const resp1 = await conexion.query('SELECT * from usuarios where nombre=$1',[nombre]);
    if (resp1.rowCount>0) {
        //ya hay un usuario en BD con ese nombre
        res.status(404).json({
            message: '0'
        })
    }
    else {
        //el usuario no está en BD -> lo añado
        //hasheo la password del usuario
        let hash = bcrypt.hashSync(password, saltRounds);
        //inserto el usuario junto a su contraseña cifrada en la base de datos
        const resp = await conexion.query('INSERT INTO usuarios (nombre,password) VALUES ($1,$2)', [nombre,hash]);
        //respondo que ya se ha insertado al user.
        res.json({
            message: '1'
        })
    }
};

//DELETE ACCOUNT.
//Al eliminarse, se eliminan tb sus contraseñas (por el DELETE on CASCADE)
const userRemove = async (req,res) => {
    //me pasan el JSON del usuario, me quedo con su nombre (clave primaria)
    const usuarioPrincipal = req.usuario;
    //elimino al usuario en cuestión
    const resp = await conexion.query('DELETE FROM usuarios WHERE nombre=$1', [usuarioPrincipal]);

    //si resp.rowCount es cero es que no ha deleteado ninguna row (el user no existe)
    if (resp.rowCount==0) {
        res.status(404).json({
            message: 'Usuario no existe!!'
        })
    }
    else {
    //envío al cliente JSON con un msj de ACK (ha ido ok)
        res.status(200).json({
            message: 'Usuario deleteado correctamente'
        })
    }
};

//CHANGE PASSWD
const userChangePw = async (req,res) => {
    //cojo la nueva pw que quiere el user
    const {password} = req.body;
    //cojo el nombre de usuario del token que me han pasado
    const usuarioPrincipal = req.usuario;
    //no compruebo q esta en BD pq al tener token, se ha tenido que loguear -> está en BD 100%
    //cambiamos la pass
    let hash = bcrypt.hashSync(password, saltRounds);
    //inserto el usuario junto a su contraseña cifrada en la base de datos
    const resp = await conexion.query('UPDATE usuarios SET password=$1 where (nombre=$2)', [hash,usuarioPrincipal]);
    //respondo que ya se ha insertado al user.
    res.json({
        message: 'Password changed correctly'
    })
};


// -------------- PASSWORDS --------------

//solamente añade un simple par usuario-contraseña asociado a un user.
//si quiere tener dos de github pues la primera tendrá de nombre github pero la segunda tendrá de nombre github2
//porque en bd ya hay una que se llama github.
const addpwtoUser = async (req,res) => {
    //cojo el par user-pass concreto y el dominio (fb,twitter,amazon...)
    const {concreteuser,concretepasswd,dominio,fechacreacion,fechacaducidad,nombre,categoria} = req.body;
    const tipo = "usuario-passwd"
    const fichero = null;
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
        res.status(200).json({
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
    //cojo los parametros de ordenacion que me pasan en la QUERY
    let ordenarPor = req.query.ordenarPor;  //nombre, fechacreacion ó fechacaducidad
    let ordenarDe = req.query.ordenarDe;    //ASC o DESC
    //let elemento = req.query.elemento;      //¿Qué quiere front que le pase?

    //NO DEJA USAR ORDER BY $1. Hay que hacerlo manualmente.
    var resp;
    switch(ordenarPor) {
        case "nombre":
            if (ordenarDe=="ASC") {
                resp =
                await conexion.query('SELECT dominio,nombre,tipo,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 ORDER BY nombre ASC',[usuarioPrincipal]);
            }
            else {
                resp =
                await conexion.query('SELECT dominio,nombre,tipo,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 ORDER BY nombre DESC',[usuarioPrincipal]);
            }
        break;

        case "fechacreacion":
            if (ordenarDe=="ASC") {
                resp =
                await conexion.query('SELECT dominio,nombre,tipo,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 ORDER BY fechacreacion ASC',[usuarioPrincipal]);
            }
            else {
                resp =
                await conexion.query('SELECT dominio,nombre,tipo,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 ORDER BY fechacreacion DESC',[usuarioPrincipal]);
            }
        break;

        case "fechacaducidad":
            if (ordenarDe=="ASC") {
                resp =
                await conexion.query('SELECT dominio,nombre,tipo,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 ORDER BY fechacaducidad ASC',[usuarioPrincipal]);
            }
            else {
                resp =
                await conexion.query('SELECT dominio,nombre,tipo,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 ORDER BY fechacaducidad DESC',[usuarioPrincipal]);
            }
        break;

        case "categoria":
            if (ordenarDe=="ASC") {
                resp =
                await conexion.query('SELECT dominio,nombre,tipo,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 ORDER BY categoria ASC',[usuarioPrincipal]);
            }
            else {
                resp =
                await conexion.query('SELECT dominio,nombre,tipo,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 ORDER BY categoria DESC',[usuarioPrincipal]);
            }
        break;

    }
    res.status(200).json(resp.rows);
};

//saca los detalles de la contraseña en específico (par,fichero ó imagen)
const detailsPasswd = async (req,res) => {
    //nombre de la contraseña en específico
    let nombrePassword = req.query.nombre;
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

//elimina la contraseña con el nombre que sea
const deletepasswd = async (req,res) => {
    //cojo el nombre de la password solicitada
    const {nombre} = req.body;
    //cojo el nombre de usuario del token que me han pasado
    const usuarioPrincipal = req.usuario;

    //miro si ya existe un par usuario-passwd con mismo nombre que el que quiere el usuario
    const aux = await conexion.query('select nombre from contrasenya where (email=$1 and nombre=$2)',[usuarioPrincipal,nombre]);

    //hay contraseña para el usuario
    if (aux.rows!=0) {
        //elimino de BD la contraseña en cuestión
        const resp =
        await conexion.query('DELETE FROM contrasenya where (email=$1 and nombre=$2)',[usuarioPrincipal,nombre]);

        //envío al cliente otro JSON, con un msj y el user creado.
        res.status(200).json({
            message: 'Contraseña eliminada correctamente'
        })
    }
    else {
        //no hay contraseña con ese nombre
        res.status(404).json({
            message: 'No hay contraseña con ese nombre'
        })
    }
};

//elimina la contraseña con el nombre que sea
const editpasswd = async (req,res) => {
    //cojo el nombre de la password solicitada
    const {nombrePassword,concreteuser,concretepasswd,dominio,categoria,fechacreacion,fechacaducidad,nombre} = req.body;
    //cojo el nombre de usuario del token que me han pasado
    const usuarioPrincipal = req.usuario;

    //comprobamos que no tiene una con ese nombre
    //comprobamos si ya tiene una contra con ese nombre
    const aux = await conexion.query('select nombre from contrasenya where (email=$1 and nombre=$2)',[usuarioPrincipal,nombre]);

    if (aux.rows==0 || nombrePassword==nombre) {
        //no hay, la añado
        //ciframos la passwd
        const encrypted_passwd = cryptr.encrypt(concretepasswd);

        //hago el UPDATE
        const aux = await conexion.query('UPDATE contrasenya SET concreteuser=$1,concretepasswd=$2,dominio=$3,categoria=$4,fechacreacion=$5,fechacaducidad=$6,nombre=$7 where nombre=$8',
        [concreteuser,encrypted_passwd,dominio,categoria,fechacreacion,fechacaducidad,nombre,nombrePassword]);

        res.status(200).json({
            message: 'Contraseña editada correctamente!!'
        })

    }
    else {
        res.status(404).json({
            message: 'Ya tiene una contraseña con ese nombre'
        })
    }

};


// -------------- CATEGORIES --------------

//crea una categoria asociada al usuario en cuestion.
const addCat = async (req,res) => {
    //cojo nombre del usuario del token que me pasa.
    const usuarioPrincipal = req.usuario;
    const {nombrecategoria} = req.body;

    //miro si tiene una categoria con ese nombre
    const resp =
    await conexion.query('SELECT * from categorias where (mail=$1 AND nombrecat=$2)',[usuarioPrincipal,nombrecategoria]);

    if (resp.rowCount==0) {
        //puedo crearla
        const resp =
        await conexion.query('INSERT INTO categorias (nombrecat,mail) VALUES ($1,$2)',[nombrecategoria,usuarioPrincipal]);

        res.status(200).json({
            message: 'Category created'
        })
    }
    else {
        //ya tienes una que se llama así
        res.status(404).json({
            message: 'Already a category with that name'
        })
    }
};

//obtiene las categorias del usuario en cuestion.
const getCat = async (req,res) => {
    //cojo nombre del usuario del token que me pasa.
    const usuarioPrincipal = req.usuario;
    //miro si tiene una categoria con ese nombre
    const resp =
    await conexion.query('SELECT nombrecat from categorias where (mail=$1)',[usuarioPrincipal]);
    //envío resultado a cliente
    res.status(200).json(resp.rows);
};

//añade una categoria del usuario a una contraseña.
const addCatToPasswd = async (req,res) => {
    //cojo nombre del usuario del token que me pasa.
    const usuarioPrincipal = req.usuario;
    //necesito el nombr de la categoria y de la contraseña.
    const {nombrecategoria,nombrePassword} = req.body;

    //miro si tiene una categoria con ese nombre
    const resp =
    await conexion.query('SELECT * from categorias where (mail=$1 AND nombrecat=$2)',[usuarioPrincipal,nombrecategoria]);

    if (resp.rowCount==0) {
        //no existe categoria con ese nombre para ese user
        res.status(404).json({
            message: 'no existe categoria con ese nombre para ese user'
        })

    }
    else {
        //puedo asignarla
        //del nombre de la contraseña que me pasen me fío, pero compruebo aun así.
        const resp =
        await conexion.query('UPDATE contrasenya SET categoria=$1 where (nombre=$2 AND email=$3)',[nombrecategoria,nombrePassword,usuarioPrincipal]);

        if (resp.rowCount>0)
            res.status(200).json({
                message: 'Password´s category updated correctly'
            })
        else {
            res.status(404).json({
                message: 'No password with that name for the user'
            })
        }
    }
};

//elimina categoria y obviamente, pone a null el campo "categoria" de las
//contraseñas pertenecientes a esa categoria.
const deleteCat = async (req,res) => {
    //cojo nombre del usuario del token que me pasa.
    const usuarioPrincipal = req.usuario;
    const {nombrecategoria} = req.body;
    //miro si tiene una categoria con ese nombre
    const resp =
    await conexion.query('SELECT * from categorias where (mail=$1 AND nombrecat=$2)',[usuarioPrincipal,nombrecategoria]);

    if (resp.rowCount==0) {
        //ninguna categoria llamada de esa manera
        res.status(404).json({
            message: 'No category with that name to be deleted'
        })

    }
    else {
        //quito la categoria de las contraseñas que la tenian
        const resp =
        await conexion.query('UPDATE contrasenya SET categoria=$1 where (categoria=$2 AND email=$3)',[null,nombrecategoria,usuarioPrincipal]);
        //elimino la categoria para ese user
        const resp2 =
        await conexion.query('DELETE from categorias where (mail=$1 AND nombrecat=$2)',[usuarioPrincipal,nombrecategoria]);
        res.status(200).json({
            message: 'Category deleted'
        })
    }
};

//obtiene las contraseñas asociadas a la categoria x del usuario.
const filterCat = async (req,res) => {
    //cojo nombre del usuario del token que me pasa.
    const usuarioPrincipal = req.usuario;
    //cojo el nombre de la categoria que pasan como QUERY paramter.
    let nombrecategoria = req.query.nombrecategoria;
    //** no miro si tiene una categoria con ese nombre ** (me fio de front que
    //le de para seleccionar solo entre las que el user tenga)

    console.log(usuarioPrincipal + " " + nombrecategoria);
    const resp =
    await conexion.query('SELECT nombre,tipo from contrasenya where (email=$1 AND categoria=$2)',[usuarioPrincipal,nombrecategoria]);
    console.log(resp);
    //envío al cliente el JSON con las passwds que tiene ese user
    res.status(200).json(resp.rows);
};

// -------------- IMÁGENES --------------

//añado una imagen al usuario
const addPic = async (req,res) => {
    //cojo nombre del usuario del token que me pasa.
    const usuarioPrincipal = req.usuario;
    //el tipo será una imagen
    const tipo = "imagen";
    //cojo el resto de atributos que me interesan
    const {
        body: {nombre,categoria,fechacreacion,fechacaducidad}
    }=req;

    console.log(nombre+' '+categoria+' '+fechacreacion+' '+fechacaducidad)

    //comprobamos si ya tiene una imagen con ese nombre
    const hasFileAlready =
    await conexion.query('SELECT * FROM contrasenya WHERE (email=$1 and nombre=$2)', [usuarioPrincipal,nombre]);

    if (hasFileAlready.rowCount==0) {
        //leo los datos del fichero para meterlo en base de datos
        const fichero = fs.readFileSync(path.join(__dirname, '../images/' + req.file.filename))
        //cifro los datos del fichero
        const encrypted_passwd = encryptFile(fichero);

        //hacemos la inserción. QUEDA COMPROBAR QUE NO TENGA ESA IMAGEN YA.
        const resp =
        await conexion.query('INSERT INTO contrasenya (email,tipo,fichero,categoria,fechacreacion,fechacaducidad,nombre) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [usuarioPrincipal,tipo,encrypted_passwd,categoria,fechacreacion,fechacaducidad,nombre]);

        // Delete the file like normal
        fs.unlink(req.file.path, (err) => {
            if (err) {
            console.error(err)
            return
            }
            //file removed
        })

        //respondo a cliente
        res.json({
            message : 'ok'
        })
    }
    else {
        //error. Ya hay una pic con ese nombre
        res.json({
            message : 'no ok'
        })
    }
};

//obtengo la imagen de nombre x para el usuario y
const getPic = async (req,res) => {
    //cojo nombre del usuario del token que me pasa.
    const usuarioPrincipal = req.usuario;
    //cojo el nombre de la imaen que el quiere
    let nombre = req.query.nombre;

    //seleccionamos la imagen del usuario e intentamos sacar los bytes.
    const resp = 
    await conexion.query('SELECT nombre,fichero,categoria,fechacaducidad,fechacreacion FROM contrasenya WHERE (email=$1 and nombre=$2 and tipo=$3)', [usuarioPrincipal,nombre,'imagen']);

    if (resp.rowCount==0) {
        //ninguna contraseña con ese nombre
        res.status(404).json({
            message : 'no ok'
        })
    }
    else {
        //obtengo el contenido del fichero (cifrado)
        var ficheroCifrado = resp.rows[0].fichero;
        //descifro el contenido
        const ficheroPlano = decryptFile(ficheroCifrado);

        //reconstruyo la pic con los datos para ver si realmente rula
        fs.writeFileSync(path.join(__dirname, '../../imagesdb/' + resp.rows[0].nombre + '.jpg'), ficheroPlano)

        //respondo a cliente
        var respuesta = resp.rows[0].nombre+'.jpg'
        res.status(200).json({
            nombreImagen : respuesta,
            categoria : resp.rows[0].categoria,
            fechacaducidad : resp.rows[0].fechacaducidad,
            fechacreacion : resp.rows[0].fechacreacion
        })
    }
};

//deleteo una imagen
const deletePic = async (req,res) => {
    //cojo nombre del usuario del token que me pasa.
    const usuarioPrincipal = req.usuario;
    //cojo el nombre de la imaen que el quiere
    const {nombre} = req.body;

    //seleccionamos la imagen del usuario e intentamos sacar los bytes.
    const resp =
    await conexion.query('SELECT nombre,fichero FROM contrasenya WHERE (email=$1 and nombre=$2 and tipo=$3)', [usuarioPrincipal,nombre,'imagen']);

    if (resp.rowCount==0) {
        //ninguna contraseña con ese nombre
        res.status(404).json({
            message : 'No pic with that name bruh. Chill it.'
        })
    }
    else {
        const resp =
        await conexion.query('DELETE FROM contrasenya WHERE (email=$1 and nombre=$2 and tipo=$3)', [usuarioPrincipal,nombre,'imagen']);

        //respondo a cliente
        res.status(200).json({
            message:'Pic deleted bruh.'
        })
    }
};

//actualizo una imagen
const editPic = async (req,res) => {
    //cojo nombre del usuario del token que me pasa.
    const usuarioPrincipal = req.usuario;
    //el tipo será una imagen
    const tipo = "imagen";
    //cojo el resto de atributos que me interesan
    const {
        body: {nuevoNombre,categoria,fechacreacion,fechacaducidad,nombreAntiguo,actualizaImagen}
    }=req;

    console.log(nuevoNombre+' '+categoria+' '+fechacreacion+' '+fechacaducidad+' '+nombreAntiguo)

    //comprobamos si ya tiene una imagen con ese nombre
    const hasFileAlready =
    await conexion.query('SELECT * FROM contrasenya WHERE (email=$1 and nombre=$2)', [usuarioPrincipal,nuevoNombre]);

    if (hasFileAlready.rowCount==0 || nombreAntiguo==nuevoNombre) {
        if (actualizaImagen=='si') {
            //leo los datos del fichero para meterlo en base de datos
            const fichero = fs.readFileSync(path.join(__dirname, '../images/' + req.file.filename))
            //cifro los datos del fichero
            const encrypted_passwd = encryptFile(fichero);

            //hacemos la inserción. QUEDA COMPROBAR QUE NO TENGA ESA IMAGEN YA.
            const resp =
            await conexion.query('UPDATE contrasenya SET categoria=$1, fechacreacion=$2, fechacaducidad=$3, fichero=$4, nombre=$5 where (nombre=$6 and email=$7)',
            [categoria,fechacreacion,fechacaducidad,encrypted_passwd,nuevoNombre,nombreAntiguo,usuarioPrincipal]);

            // Delete the file like normal
            fs.unlink(req.file.path, (err) => {
                if (err) {
                console.error(err)
                return
                }
                //file removed
            })
        }
        else {
            const resp =
            await conexion.query('UPDATE contrasenya SET categoria=$1, fechacreacion=$2, fechacaducidad=$3, nombre=$4 where (nombre=$5 and email=$6)',
            [categoria,fechacreacion,fechacaducidad,nuevoNombre,nombreAntiguo,usuarioPrincipal]);
        }

        //respondo a cliente
        res.json({
            message : 'ok'
        })
    }
    else {
        //error. Ya hay una pic con ese nombre
        res.json({
            message : 'no ok'
        })
    }
};

//metodo auxiliar para saber cuando eliminar foto de la carpeta (NO DE LA BD)
const aux = async (req,res) => {
    //cojo nombre del usuario del token que me pasa.
    const usuarioPrincipal = req.usuario;
    //cojo el nombre de la imaen que el quiere
    const {nombreImagen} = req.body;
    //eliminamos la foto que nos pasa el user
    const pathToFile = path.join(__dirname, '../../imagesdb/')
    const pathFinal = path.join(pathToFile,nombreImagen)
    //unlinkear las imagenes
    fs.unlink(pathFinal, (err) => {
        if (err) {
            console.error(err)
            res.json({
                message : 'ok'
            })
        }
        else {
            console.log("Image deleted succesfully from fs")
            res.json({
                message : 'no ok'
            })
        }
        
    }) 
};

//método para devolver todas las imágenes al front
const getPicWeb = async (req,res) => {
    //cojo nombre del usuario del token que me pasa.
    const usuarioPrincipal = req.usuario;
    //cojo los parametros de ordenacion que me pasan en la QUERY
    let ordenarPor = req.query.ordenarPor;  //nombre, fechacreacion ó fechacaducidad
    let ordenarDe = req.query.ordenarDe;    //ASC o DESC
    //let elemento = req.query.elemento;      //¿Qué quiere front que le pase?

    //NO DEJA USAR ORDER BY $1. Hay que hacerlo manualmente.
    var resp;
    switch(ordenarPor) {
        case "nombre":
            if (ordenarDe=="ASC") {
                resp =
                await conexion.query('SELECT nombre,fichero,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 and tipo=$2 ORDER BY nombre ASC',[usuarioPrincipal,'imagen']);
            }
            else {
                resp =
                await conexion.query('SELECT nombre,fichero,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 and tipo=$2 ORDER BY nombre DESC',[usuarioPrincipal,'imagen']);
            }
        break;

        case "fechacreacion":
            if (ordenarDe=="ASC") {
                resp =
                await conexion.query('SELECT nombre,fichero,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 and tipo=$2 ORDER BY fechacreacion ASC',[usuarioPrincipal,'imagen']);
            }
            else {
                resp =
                await conexion.query('SELECT nombre,fichero,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 and tipo=$2 ORDER BY fechacreacion DESC',[usuarioPrincipal,'imagen']);
            }
        break;

        case "fechacaducidad":
            if (ordenarDe=="ASC") {
                resp =
                await conexion.query('SELECT nombre,fichero,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 and tipo=$2 ORDER BY fechacaducidad ASC',[usuarioPrincipal,'imagen']);
            }
            else {
                resp =
                await conexion.query('SELECT nombre,fichero,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 and tipo=$2 ORDER BY fechacaducidad DESC',[usuarioPrincipal,'imagen']);
            }
        break;

        case "categoria":
            if (ordenarDe=="ASC") {
                resp =
                await conexion.query('SELECT nombre,fichero,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 and tipo=$2 ORDER BY categoria ASC',[usuarioPrincipal,'imagen']);
            }
            else {
                resp =
                await conexion.query('SELECT nombre,fichero,fechacreacion,fechacaducidad,categoria from contrasenya where email=$1 and tipo=$2 ORDER BY categoria DESC',[usuarioPrincipal,'imagen']);
            }
        break;

    }

    //reconstruyo la pic con los datos para ver si realmente rula
    resp.rows.map( fila => {
        fs.writeFileSync(path.join(__dirname, '../../imagesdb/' + fila.nombre + '.jpg'), decryptFile(fila.fichero))
    })

    console.log(resp.rows)
    
    res.status(200).json(resp.rows);
    
};

// -------------- FICHEROS --------------

//añado un ficherito
const addFile = async (req,res) => {
    //cojo nombre del usuario del token que me pasa.
    const usuarioPrincipal = req.usuario;
    //el tipo será una imagen
    const tipo = "file";
    //cojo el resto de atributos que me interesan
    const {
        body: {nombre,categoria,fechacreacion,fechacaducidad}
    }=req;

    console.log(nombre+' '+categoria+' '+fechacreacion+' '+fechacaducidad)

    //comprobamos si ya tiene una imagen con ese nombre
    const hasFileAlready =
    await conexion.query('SELECT * FROM contrasenya WHERE (email=$1 and nombre=$2)', [usuarioPrincipal,nombre]);

    if (hasFileAlready.rowCount==0) {
        //leo los datos del fichero para meterlo en base de datos
        const fichero = fs.readFileSync(path.join(__dirname, '../files/' + req.file.filename))
        //cifro los datos del fichero
        const encrypted_passwd = encryptFile(fichero);

        //hacemos la inserción. QUEDA COMPROBAR QUE NO TENGA ESE FICHERO YA.
        const resp =
        await conexion.query('INSERT INTO contrasenya (email,tipo,fichero,categoria,fechacreacion,fechacaducidad,nombre) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [usuarioPrincipal,tipo,encrypted_passwd,categoria,fechacreacion,fechacaducidad,nombre]);

        // Delete the file like normal
        fs.unlink(req.file.path, (err) => {
            if (err) {
            console.error(err)
            return
            }
            //file removed
        })

        //respondo a cliente
        res.json({
            message : 'ok'
        })
    }
    else {
        //error. Ya hay una pic con ese nombre
        res.json({
            message : 'no ok'
        })
    }
};

//cojo un fichero
const getFile = async (req,res) => {
    //cojo nombre del usuario del token que me pasa.
    const usuarioPrincipal = req.usuario;
    //cojo el nombre de la imaen que el quiere
    let nombre = req.query.nombre;

    //seleccionamos la imagen del usuario e intentamos sacar los bytes.
    const resp = 
    await conexion.query('SELECT nombre,fichero,categoria,fechacaducidad,fechacreacion FROM contrasenya WHERE (email=$1 and nombre=$2 and tipo=$3)', [usuarioPrincipal,nombre,'file']);

    if (resp.rowCount==0) {
        //ninguna contraseña con ese nombre
        res.status(404).json({
            message : 'no ok'
        })
    }
    else {
        //obtengo el contenido del fichero (cifrado)
        var ficheroCifrado = resp.rows[0].fichero;
        //descifro el contenido
        const ficheroPlano = decryptFile(ficheroCifrado);

        //reconstruyo la pic con los datos para ver si realmente rula
        fs.writeFileSync(path.join(__dirname, '../../filesdb/' + resp.rows[0].nombre + '.pdf'), ficheroPlano)

        //respondo a cliente
        var respuesta = resp.rows[0].nombre+'.pdf'
        res.status(200).json({
            nombreImagen : respuesta,
            categoria : resp.rows[0].categoria,
            fechacaducidad : resp.rows[0].fechacaducidad,
            fechacreacion : resp.rows[0].fechacreacion
        })
    }
};

//edito un fichero
const editFile = async (req,res) => {
    //cojo nombre del usuario del token que me pasa.
    const usuarioPrincipal = req.usuario;
    //el tipo será una imagen
    const tipo = "file";
    //cojo el resto de atributos que me interesan
    const {
        body: {nuevoNombre,categoria,fechacreacion,fechacaducidad,nombreAntiguo,actualizaImagen}
    }=req;

    console.log(nuevoNombre+' '+categoria+' '+fechacreacion+' '+fechacaducidad+' '+nombreAntiguo)

    //comprobamos si ya tiene una imagen con ese nombre
    const hasFileAlready =
    await conexion.query('SELECT * FROM contrasenya WHERE (email=$1 and nombre=$2)', [usuarioPrincipal,nuevoNombre]);

    if (hasFileAlready.rowCount==0 || nombreAntiguo==nuevoNombre) {
        if (actualizaImagen=='si') {
            //leo los datos del fichero para meterlo en base de datos
            const fichero = fs.readFileSync(path.join(__dirname, '../files/' + req.file.filename))
            //cifro los datos del fichero
            const encrypted_passwd = encryptFile(fichero);

            //hacemos la inserción. QUEDA COMPROBAR QUE NO TENGA ESA IMAGEN YA.
            const resp =
            await conexion.query('UPDATE contrasenya SET categoria=$1, fechacreacion=$2, fechacaducidad=$3, fichero=$4, nombre=$5 where (nombre=$6 and email=$7)',
            [categoria,fechacreacion,fechacaducidad,encrypted_passwd,nuevoNombre,nombreAntiguo,usuarioPrincipal]);

            // Delete the file like normal
            fs.unlink(req.file.path, (err) => {
                if (err) {
                console.error(err)
                return
                }
                //file removed
            })
        }
        else {
            const resp =
            await conexion.query('UPDATE contrasenya SET categoria=$1, fechacreacion=$2, fechacaducidad=$3, nombre=$4 where (nombre=$5 and email=$6)',
            [categoria,fechacreacion,fechacaducidad,nuevoNombre,nombreAntiguo,usuarioPrincipal]);
        }

        //respondo a cliente
        res.json({
            message : 'ok'
        })
    }
    else {
        //error. Ya hay una pic con ese nombre
        res.json({
            message : 'no ok'
        })
    }
};

//edito una categoría
const editCat = async (req,res) => {
    //edito la categoría del usuario X.
    //todas las contraseñas con tenían esa categoría, ahora tienen la nueva
    const usuarioPrincipal = req.usuario;
    const {nomCatAntigua, nomCatNueva} = req.body;

    //actualizamos el nombre de la categoría en la tabla categorías
    const aux = await conexion.query('UPDATE categorias SET nombrecat=$1 where (mail=$2 and nombrecat=$3)',[nomCatNueva,usuarioPrincipal,nomCatAntigua]);
    
    //le cambiamos la categoría a aquellas passwords que la tenían
    const aux2 = await conexion.query('UPDATE contrasenya SET categoria=$1 where (email=$2 and categoria=$3)',[nomCatNueva,usuarioPrincipal,nomCatAntigua]);

    res.json ({
        message : 'ok'
    })
};

//aquí simplemente digo que exporto las funciones aquí definidas para que
//se puedan usar en el módulo de index.js (routes)
module.exports = {
    userLogin,
    userSignin,
    userRemove,
    userChangePw,
    pruebilla,
    addpwtoUser,
    getPasswdsUser,
    detailsPasswd,
    deletepasswd,
    editpasswd,
    addCat,
    getCat,
    addCatToPasswd,
    deleteCat,
    filterCat,
    addPic,
    getPic,
    deletePic,
    editPic,
    aux,
    getPicWeb,
    addFile,
    editCat,
    getFile,
    editFile
}
