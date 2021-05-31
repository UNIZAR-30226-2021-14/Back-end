//definimos las rutas, las URLs que va a tener nuestro servidor
const {  Router } = require('express');
const router = Router();

//JWT
const jwt = require('jsonwebtoken');
const config = require('../../env/config');

//cojo la función de getUsers del fichero controllers.
const {userLogin, userSignin, userRemove, userChangePw, pruebilla, addpwtoUser, deletepasswd, getPasswdsUser,detailsPasswd, editpasswd,
    addCat,addCatToPasswd,getCat,deleteCat,filterCat,addPic,deletePic,getPic,editPic,aux,getPicWeb,addFile,editCat,getFile,editFile} = require('../controllers/index_controllers_users');

//middleware para comprobar token
/*function rutasProtegidas(req, res, next) {
    //me aseguro que front envíe en la cabecera el token
    const token = req.headers['access-token'];
        
    if (token) {
        //si manda token, verifico que es correcto
        jwt.verify(token, router.get(config.llave_token), (err, decoded) => {      
        if (err) {
            return res.json({ mensaje: 'Token inválida' });    
        } 
        else {
            req.decoded = decoded;   
            console.log("TOKEN BUENOOOOOOOOO"); 
            next();
        }
        });
    } 
    else {
    //caso de que no mande el token
        res.send({ 
            mensaje: 'Token no proveída.' 
        });
    }
};*/

//MIDDLEWARE.
const rutasProtegidas = (req, res, next) => {
    //cojo la cabecera authorization, donde está el el token
    const authHeader = req.headers.authorization;
    //si existe esa cabecera
    if (authHeader) {
        //quito lo de Bearer, palabra que se pone automáticamente en las peticiones HTTP
        const token = authHeader.split(' ')[1];
        //verifico el token que me mandan
        jwt.verify(token, config.llave_token, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            //dejo en la varibale req.user el nombre de usuario de la persona
            //que me ha pasado el token.
            req.usuario = user.username;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};

//página de inicio (nadie va a hacer get aquí)
router.get('/', (req, res) => {
    res.send('Fresh tech API running...');
})

//pequeña prueba
//se ejecutará la función pruebilla despues de haberse ejecutado
//la función de autenticación rutasProtegidas (valida token)
router.get('/prueba',rutasProtegidas,pruebilla);   

// -------------- USERS --------------

//LOGIN. 
router.post('/login',userLogin);  

//SIGNIN.
router.post('/signin',userSignin);  

//DELETE ACCOUNT.
router.delete('/removeAccount',rutasProtegidas,userRemove);

//CHANGE PASSWORD. (cambia la pw una vez logueado)
router.post('/changepw',rutasProtegidas,userChangePw);


// -------------- PASSWORDS --------------

//almacenamos una contraseña para un usuario
router.post('/passwd',rutasProtegidas,addpwtoUser);

//sacamos el nombre de todas las contraseñas asociadas a un usuario en concreto 
router.get('/passwdUser',rutasProtegidas,getPasswdsUser);

//sacamos los detalles de una contraseña 
router.get('/detailspasswd',rutasProtegidas,detailsPasswd);

//eliminar una contraseña
router.delete('/deletepasswd',rutasProtegidas,deletepasswd);

//editar una contraseña
router.post('/editpasswd',rutasProtegidas,editpasswd);


// -------------- CATEGORIES --------------

//almacenamos una categoria para un usuario
router.post('/addcat',rutasProtegidas,addCat);

//asignarle a una contraseña una categoria ya creada por el user
router.post('/catpasswd',rutasProtegidas,addCatToPasswd);

//obtenemos las contraseñas del usuario
router.get('/getcat',rutasProtegidas,getCat);

//obtenemos las contraseñas del usuario
router.delete('/deletecat',rutasProtegidas,deleteCat);

//filtramos por categoria en específico
router.get('/filtercat',rutasProtegidas,filterCat);

// -------------- IMÁGENES --------------
const multer = require('multer');
const path = require('path');
const diskstorage = multer.diskStorage ({
    destination: path.join(__dirname, '../images'),
    filename : (req,file,cb) => {
        //forma en la que se guarda la imagen (nombre)
        cb(null, Date.now() + '-' + file.originalname)
    }
})

// single('image') es importante. pongo 'image' porq es el nombre que pone
// el front al hacer el formdata.append('image',file)
const fileUpload = multer({
    storage:diskstorage
}).single('image');

router.post('/addPic',rutasProtegidas,fileUpload,addPic);

router.get('/getPic',rutasProtegidas,getPic);

router.delete('/deletePic',rutasProtegidas,deletePic);

router.post('/editPic',rutasProtegidas,fileUpload,editPic);

router.post('/aux',rutasProtegidas,aux);

router.get('/getPicWeb',rutasProtegidas,getPicWeb);

// -------------- FICHEROS --------------
const diskstorageFile = multer.diskStorage ({
    destination: path.join(__dirname, '../files'),
    filename : (req,file,cb) => {
        //forma en la que se guarda la imagen (nombre)
        cb(null, Date.now() + '-' + file.originalname)
    }
})

const fileUpload2 = multer({
    storage:diskstorageFile
}).single('file');

router.post('/addFile',rutasProtegidas,fileUpload2,addFile)

router.post('/editCat',rutasProtegidas,editCat)

router.get('/getFile',rutasProtegidas,fileUpload2,getFile)

router.post('/editFile',rutasProtegidas,fileUpload2,editFile);

module.exports = router;