//definimos las rutas, las URLs que va a tener nuestro servidor
const {  Router } = require('express');
const router = Router();

//JWT
const jwt = require('jsonwebtoken');
const config = require('../../env/config');

//cojo la función de getUsers del fichero controllers.
const {userLogin, userSignin, userRemove, pruebilla, addpwtoUser, getPasswdsUser,detailsPasswd,addCat,addCatToPasswd,getCat,deleteCat} = 
    require('../controllers/index_controllers_users');

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


// -------------- PASSWORDS --------------

//almacenamos una contraseña para un usuario
router.post('/passwd',rutasProtegidas,addpwtoUser);

//sacamos el nombre de todas las contraseñas asociadas a un usuario en concreto 
router.get('/passwdUser',rutasProtegidas,getPasswdsUser);

//sacamos los detalles de una contraseña 
router.get('/detailspasswd',rutasProtegidas,detailsPasswd);


// -------------- CATEGORIES --------------
//almacenamos una categoria para un usuario
router.post('/addcat',rutasProtegidas,addCat);

//asignarle a una contraseña una categoria ya creada por el user
router.post('/catpasswd',rutasProtegidas,addCatToPasswd);

//obtenemos las contraseñas del usuario
router.get('/getcat',rutasProtegidas,getCat);

//obtenemos las contraseñas del usuario
router.delete('/deletecat',rutasProtegidas,deleteCat);


module.exports = router;