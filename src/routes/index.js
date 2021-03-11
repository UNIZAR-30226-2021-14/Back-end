//definimos las rutas, las URLs que va a tener nuestro servidor
const {  Router } = require('express');
const router = Router();

//cojo la función de getUsers del fichero controllers.
const { getUsers, addUser, removeUser, pruebilla, addpwtoUser, getPasswdsUser, verifyUser,detailsPasswd} = 
    require('../controllers/index_controllers_user');

//dependiendo del tipo de peticion (get,post...) a la ruta dada, ejecutaré 
//una función u otra, importadas del módulo controllers

//pequeña prueba
router.get('/prueba',pruebilla);

//get sirve para coger datos, coger usuarios. 
router.get('/users',getUsers);

//post es para guardar datos, guardar usuarios. 
router.post('/users',addUser);

//delete es para eliminar datos
router.delete('/users',removeUser);

//almacenamos una contraseña para un usuario
router.post('/passwd',addpwtoUser)

//sacamos el nombre de todas las contraseñas asociadas a un usuario en concreto 
router.get('/passwdUser',getPasswdsUser)

//verificar que el usuario está en BD
router.get('/verify', verifyUser);

//sacamos los detalles de una contraseña 
router.get('/detailspasswd',detailsPasswd)

module.exports = router;