const {Router} = require('express');
const {check} = require('express-validator');
const {crearUsuario, loginUsuario, validarUsuario} = require('../controllers/auth');
const {validarCampos} = require('../middlewares/validar-campos');
const { validarJWT } = require('../middlewares/validar-jwt');

const router = Router();

router.post('/new', [
    check('name', 'El nombre es obligatorio').not().isEmpty(),
    check('email', 'El email es obligatorio').isEmail(),
    check('password', 'La contrtaseña es obligatorio').isLength({min: 6}),
    validarCampos
], crearUsuario);

//Login de usuario
router.post('/', [
    check('email', 'El email es obligatorio').isEmail(),
    check('password', 'La contrtaseña es obligatorio').isLength({min: 6}),
    validarCampos
], loginUsuario);

//Validar usuario
router.get('/renew', validarJWT, validarUsuario);


module.exports = router;