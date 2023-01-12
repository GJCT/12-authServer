const {response} = require('express');
const Usuario = require('../models/Usuario');
const bcrypt = require('bcryptjs');
const { generarJWT } = require('../helpers/jwt');

const crearUsuario = async(req, resp = response)=>{

    const {email, name, password} = req.body;

    try {
            
    //Unico correo
        const usuario = await Usuario.findOne({email});

        if(usuario){
            return resp.status(400).json({
                ok: false,
                msg: 'Email ya registrado'
            })
        }

    //Usuario modelo
        const dbUser = new Usuario(req.body);

    //Encriptar pass
        const salt = bcrypt.genSaltSync();
        dbUser.password = bcrypt.hashSync(password, salt);

    //Generar JWT
        const token = await generarJWT(dbUser.id, name);

    //Crear User BD
        await dbUser.save();

    //Respuesta 
        return resp.status(201).json({
            ok: true,
            uid: dbUser.id,
            name,
            email,
            token
        });
        
    } catch (error) {
        return resp.status(500).json({
            ok: false,
            msg: 'Por favor comuniquese con el admin'
        });
    }
    
};

//Login Usuario
const loginUsuario = async(req, res = response)=>{

    const {email, password} = req.body;

    try {
        const dbUser = await Usuario.findOne({email});
        if(!dbUser){
            return res.status(400).json({
                ok:false,
                msg: 'El correo no existe'
            });
        }
        
        //Validar pass
        const validPass = bcrypt.compareSync(password, dbUser.password);
        if(!validPass){
            return res.status(400).json({
                ok:false,
                msg: 'La contraseña no son iguales'
            });
        }

        //Generar JWT
        const token = await generarJWT(dbUser.id, dbUser.name);
        
        //Respuesta
        res.json({
            ok: true,
            uid: dbUser.id,
            name: dbUser.name,
            email: dbUser.email,
            token
        });
        
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            ok: false,
            msg: 'Comuniquese con el admin'
        });
    }
    // return res.json({
    //     ok: true,
    //     msg: 'Login usuario /'
    // });
};

//Validar usuario
const validarUsuario = async(req, resp = response)=>{

    const {uid} = req;

    //Leer BD
    const dbUser = await Usuario.findById(uid);
    
    //Generar JWT
    const token = await generarJWT(uid, dbUser.name);

    return resp.json({
        ok: true,
        uid,
        name: dbUser.name,
        email: dbUser.email,
        token
    });
};


module.exports = {
    crearUsuario,
    loginUsuario,
    validarUsuario
}