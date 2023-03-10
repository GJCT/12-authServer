const { jwt } = require('jsonwebtoken')
require('dotenv').config();

const generarJWT = (uid, name) => {

    const payload = {uid, name};

    return new Promise((resolve, reject) => {
        jwt(payload, process.env.SECRET_JWT_SEED, {
                expiresIn: '2h'
            }, (err, token)=> {
                if(err){
                    console.log(err);
                    reject(err);
                }else{
                    resolve(token);
                }
        });
    });
}


module.exports = {
    generarJWT
}