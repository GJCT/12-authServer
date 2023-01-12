const express = require('express');
const cors = require('cors');
const path = require('path');

const { dbConnection } = require('./db/config');
const { response } = require('express');
require('dotenv').config();

//Crear el servidor/App de express
const app = express();

//Base de datos
dbConnection();

//Directorio Publico
app.use(express.static('public'));

// CORS
app.use(cors());

//Lectura y parseo del body
app.use(express.json());

//Rutas
app.use('/api/auth', require('./routes/auth'));

//Manejar rutas
// app.get('*', (req, resp = response)=>{
//     resp.sendFile(path.resolve(__dirname, 'public/index.html'))
// })

app.listen(process.env.PORT, ()=>{
    console.log(`Servidor corriendo en puerto ${process.env.PORT}`);
});