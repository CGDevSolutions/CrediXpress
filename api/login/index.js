const { app } = require('@azure/functions');
const sql = require('mssql');

const config = {
    user: 'sqladmin',
    password: 'Carlosflowc08',
    server: 'bdprestamos.database.windows.net',
    database: 'tu_nombre_bd',
    options: {
        encrypt: true // Necesario para Azure
    }
};

app.http('login', {
    methods: ['POST'],
    authLevel: 'anonymous',
    handler: async (request, context) => {
        context.log('Login function processed a request.');

        try {
            const requestBody = await request.json();
            const { usuario, password } = requestBody;

            await sql.connect(config);
            const result = await sql.query`SELECT * FROM Usuarios WHERE usuario = ${usuario}`;
            
            if (result.recordset.length === 0) {
                return {
                    status: 401,
                    jsonBody: { success: false, message: "Usuario no encontrado" }
                };
            }

            const user = result.recordset[0];
            
            // En producción, usa bcrypt para comparar contraseñas hasheadas
            if (user.password !== password) {
                return {
                    status: 401,
                    jsonBody: { success: false, message: "Contraseña incorrecta" }
                };
            }

            return {
                status: 200,
                jsonBody: { 
                    success: true,
                    usuario: user.usuario,
                    rol: user.rol
                }
            };
        } catch (error) {
            context.log('Error:', error);
            return {
                status: 500,
                jsonBody: { success: false, message: "Error interno del servidor" }
            };
        }
    }
});
