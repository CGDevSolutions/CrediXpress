const { app } = require('@azure/functions');
const sql = require('mssql');

const sqlConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    database: process.env.DB_NAME,
    options: {
        encrypt: true,
        trustServerCertificate: false
    }
};

app.http('login', {
    methods: ['POST', 'OPTIONS'], // ¡Asegúrate que POST esté incluido!
    authLevel: 'anonymous',
    route: 'auth/login', // Esta línea es crucial
    handler: async (request, context) => {
        // Configuración CORS
        const corsHeaders = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type"
        };

        // Manejar solicitud OPTIONS para CORS
        if (request.method === 'OPTIONS') {
            return { 
                status: 204,
                headers: corsHeaders
            };
        }

        try {
            const body = await request.json();
            const { usuario, password } = body;

            // Validación de entrada
            if (!usuario || !password) {
                return {
                    status: 400,
                    jsonBody: { success: false, message: "Usuario y contraseña requeridos" },
                    headers: corsHeaders
                };
            }

            await sql.connect(sqlConfig);
            const result = await sql.query`SELECT * FROM Usuarios WHERE nombre_usuario = ${usuario}`;

            if (result.recordset.length === 0) {
                return {
                    status: 401,
                    jsonBody: { success: false, message: "Credenciales incorrectas" },
                    headers: corsHeaders
                };
            }

            const user = result.recordset[0];
            
            // Comparación de contraseña (en producción usa bcrypt)
            if (user.contrasena !== password) {
                return {
                    status: 401,
                    jsonBody: { success: false, message: "Credenciales incorrectas" },
                    headers: corsHeaders
                };
            }

            return {
                status: 200,
                jsonBody: {
                    success: true,
                    usuario: user.nombre_usuario,
                    rol: user.rol
                },
                headers: {
                    ...corsHeaders,
                    'Content-Type': 'application/json'
                }
            };

        } catch (error) {
            context.log('Error:', error);
            return {
                status: 500,
                jsonBody: { success: false, message: "Error interno del servidor" },
                headers: corsHeaders
            };
        } finally {
            await sql.close();
        }
    }
});
