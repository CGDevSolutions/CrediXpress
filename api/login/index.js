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
    methods: ['POST', 'OPTIONS'],
    authLevel: 'anonymous',
    handler: async (request, context) => {
        // Configuración CORS
        const corsHeaders = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type"
        };

        if (request.method === 'OPTIONS') {
            return { status: 204, headers: corsHeaders };
        }

        try {
            const body = await request.json();
            const { usuario, password } = body;

            if (!usuario || !password) {
                return {
                    status: 400,
                    jsonBody: { success: false, message: "Usuario y contraseña requeridos" },
                    headers: corsHeaders
                };
            }

            await sql.connect(sqlConfig);
            const result = await sql.query`SELECT * FROM Usuarios WHERE usuario = ${usuario}`;

            if (result.recordset.length === 0) {
                return {
                    status: 401,
                    jsonBody: { success: false, message: "Usuario no encontrado" },
                    headers: corsHeaders
                };
            }

            const user = result.recordset[0];
            
            // Comparación de contraseña (en producción usa bcrypt)
            if (user.password !== password) {
                return {
                    status: 401,
                    jsonBody: { success: false, message: "Contraseña incorrecta" },
                    headers: corsHeaders
                };
            }

            return {
                status: 200,
                jsonBody: {
                    success: true,
                    usuario: user.usuario,
                    rol: user.rol,
                    message: "Login exitoso"
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
