const { app } = require('@azure/functions');
const sql = require('mssql');
const bcrypt = require('bcryptjs');

// Configuración de conexión (usa variables de entorno)
const sqlConfig = {
    user: process.env.DB_USER || 'sqladmin',
    password: process.env.DB_PASSWORD || 'Carlosflowc08',
    server: process.env.DB_SERVER || 'bdprestamos.database.windows.net',
    database: process.env.DB_NAME || 'bd_prestamos',
    options: {
        encrypt: true,
        trustServerCertificate: false
    }
};

app.http('login', {
    methods: ['POST'],
    route: 'auth/login',
    authLevel: 'anonymous',
    handler: async (request, context) => {
        context.log('Procesando solicitud de login...');
        
        // Configuración CORS
        const corsSettings = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type"
        };

        // Manejar preflight (CORS)
        if (request.method === 'OPTIONS') {
            return { 
                status: 204,
                headers: corsSettings
            };
        }

        try {
            const body = await request.json();
            const { usuario, contrasena } = body;

            if (!usuario || !contrasena) {
                return {
                    status: 400,
                    jsonBody: { success: false, message: "Usuario y contraseña son requeridos" },
                    headers: corsSettings
                };
            }

            let pool = await sql.connect(sqlConfig);
            const result = await pool.request()
                .input('nombre_usuario', sql.NVarChar(50), usuario)
                .query('SELECT id, nombre_usuario, contrasena, rol FROM Usuarios WHERE nombre_usuario = @nombre_usuario');

            if (result.recordset.length === 0) {
                return {
                    status: 401,
                    jsonBody: { success: false, message: "Usuario no encontrado" },
                    headers: corsSettings
                };
            }

            const user = result.recordset[0];
            
            // Comparar contraseñas con bcrypt
            const passwordMatch = await bcrypt.compare(contrasena, user.contrasena);
            
            if (!passwordMatch) {
                return {
                    status: 401,
                    jsonBody: { success: false, message: "Credenciales incorrectas" },
                    headers: corsSettings
                };
            }

            // Generar token JWT (opcional)
            const token = generateJWT(user); // Implementa esta función

            return {
                status: 200,
                jsonBody: { 
                    success: true,
                    token: token,
                    usuario: user.nombre_usuario,
                    rol: user.rol
                },
                headers: {
                    ...corsSettings,
                    'Content-Type': 'application/json'
                }
            };

        } catch (error) {
            context.log('Error en login:', error);
            return {
                status: 500,
                jsonBody: { success: false, message: "Error interno del servidor" },
                headers: corsSettings
            };
        }
    }
});

// Función para generar JWT (ejemplo)
function generateJWT(user) {
    // Implementación real debería usar jsonwebtoken
    return `simulated-jwt-for-${user.id}`;
}
