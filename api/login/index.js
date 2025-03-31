const { app } = require('@azure/functions');
const sql = require('mssql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Configuración de la base de datos (usa variables de entorno)
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

// Configuración JWT (debería estar en variables de entorno)
const JWT_SECRET = process.env.JWT_SECRET || 'tu_super_secreto_jwt';
const JWT_EXPIRES_IN = '8h';

app.http('login', {
    methods: ['POST'],
    route: 'auth/login',
    authLevel: 'anonymous',
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
            const { usuario, contrasena } = body;

            // Validación de entrada
            if (!usuario || !contrasena) {
                return {
                    status: 400,
                    jsonBody: { 
                        success: false, 
                        message: "Usuario y contraseña son requeridos" 
                    },
                    headers: corsHeaders
                };
            }

            // Conectar a la base de datos
            const pool = await sql.connect(sqlConfig);
            const result = await pool.request()
                .input('nombre_usuario', sql.NVarChar(50), usuario)
                .query(`
                    SELECT id, nombre_usuario, contrasena, rol 
                    FROM Usuarios 
                    WHERE nombre_usuario = @nombre_usuario
                `);

            // Verificar si el usuario existe
            if (result.recordset.length === 0) {
                return {
                    status: 401,
                    jsonBody: { 
                        success: false, 
                        message: "Credenciales incorrectas" 
                    },
                    headers: corsHeaders
                };
            }

            const user = result.recordset[0];
            
            // Comparar contraseñas hasheadas
            const passwordMatch = await bcrypt.compare(contrasena, user.contrasena);
            
            if (!passwordMatch) {
                return {
                    status: 401,
                    jsonBody: { 
                        success: false, 
                        message: "Credenciales incorrectas" 
                    },
                    headers: corsHeaders
                };
            }

            // Generar token JWT
            const token = jwt.sign(
                {
                    id: user.id,
                    usuario: user.nombre_usuario,
                    rol: user.rol
                },
                JWT_SECRET,
                { expiresIn: JWT_EXPIRES_IN }
            );

            // Respuesta exitosa
            return {
                status: 200,
                jsonBody: { 
                    success: true,
                    token: token,
                    usuario: user.nombre_usuario,
                    rol: user.rol,
                    message: "Inicio de sesión exitoso"
                },
                headers: {
                    ...corsHeaders,
                    'Content-Type': 'application/json'
                }
            };

        } catch (error) {
            context.log('Error en el login:', error);
            return {
                status: 500,
                jsonBody: { 
                    success: false, 
                    message: "Error interno del servidor" 
                },
                headers: corsHeaders
            };
        } finally {
            // Cerrar conexión a la base de datos
            await sql.close();
        }
    }
});
