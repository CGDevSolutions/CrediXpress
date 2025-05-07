const { app } = require('@azure/functions');
const sql = require('mssql');
const crypto = require('crypto');

// Configuración mejorada para Azure SQL
const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    database: process.env.DB_NAME,
    options: {
        encrypt: true,
        trustServerCertificate: false,
        connectTimeout: 15000,
        requestTimeout: 15000
    },
    pool: {
        max: 10,
        min: 0,
        idleTimeoutMillis: 30000
    }
};

// Pool de conexiones global
const pool = new sql.ConnectionPool(dbConfig);
const poolConnect = pool.connect();

app.post('login', {
    authLevel: 'anonymous',
    handler: async (request, context) => {
        context.log('Iniciando proceso de login...');
        
        try {
            // Verificar cuerpo de la petición
            if (!request.body) {
                return {
                    status: 400,
                    jsonBody: {
                        success: false,
                        message: "Datos de login no proporcionados"
                    },
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    }
                };
            }

            const { usuario, contrasena } = await request.json();
            
            // Validación básica
            if (!usuario?.trim() || !contrasena?.trim()) {
                return {
                    status: 400,
                    jsonBody: {
                        success: false,
                        message: "Usuario y contraseña son requeridos"
                    },
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    }
                };
            }

            await poolConnect; // Usar conexión existente
            
            // Consulta segura con parámetros
            const result = await pool.request()
                .input('username', sql.NVarChar, usuario.trim())
                .query(`
                    SELECT U.*, R.nombre as rol 
                    FROM Usuarios U
                    JOIN Roles R ON U.rol_id = R.id
                    WHERE U.username = @username
                    AND U.activo = 1
                `);

            if (result.recordset.length === 0) {
                return {
                    status: 401,
                    jsonBody: {
                        success: false,
                        message: "Usuario no encontrado o inactivo"
                    },
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    }
                };
            }

            const user = result.recordset[0];
            
            // Verificar contraseña (SHA-256)
            const hashedInput = crypto.createHash('sha256').update(contrasena).digest('hex');
            if (user.password !== hashedInput) {
                return {
                    status: 401,
                    jsonBody: {
                        success: false,
                        message: "Contraseña incorrecta"
                    },
                    headers: {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    }
                };
            }

            // Generar respuesta exitosa
            return {
                status: 200,
                jsonBody: {
                    success: true,
                    token: "simulated-jwt-token", // En producción usar jsonwebtoken
                    usuario: user.username,
                    rol: user.rol,
                    userData: {
                        nombre: user.nombre,
                        email: user.email
                    }
                },
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            };
            
        } catch (error) {
            context.error('Error en el login:', error);
            
            return {
                status: 500,
                jsonBody: {
                    success: false,
                    message: "Error interno del servidor",
                    debug: process.env.NODE_ENV === 'development' ? error.message : undefined
                },
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            };
        }
    }
});

// Manejar CORS para OPTIONS
app.options('login', {
    authLevel: 'anonymous',
    handler: async (request, context) => {
        return {
            status: 204,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
            }
        };
    }
});
