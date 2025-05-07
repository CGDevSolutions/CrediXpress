const { app } = require('@azure/functions');
const sql = require('mssql');
const crypto = require('crypto');

// Configuración de conexión
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

const pool = new sql.ConnectionPool(dbConfig);
const poolConnect = pool.connect();

app.post('login', {
    authLevel: 'anonymous',
    handler: async (request, context) => {
        context.log('Proceso de login iniciado');
        
        try {
            const { usuario, contrasena } = await request.json();
            
            if (!usuario?.trim() || !contrasena?.trim()) {
                return {
                    status: 400,
                    jsonBody: {
                        success: false,
                        message: "Usuario y contraseña son requeridos"
                    }
                };
            }

            await poolConnect;
            
            // Consulta ajustada para la tabla Usuarios (con mayúscula)
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
                context.log(`Usuario no encontrado: ${usuario}`);
                return {
                    status: 401,
                    jsonBody: {
                        success: false,
                        message: "Usuario no encontrado o inactivo"
                    }
                };
            }

            const user = result.recordset[0];
            
            // Verificación de contraseña (ajustar según tu método de almacenamiento)
            const hashedInput = crypto.createHash('sha256').update(contrasena).digest('hex');
            if (user.password !== hashedInput) {
                context.log(`Contraseña incorrecta para usuario: ${usuario}`);
                return {
                    status: 401,
                    jsonBody: {
                        success: false,
                        message: "Contraseña incorrecta"
                    }
                };
            }

            context.log(`Login exitoso para: ${user.username}`);
            
            return {
                status: 200,
                jsonBody: {
                    success: true,
                    token: generateToken(user),
                    userData: {
                        id: user.id,
                        nombre: user.nombre,
                        email: user.email,
                        rol: user.rol
                    }
                }
            };
            
        } catch (error) {
            context.error('Error en login:', error);
            return {
                status: 500,
                jsonBody: {
                    success: false,
                    message: "Error en el servidor",
                    debug: process.env.NODE_ENV === 'development' ? error.message : undefined
                }
            };
        }
    }
});

// Función para generar token JWT básico
function generateToken(user) {
    const payload = {
        sub: user.id,
        name: user.nombre,
        role: user.rol,
        email: user.email,
        exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hora de expiración
    };
    
    // En producción, usa: jsonwebtoken.sign(payload, process.env.JWT_SECRET)
    return Buffer.from(JSON.stringify(payload)).toString('base64');
}
