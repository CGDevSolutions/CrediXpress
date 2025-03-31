const { app } = require('@azure/functions');
const sql = require('mssql');

// Configuración de la conexión a tu Azure SQL Database
const sqlConfig = {
    user: 'sqladmin',
    password: 'Carlosflowc08',
    server: 'bdprestamos.database.windows.net',
    database: 'tu_nombre_bd', // Reemplaza con el nombre real de tu BD
    options: {
        encrypt: true, // Necesario para Azure
        trustServerCertificate: false // Necesario para Azure
    }
};

app.http('login', {
    methods: ['POST'],
    route: 'login',
    authLevel: 'anonymous',
    handler: async (request, context) => {
        context.log('Procesando solicitud de login...');

        try {
            const body = await request.json();
            const { usuario, password } = body;

            if (!usuario || !password) {
                return {
                    status: 400,
                    jsonBody: {
                        success: false,
                        message: "Usuario y contraseña son requeridos"
                    }
                };
            }

            let pool = await sql.connect(sqlConfig);
            const result = await pool.request()
                .input('usuario', sql.NVarChar(50), usuario)
                .query('SELECT id, usuario, password, rol FROM Usuarios WHERE usuario = @usuario');

            if (result.recordset.length === 0) {
                return {
                    status: 401,
                    jsonBody: {
                        success: false,
                        message: "Usuario no encontrado"
                    }
                };
            }

            const user = result.recordset[0];
            
            // En producción real, usa bcrypt.compareSync(password, user.password)
            if (password !== user.password) {
                return {
                    status: 401,
                    jsonBody: {
                        success: false,
                        message: "Contraseña incorrecta"
                    }
                };
            }

            // Login exitoso
            return {
                status: 200,
                jsonBody: {
                    success: true,
                    usuario: user.usuario,
                    rol: user.rol,
                    message: "Login exitoso"
                }
            };

        } catch (error) {
            context.log('Error en login:', error);
            return {
                status: 500,
                jsonBody: {
                    success: false,
                    message: "Error interno del servidor"
                }
            };
        } finally {
            sql.close(); // Cerrar conexión
        }
    }
});
