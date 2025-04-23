const { app } = require('@azure/functions');
const sql = require('mssql');

const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER,
    database: process.env.DB_NAME,
    options: {
        encrypt: true,
        trustServerCertificate: false
    }
};

app.post('login', {
    authLevel: 'anonymous',
    handler: async (request, context) => {
        context.log('Iniciando proceso de login...');
        
        try {
            const { usuario, contrasena } = await request.json();
            context.log(`Intento de login para usuario: ${usuario}`);
            
            if (!usuario || !contrasena) {
                context.log('Faltan credenciales');
                return {
                    status: 400,
                    jsonBody: {
                        success: false,
                        message: "Usuario y contraseña son requeridos"
                    }
                };
            }

            context.log('Conectando a la base de datos...');
            await sql.connect(dbConfig);
            
            context.log('Ejecutando consulta SQL...');
            const result = await sql.query`
                SELECT u.*, r.nombre as rol 
                FROM usuarios u
                JOIN roles r ON u.rol_id = r.id
                WHERE u.username = ${usuario} 
                AND u.password = CONVERT(VARCHAR(32), HashBytes('MD5', ${contrasena}), 2)
                AND u.activo = 1
            `;
            
            if (result.recordset.length > 0) {
                const user = result.recordset[0];
                context.log(`Usuario autenticado: ${user.username}`);
                
                return {
                    status: 200,
                    jsonBody: {
                        success: true,
                        token: "simulated-token-12345",
                        usuario: user.username,
                        rol: user.rol,
                        userData: {
                            nombre: user.nombre,
                            email: user.email
                        }
                    }
                };
            } else {
                context.log('Credenciales incorrectas');
                return {
                    status: 401,
                    jsonBody: {
                        success: false,
                        message: "Usuario o contraseña incorrectos"
                    }
                };
            }
        } catch (error) {
            context.error('ERROR EN EL LOGIN:', error);
            return {
                status: 500,
                jsonBody: {
                    success: false,
                    message: "Error interno del servidor",
                    debug: process.env.NODE_ENV === 'development' ? error.message : undefined
                }
            };
        } finally {
            await sql.close();
        }
    }
});
