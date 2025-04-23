const sql = require('mssql');

// Configuración de la conexión a la base de datos
const dbConfig = {
  user: 'sqladmin',
  password: 'Carlosflowc08',
  server: 'bdprestamos.database.windows.net',
  database: 'PrestamosDB', // Asumo este nombre, ajústalo si es diferente
  options: {
    encrypt: true, // Necesario para Azure SQL
    enableArithAbort: true
  }
};

module.exports = async function (context, req) {
    const { usuario, contrasena } = req.body;

    // Validación básica
    if (!usuario || !contrasena) {
        return context.res = {
            status: 400,
            body: {
                success: false,
                message: "Usuario y contraseña son requeridos"
            },
            headers: {
                'Content-Type': 'application/json'
            }
        };
    }

    let pool;
    try {
        // Crear conexión a la base de datos
        pool = await sql.connect(dbConfig);
        
        // Consulta para verificar credenciales
        const result = await pool.request()
            .input('usuario', sql.NVarChar, usuario)
            .input('contrasena', sql.NVarChar, contrasena)
            .query(`
                SELECT id, nombre, rol 
                FROM usuarios 
                WHERE usuario = @usuario AND contrasena = @contrasena
            `);

        // Verificar si se encontró el usuario
        if (result.recordset.length > 0) {
            const user = result.recordset[0];
            
            return context.res = {
                status: 200,
                body: {
                    success: true,
                    usuario: user.nombre || usuario,
                    rol: user.rol || 'usuario',
                    token: generateToken(user.id) // Función para generar token
                },
                headers: {
                    'Content-Type': 'application/json'
                }
            };
        } else {
            return context.res = {
                status: 401,
                body: {
                    success: false,
                    message: 'Credenciales incorrectas'
                },
                headers: {
                    'Content-Type': 'application/json'
                }
            };
        }
    } catch (error) {
        context.log.error('Error en la autenticación:', error);
        
        return context.res = {
            status: 500,
            body: {
                success: false,
                message: 'Error en el servidor al autenticar'
            },
            headers: {
                'Content-Type': 'application/json'
            }
        };
    } finally {
        // Cerrar la conexión si existe
        if (pool) {
            await pool.close();
        }
    }
};

// Función simple para generar token (mejorar en producción)
function generateToken(userId) {
    return Buffer.from(`${userId}|${Date.now()}`).toString('base64');
}
