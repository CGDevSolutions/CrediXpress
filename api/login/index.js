const { app } = require('@azure/functions');

app.post('login', {
    authLevel: 'anonymous',
    handler: async (request, context) => {
        try {
            const { usuario, contrasena } = await request.json();
            
            if (!usuario || !contrasena) {
                return {
                    status: 400,
                    body: JSON.stringify({
                        success: false,
                        message: "Usuario y contraseña son requeridos"
                    }),
                    headers: {
                        'Content-Type': 'application/json'
                    }
                };
            }

            // Aquí iría tu lógica de conexión a la base de datos
            // Este es un ejemplo simulado:
            const isValid = usuario === "admin" && contrasena === "admin123";
            
            return {
                status: isValid ? 200 : 401,
                body: JSON.stringify({
                    success: isValid,
                    message: isValid ? "Autenticación exitosa" : "Credenciales incorrectas",
                    token: isValid ? "simulated-token-12345" : null,
                    usuario: isValid ? usuario : null,
                    rol: isValid ? "admin" : null
                }),
                headers: {
                    'Content-Type': 'application/json'
                }
            };

        } catch (error) {
            context.error('Error en el login:', error);
            return {
                status: 500,
                body: JSON.stringify({
                    success: false,
                    message: "Error interno del servidor"
                }),
                headers: {
                    'Content-Type': 'application/json'
                }
            };
        }
    }
});
