module.exports = async function (context, req) {
    const { usuario, password } = req.body;

    // Validación sencilla (puedes reemplazar esto con verificación en BD)
    if (usuario === 'admin' && password === '1234') {
        return context.res = {
            status: 200,
            body: {
                success: true,
                usuario: 'admin',
                rol: 'admin',
                token: 'demo-token-1234'
            }
        };
    }

    return context.res = {
        status: 401,
        body: {
            success: false,
            message: 'Credenciales incorrectas'
        }
    };
};
