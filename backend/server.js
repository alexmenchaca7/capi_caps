const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcryptjs');

const app = express();
const port = 8080;

// --- Configuración de Multer ---
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadsDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// --- INICIO DE LA CORRECCIÓN DE CORS ---
const corsOptions = {
    origin: 'http://localhost:4200',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'], // 'PATCH' AÑADIDO
    allowedHeaders: ['Content-Type', 'Authorization', 'x-user-id'], // 'x-user-id' AÑADIDO
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
// --- FIN DE LA CORRECCIÓN DE CORS ---

app.use(express.json());
app.use('/uploads', express.static(uploadsDir));

// --- Conexión a Base de Datos ---
const dbConfig = {
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'ecommerce',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};
const pool = mysql.createPool(dbConfig);

async function verificarConexionDB() {
    try {
        const connection = await pool.getConnection();
        console.log('Conectado exitosamente a la base de datos MySQL (pool).');
        connection.release();
    } catch (error) {
        console.error('Error CRÍTICO al conectar con la base de datos MySQL (pool):', error.message || error);
        process.exit(1);
    }
}
verificarConexionDB();

// Función de validación de contraseña
function validarContrasena(contrasena) {
    if (contrasena.length < 8) return false;
    if (!/[A-Z]/.test(contrasena)) return false;
    if (!/[a-z]/.test(contrasena)) return false;
    if (!/[0-9]/.test(contrasena)) return false;
    return true;
}

// --- Middleware de autenticación ---
function requireAuth(req, res, next) {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ message: 'Autenticación requerida' });
    }
    
    req.userId = parseInt(userId);
    next();
}


// --- RUTAS API ---  //

// --- RUTAS DE AUTENTICACIÓN SIMPLIFICADAS ---
app.post('/api/auth/registro', async (req, res) => {
  console.log('POST /api/auth/registro - Recibido:', req.body);
  const { nombre, apellido, username, correo, telefono, contrasena } = req.body;
  
  if (!nombre || !apellido || !username || !correo || !contrasena) { // Teléfono es opcional
    return res.status(400).json({ message: 'Nombre, apellido, nombre de usuario, correo y contraseña son requeridos.' });
  }
  if (contrasena.length < 6) {
      return res.status(400).json({ message: 'La contraseña debe tener al menos 6 caracteres.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo)) {
      return res.status(400).json({ message: 'Formato de correo inválido.' });
  }
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) { // Validación básica para username
      return res.status(400).json({ message: 'Nombre de usuario inválido (3-20 caracteres alfanuméricos y guion bajo).' });
  }
  if (!validarContrasena(contrasena)) {
        return res.status(400).json({ message: 'La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número.' });
  }

  try {
    // Verificar si el correo o username ya existen
    const [usuariosExistentes] = await pool.query(
      'SELECT id FROM usuarios WHERE correo = ? OR username = ?',
      [correo, username]
    );
    if (usuariosExistentes.length > 0) {
      // Determinar qué campo está duplicado para un mensaje más específico (opcional)
      const existingUser = usuariosExistentes[0]; // Asumimos que la query podría devolver más si ambos coinciden con diferentes usuarios
      const isCorreoDup = existingUser.correo === correo; // Esto es una simplificación, la query ya previene esto si son diferentes usuarios
      const isUsernameDup = existingUser.username === username; // Simplificación
      // Mejor: consultar por separado o analizar el resultado de la query combinada
      const [correoCheck] = await pool.query('SELECT id FROM usuarios WHERE correo = ?', [correo]);
      if (correoCheck.length > 0) {
          return res.status(409).json({ message: 'El correo electrónico ya está registrado.' });
      }
      const [usernameCheck] = await pool.query('SELECT id FROM usuarios WHERE username = ?', [username]);
      if (usernameCheck.length > 0) {
          return res.status(409).json({ message: 'El nombre de usuario ya está en uso.' });
      }
      // Si llegamos aquí después de las verificaciones individuales, algo es raro, pero el OR inicial debería haberlo capturado.
      // Mantenemos un mensaje genérico si la lógica OR es suficiente.
      // return res.status(409).json({ message: 'El correo electrónico o nombre de usuario ya está registrado.' });
    }

    const salt = await bcrypt.genSalt(10);
    const contrasenaHasheada = await bcrypt.hash(contrasena, salt);

    const [resultado] = await pool.query(
      'INSERT INTO usuarios (nombre, apellido, username, correo, telefono, contrasena, rol) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [nombre, apellido, username, correo, telefono || null, contrasenaHasheada, 'cliente'] // telefono puede ser null
    );

    res.status(201).json({ message: 'Usuario registrado exitosamente.', usuarioId: resultado.insertId });
  } catch (error) {
    console.error('Error en /api/auth/registro:', error);
    if (error.code === 'ER_DUP_ENTRY') { // Código de error de MySQL para entradas duplicadas
        if (error.message.includes('correo')) {
            return res.status(409).json({ message: 'El correo electrónico ya está registrado.' });
        } else if (error.message.includes('username')) {
            return res.status(409).json({ message: 'El nombre de usuario ya está en uso.' });
        }
    }
    res.status(500).json({ message: 'Error interno del servidor al registrar.' });
  }
});

app.post('/api/auth/login', async (req, res) => {

  const { loginIdentifier, contrasena } = req.body; // Intento de desestructurar

  if (!loginIdentifier || !contrasena) {
    console.log('BACKEND VALIDACIÓN FALLÓ: loginIdentifier o contrasena es falsy.');
    return res.status(400).json({ message: 'Identificador de inicio de sesión y contraseña son requeridos.' });
  }

  try {
    // Intentar encontrar al usuario por correo O por username
    const [usuarios] = await pool.query(
            'SELECT * FROM usuarios WHERE correo = ? OR username = ?',
            [loginIdentifier, loginIdentifier]
    );

    if (usuarios.length === 0) {
        return res.status(401).json({ message: 'Credenciales inválidas.' });
    }

    const usuario = usuarios[0];
    const esContrasenaValida = await bcrypt.compare(contrasena, usuario.contrasena);

    if (!esContrasenaValida) {
        console.log('BACKEND LOGIN: Contraseña incorrecta para:', loginIdentifier);
        return res.status(401).json({ message: 'Credenciales inválidas.' });
    }
    
    // Restablecer intentos al iniciar sesión correctamente
    await pool.query(
        'UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?',
        [usuario.id]
    );

    const { contrasena: _, ...usuarioParaEnviar } = usuario;
    
    res.json({
        message: 'Inicio de sesión exitoso.',
        usuario: usuarioParaEnviar
    });
  } catch (error) {
    console.error('BACKEND LOGIN: Error en el bloque try-catch:', error);
    res.status(500).json({ message: 'Error interno del servidor durante el login.' });
  }
});

app.post('/api/auth/recuperar-simple', async (req, res) => {
  console.log('POST /api/auth/recuperar-simple - Recibido:', req.body);
  // Permitir recuperación por correo o username
  const { loginIdentifier, nuevaContrasena } = req.body;

  if (!loginIdentifier || !nuevaContrasena) {
    return res.status(400).json({ message: 'Identificador (correo/username) y nueva contraseña son requeridos.' });
  }
  if (!validarContrasena(nuevaContrasena)) {
        return res.status(400).json({ message: 'La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número.' });
  }

  try {
    const [usuarios] = await pool.query(
        'SELECT id FROM usuarios WHERE correo = ? OR username = ?',
        [loginIdentifier, loginIdentifier]
    );

    if (usuarios.length === 0) {
      return res.status(404).json({ message: 'El correo electrónico o nombre de usuario no se encuentra registrado.' });
    }

    const usuarioId = usuarios[0].id; // Tomar el ID del primer usuario encontrado

    const salt = await bcrypt.genSalt(10);
    const contrasenaHasheada = await bcrypt.hash(nuevaContrasena, salt);

    const [resultadoUpdate] = await pool.query(
      'UPDATE usuarios SET contrasena = ? WHERE id = ?', // Actualizar por ID es más seguro
      [contrasenaHasheada, usuarioId]
    );

    if (resultadoUpdate.affectedRows > 0) {
      console.log('Contraseña actualizada exitosamente para el usuario ID:', usuarioId);
      res.status(200).json({ message: 'Contraseña actualizada exitosamente. Ya puedes iniciar sesión con tu nueva contraseña.' });
    } else {
      console.error('Error inesperado: Usuario encontrado pero no se pudo actualizar la contraseña para ID:', usuarioId);
      res.status(500).json({ message: 'Error al actualizar la contraseña.' });
    }
  } catch (error) {
    console.error('Error en /api/auth/recuperar-simple:', error);
    res.status(500).json({ message: 'Error interno del servidor al recuperar la contraseña.' });
  }
});

// Endpoint "actualizar-contrasena-admin" (sin cambios respecto a tu versión, es conceptual)
app.put('/api/auth/actualizar-contrasena-admin/:idUsuarioAModificar', async (req, res) => {
    const { idUsuarioAModificar } = req.params;
    const { nuevaContrasena, correoAdmin /*, contrasenaAdmin */ } = req.body;
    if (correoAdmin !== 'admin@example.com') {
        return res.status(403).json({ message: 'No autorizado.' });
    }
    if (!nuevaContrasena || nuevaContrasena.length < 6) {
        return res.status(400).json({ message: 'Nueva contraseña inválida.' });
    }
    try {
        const salt = await bcrypt.genSalt(10);
        const contrasenaHasheada = await bcrypt.hash(nuevaContrasena, salt);
        const [resultado] = await pool.query('UPDATE usuarios SET contrasena = ? WHERE id = ?', [contrasenaHasheada, idUsuarioAModificar]);
        if (resultado.affectedRows === 0) return res.status(404).json({ message: 'Usuario a modificar no encontrado.' });
        res.json({ message: `Contraseña actualizada para usuario ID ${idUsuarioAModificar}` });
    } catch (error) {
        console.error('Error actualizando contraseña admin:', error);
        res.status(500).json({ message: 'Error actualizando contraseña.' });
    }
});

app.post('/api/auth/solicitar-recuperacion', async (req, res) => {
    const { loginIdentifier } = req.body;
    const token = crypto.randomBytes(32).toString('hex');
    const expiracion = new Date(Date.now() + 30 * 60000); // 30 minutos
    
    // ... buscar usuario ...
    await pool.query(
        'INSERT INTO tokens_recuperacion (usuario_id, token, expiracion) VALUES (?, ?, ?)',
        [usuario.id, token, expiracion]
    );
    
    // Enviar correo con enlace (pseudocódigo)
    enviarCorreo(usuario.correo, `${BASE_URL}/recuperar?token=${token}`);
    res.json({ message: 'Enlace de recuperación enviado' });
});


// --- RUTAS DE PRODUCTOS Y ARCHIVOS (como las tenías, usando pool.query) ---
app.post('/api/upload', upload.single('file'), (req, res) => {
  console.log('--- Petición a POST /api/upload recibida ---');
  if (req.file) {
    console.log('Archivo recibido:', req.file.filename);
    const filePath = `uploads/${req.file.filename}`;
    res.json({ path: filePath });
  } else {
    console.log('No se recibió ningún archivo en /api/upload.');
    res.status(400).json({ message: 'No se subió ningún archivo.' });
  }
});

app.delete('/api/files/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(uploadsDir, filename);
  fs.unlink(filePath, (err) => {
    if (err) {
      if (err.code === 'ENOENT') return res.status(404).json({ message: 'Archivo no encontrado.' });
      console.error('Error eliminando archivo:', err);
      return res.status(500).json({ message: 'Error al eliminar archivo.' });
    }
    res.status(200).json({ message: 'Archivo eliminado exitosamente.' });
  });
});

app.get('/api/productos', async (req, res) => {
  console.log('GET /api/productos - Obteniendo productos en stock.');
  try {
    const [productos] = await pool.query('SELECT * FROM productos WHERE cantidad > 0');
    res.json(productos);
  } catch (err) {
    console.error('Error al obtener los productos desde /api/productos:', err);
    res.status(500).json({ message: 'Error en el servidor al obtener productos.' });
  }
});


// NUEVA RUTA DE STOCK
app.patch('/api/productos/:id/stock', async (req, res) => {
    const { id } = req.params;
    const { cantidadAfectada, operacion } = req.body; // operacion: 'sumar' o 'restar'

    if (typeof cantidadAfectada !== 'number' || !['sumar', 'restar'].includes(operacion)) {
        return res.status(400).json({ message: 'Se requiere una cantidad y una operación (sumar/restar) válidas.' });
    }

    const operator = operacion === 'restar' ? '-' : '+';
    const query = `UPDATE productos SET cantidad = cantidad ${operator} ? WHERE id = ?`;

    try {
        if (operacion === 'restar') {
            const [productos] = await pool.query('SELECT cantidad FROM productos WHERE id = ?', [id]);
            if (productos.length === 0) {
                return res.status(404).json({ message: 'Producto no encontrado.' });
            }
            if (productos[0].cantidad < cantidadAfectada) {
                return res.status(409).json({ message: 'No hay suficiente stock disponible.' });
            }
        }

        const [result] = await pool.query(query, [cantidadAfectada, id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Producto no encontrado para actualizar stock.' });
        }
        res.json({ message: 'Stock actualizado correctamente.' });
    } catch (error) {
        console.error(`Error al actualizar stock para producto ${id}:`, error);
        res.status(500).json({ message: 'Error interno al actualizar el stock.' });
    }
});


app.get('/api/productos/:id', async (req, res) => {
  const { id } = req.params;
  console.log(`GET /api/productos/${id} - Solicitud recibida`);
  try {
    const [results] = await pool.query('SELECT * FROM productos WHERE id = ?', [id]);
    if (results.length === 0) return res.status(404).json({ message: 'Producto no encontrado' });
    console.log(`GET /api/productos/${id} - Enviando producto.`);
    res.json(results[0]);
  } catch (err) {
    console.error(`GET /api/productos/${id} - Error en DB:`, err);
    return res.status(500).json({ message: 'Error al obtener el producto', error: err.message });
  }
});

app.post('/api/productos', async (req, res) => {
  const { nombre, cantidad, precio, imagen } = req.body;
  if (!nombre || cantidad === undefined || precio === undefined) {
    return res.status(400).json({ message: 'Nombre, cantidad y precio son requeridos.' });
  }
  console.log('POST /api/productos - Datos recibidos:', req.body);
  try {
    const [results] = await pool.query(
      'INSERT INTO productos (nombre, cantidad, precio, imagen) VALUES (?, ?, ?, ?)',
      [nombre, Number(cantidad), Number(precio), imagen || null]
    );
    console.log('POST /api/productos - Producto creado con ID:', results.insertId);
    res.status(201).json({ id: results.insertId, nombre, cantidad: Number(cantidad), precio: Number(precio), imagen });
  } catch (err) {
    console.error('POST /api/productos - Error en DB:', err);
    res.status(500).json({ message: 'Error al crear producto', error: err.message });
  }
});

app.put('/api/productos/:id', async (req, res) => {
  const { id } = req.params;
  const { nombre, cantidad, precio, imagen } = req.body;
  console.log(`PUT /api/productos/${id} - Datos recibidos:`, req.body);
  if (!nombre || cantidad === undefined || precio === undefined) {
    return res.status(400).json({ message: 'Nombre, cantidad y precio son requeridos para la actualización.' });
  }
  try {
    const [results] = await pool.query(
      'UPDATE productos SET nombre = ?, cantidad = ?, precio = ?, imagen = ? WHERE id = ?',
      [nombre, Number(cantidad), Number(precio), imagen, id]
    );
    if (results.affectedRows === 0) {
      return res.status(404).json({ message: 'Producto no encontrado para actualizar' });
    }
    console.log(`PUT /api/productos/${id} - Producto actualizado.`);
    const [updatedProductRows] = await pool.query('SELECT * FROM productos WHERE id = ?', [id]);
    res.json(updatedProductRows[0] || { id: Number(id), nombre, cantidad: Number(cantidad), precio: Number(precio), imagen });
  } catch (err) {
    console.error(`PUT /api/productos/${id} - Error en DB:`, err);
    res.status(500).json({ message: 'Error al actualizar producto', error: err.message });
  }
});

app.delete('/api/productos/:id', async (req, res) => {
  const { id } = req.params;
  console.log(`DELETE /api/productos/${id} - Solicitud recibida`);
  try {
    const [results] = await pool.query('DELETE FROM productos WHERE id = ?', [id]);
    if (results.affectedRows === 0) {
      return res.status(404).json({ message: 'Producto no encontrado para eliminar' });
    }
    console.log(`DELETE /api/productos/${id} - Producto eliminado.`);
    res.json({ message: 'Producto eliminado exitosamente' });
  } catch (err) {
    console.error(`DELETE /api/productos/${id} - Error en DB:`, err);
    res.status(500).json({ message: 'Error al eliminar producto', error: err.message });
  }
});

// Rutas para el inventario (ahora protegida)
app.get('/api/inventario', async (req, res) => { 
  console.log('GET /api/inventario - Obteniendo todo el inventario.');
  try {
    const [inventario] = await pool.query('SELECT * FROM productos');
    res.json(inventario);
  } catch (err) {
    console.error('Error al obtener el inventario desde /api/inventario:', err);
    res.status(500).json({ message: 'Error en el servidor al obtener el inventario.' });
  }
});

// Obtener el carrito de un usuario
app.get('/api/carrito', requireAuth, async (req, res) => {
    try {
        const [carrito] = await pool.query(
            'SELECT c.id as carritoId, c.cantidad as cantidadEnCarrito, p.id as producto_id, p.nombre, p.precio, p.imagen, p.cantidad as stock ' +
            'FROM carrito c ' +
            'JOIN productos p ON c.producto_id = p.id ' +
            'WHERE c.usuario_id = ?',
            [req.userId]
        );
        res.json(carrito);
    } catch (error) {
        console.error('Error al obtener carrito:', error);
        res.status(500).json({ message: 'Error al obtener carrito' });
    }
});

// Agregar un producto al carrito (usado por agregarProducto en el servicio)
app.post('/api/carrito', requireAuth, async (req, res) => {
    const { producto_id, cantidad } = req.body;
    if (!producto_id || cantidad === undefined) {
        return res.status(400).json({ message: 'producto_id y cantidad son requeridos' });
    }

    try {
        const [existing] = await pool.query(
            'SELECT id, cantidad FROM carrito WHERE usuario_id = ? AND producto_id = ?',
            [req.userId, producto_id]
        );

        if (existing.length > 0) {
            const newQuantity = existing[0].cantidad + cantidad;
            await pool.query('UPDATE carrito SET cantidad = ? WHERE id = ?', [newQuantity, existing[0].id]);
            res.json({ message: 'Cantidad actualizada en el carrito' });
        } else {
            await pool.query('INSERT INTO carrito (usuario_id, producto_id, cantidad) VALUES (?, ?, ?)', [req.userId, producto_id, cantidad]);
            res.status(201).json({ message: 'Producto agregado al carrito' });
        }
    } catch (error) {
        console.error('Error al agregar al carrito:', error);
        res.status(500).json({ message: 'Error al agregar producto al carrito' });
    }
});

// Actualizar cantidad y stock (usado por actualizarCantidad en el servicio)
app.put('/api/carrito/actualizar-cantidad', requireAuth, async (req, res) => {
    const { carritoId, nuevaCantidad } = req.body;
    const usuario_id = req.userId;

    if (!carritoId || nuevaCantidad === undefined || nuevaCantidad < 1) {
        return res.status(400).json({ message: 'Se requieren el ID del ítem y una nueva cantidad válida.' });
    }

    try {
        const [result] = await pool.query(
            'UPDATE carrito SET cantidad = ? WHERE id = ? AND usuario_id = ?',
            [nuevaCantidad, carritoId, usuario_id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Ítem del carrito no encontrado o no pertenece al usuario.' });
        }

        res.json({ message: 'Cantidad del carrito actualizada.' });

    } catch (error) {
        console.error('Error al actualizar la cantidad del carrito:', error);
        res.status(500).json({ message: 'Error en el servidor al actualizar la cantidad.' });
    }
});


// Eliminar un producto del carrito (OJO: esta ruta puede ser necesaria para el futuro)
app.delete('/api/carrito/:id', requireAuth, async (req, res) => {
    const carritoId = req.params.id;
    try {
        const [result] = await pool.query('DELETE FROM carrito WHERE id = ? AND usuario_id = ?', [carritoId, req.userId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Ítem no encontrado en el carrito' });
        }
        res.json({ message: 'Producto eliminado del carrito' });
    } catch (error) {
        console.error('Error al eliminar del carrito:', error);
        res.status(500).json({ message: 'Error al eliminar producto del carrito' });
    }
});

app.delete('/api/carrito', requireAuth, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM carrito WHERE usuario_id = ?',
      [req.userId]
    );
    res.json({ message: 'Carrito vaciado' });
  } catch (error) {
    console.error('Error al vaciar carrito:', error);
    res.status(500).json({ message: 'Error al vaciar carrito' });
  }
});


// Manejador para rutas no encontradas (404)
app.use((req, res, next) => {
  console.log(`404 Not Found: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ message: `La ruta ${req.originalUrl} no fue encontrada en el servidor.` });
});

// Manejador de errores global
app.use((err, req, res, next) => {
  console.error("Error global en el servidor:", err); // Loguear el error completo puede ser útil
  res.status(500).json({ message: 'Ocurrió un error inesperado en el servidor.', error: err.message });
});

app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
  console.log(`Directorio de subidas de imágenes: ${uploadsDir}`);
  console.log(`Imágenes servidas desde: http://localhost:${port}/uploads`);
});