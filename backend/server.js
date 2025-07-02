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
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'], 
    allowedHeaders: ['Content-Type', 'Authorization', 'x-user-id'],
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

function generarReciboXML(pedidoId, pagoId, total, detalles) {
    // Genera el detalle de los productos
    const itemsXML = detalles.map(item => `
        <Item>
            <ProductoID>${item.producto_id}</ProductoID>
            <Nombre>${item.nombre}</Nombre>
            <Cantidad>${item.cantidadEnCarrito}</Cantidad>
            <PrecioUnitario>${item.precio.toFixed(2)}</PrecioUnitario>
        </Item>`).join('');

    // Calcula el IVA (asumiendo 16% como ejemplo)
    const subtotal = total / 1.16;
    const iva = total - subtotal;

    // Estructura completa del XML
    return `<?xml version="1.0" encoding="UTF-8"?>
<Recibo>
    <Encabezado>
        <Tienda>CapiCaps</Tienda>
        <PedidoID>${pedidoId}</PedidoID>
        <TransaccionID>${pagoId}</TransaccionID>
        <Fecha>${new Date().toISOString()}</Fecha>
    </Encabezado>
    <Cuerpo>
        <Items>${itemsXML}
        </Items>
        <Totales>
            <Subtotal>${subtotal.toFixed(2)}</Subtotal>
            <IVA>${iva.toFixed(2)}</IVA>
            <TotalPagado>${total.toFixed(2)}</TotalPagado>
        </Totales>
    </Cuerpo>
</Recibo>`;
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

// --- Middleware de administrador ---
async function requireAdmin(req, res, next) {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ message: 'Autenticación requerida.' });
    }

    try {
        const [users] = await pool.query('SELECT rol FROM usuarios WHERE id = ?', [userId]);
        if (users.length === 0 || users[0].rol !== 'administrador') {
            return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
        }
        req.userId = parseInt(userId);
        next();
    } catch (error) {
        console.error('Error en middleware de administrador:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
}


// --- RUTAS API ---  //

// --- RUTAS DE AUTENTICACIÓN ---
app.post('/api/auth/registro', async (req, res) => {
    console.log('POST /api/auth/registro - Recibido:', req.body);
    const { nombre, apellido, username, correo, telefono, contrasena, confirmarContrasena } = req.body;

    // Validación de que todos los campos requeridos, incluyendo la confirmación, están presentes.
    if (!nombre || !apellido || !username || !correo || !contrasena || !confirmarContrasena) {
        return res.status(400).json({ message: 'Todos los campos, incluyendo la confirmación de contraseña, son requeridos.' });
    }

    // Validación de que las contraseñas coinciden.
    if (contrasena !== confirmarContrasena) {
        return res.status(400).json({ message: 'Las contraseñas no coinciden.' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo)) {
        return res.status(400).json({ message: 'Formato de correo inválido.' });
    }

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
        return res.status(400).json({ message: 'Nombre de usuario inválido (3-20 caracteres alfanuméricos y guion bajo).' });
    }

    if (!validarContrasena(contrasena)) {
        return res.status(400).json({ message: 'La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número.' });
    }

    try {
        // Verificar si el correo/username/telefono ya existen
        const [existingUsers] = await pool.query(
            'SELECT username, correo, telefono FROM usuarios WHERE username = ? OR correo = ? OR (telefono = ? AND telefono IS NOT NULL)',
            [username, correo, telefono]
        );

        if (existingUsers.length > 0) {
            if (existingUsers.some(u => u.username === username)) {
                return res.status(409).json({ message: 'El nombre de usuario ya está en uso.' });
            }
            if (existingUsers.some(u => u.correo === correo)) {
                return res.status(409).json({ message: 'El correo electrónico ya está registrado.' });
            }
            if (telefono && existingUsers.some(u => u.telefono === telefono)) {
                return res.status(409).json({ message: 'El número de teléfono ya está registrado.' });
            }
        }

        const salt = await bcrypt.genSalt(10);
        const contrasenaHasheada = await bcrypt.hash(contrasena, salt);

        const [resultado] = await pool.query(
            'INSERT INTO usuarios (nombre, apellido, username, correo, telefono, contrasena, rol) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [nombre, apellido, username, correo, telefono || null, contrasenaHasheada, 'cliente']
        );

        res.status(201).json({ message: 'Usuario registrado exitosamente.', usuarioId: resultado.insertId });
    } catch (error) {
        console.error('Error en /api/auth/registro:', error);
        if (error.code === 'ER_DUP_ENTRY') {
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

// Endpoint "actualizar-contrasena-admin"
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
  // Asegurarnos que la cantidad sea un número, incluso si es 0
  const cantidadNumerica = Number(cantidad);
  if (isNaN(cantidadNumerica) || cantidadNumerica < 0) {
    return res.status(400).json({ message: 'La cantidad debe ser un número no negativo.' });
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

// Crear un nuevo pedido
app.post('/api/pedidos', requireAuth, async (req, res) => {
    const { pago_id, detalles_pedido, total_pagado } = req.body;
    const usuario_id = req.userId;

    if (!pago_id || !detalles_pedido || total_pagado === undefined) {
        return res.status(400).json({ message: 'pago_id, detalles_pedido y total_pagado son requeridos.' });
    }
    if (!Array.isArray(detalles_pedido) || detalles_pedido.length === 0) {
        return res.status(400).json({ message: 'Los detalles del pedido deben ser un array con al menos un producto.' });
    }
    
    const connection = await pool.getConnection();

    try {
        await connection.beginTransaction();

        for (const item of detalles_pedido) {
            const [productos] = await connection.query('SELECT cantidad FROM productos WHERE id = ? FOR UPDATE', [item.producto_id]);
            if (productos.length === 0) throw new Error(`Producto con ID ${item.producto_id} no encontrado.`);
            
            const stockActual = productos[0].cantidad;
            if (stockActual < item.cantidadEnCarrito) {
                throw new Error(`Stock insuficiente para el producto "${item.nombre}". Solicitado: ${item.cantidadEnCarrito}, Disponible: ${stockActual}`);
            }

            const nuevoStock = stockActual - item.cantidadEnCarrito;
            await connection.query('UPDATE productos SET cantidad = ? WHERE id = ?', [nuevoStock, item.producto_id]);
        }
        
        const [resultadoPedido] = await connection.query(
            'INSERT INTO pedidos (usuario_id, pago_id, total_pagado, detalles_pedido) VALUES (?, ?, ?, ?)',
            [usuario_id, pago_id, total_pagado, JSON.stringify(detalles_pedido)]
        );

        const nuevoPedidoId = resultadoPedido.insertId;
        const reciboXML = generarReciboXML(nuevoPedidoId, pago_id, total_pagado, detalles_pedido);
        
        await connection.query(
            'UPDATE pedidos SET recibo_xml = ? WHERE id = ?',
            [reciboXML, nuevoPedidoId]
        );

        await connection.commit();
        res.status(201).json({ message: 'Pedido creado exitosamente.', pedidoId: nuevoPedidoId });

    } catch (error) {
        await connection.rollback();
        console.error('Error al crear el pedido:', error);
        res.status(500).json({ message: error.message || 'Error interno del servidor al crear el pedido.' });
    } finally {
        connection.release();
    }
});

// Obtener historial de pedidos del usuario logueado
app.get('/api/pedidos/mis-pedidos', requireAuth, async (req, res) => {
    try {
        const [pedidos] = await pool.query(
            'SELECT id, pago_id, fecha_pedido, total_pagado, detalles_pedido, estado FROM pedidos WHERE usuario_id = ? ORDER BY fecha_pedido DESC',
            [req.userId]
        );
        res.json(pedidos);
    } catch (error) {
        console.error('Error al obtener el historial de pedidos del usuario:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// Obtener TODOS los pedidos (solo para administradores)
app.get('/api/pedidos/todos', requireAdmin, async (req, res) => {
    try {
        const [pedidos] = await pool.query(
            'SELECT p.id, p.pago_id, p.fecha_pedido, p.total_pagado, p.detalles_pedido, p.estado, u.correo as correo_usuario FROM pedidos p JOIN usuarios u ON p.usuario_id = u.id ORDER BY p.fecha_pedido DESC'
        );
        res.json(pedidos);
    } catch (error) {
        console.error('Error al obtener todos los pedidos:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// Obtener un recibo XML por ID de pedido
app.get('/api/pedidos/:id/recibo', requireAuth, async (req, res) => {
    const { id } = req.params;
    const usuario_id = req.userId;

    try {
        const [userRows] = await pool.query('SELECT rol FROM usuarios WHERE id = ?', [usuario_id]);
        const isAdmin = userRows.length > 0 && userRows[0].rol === 'administrador';
        
        const [pedidoRows] = await pool.query('SELECT recibo_xml, usuario_id FROM pedidos WHERE id = ?', [id]);

        if (pedidoRows.length === 0) {
            return res.status(404).json({ message: 'Pedido no encontrado.' });
        }

        const pedido = pedidoRows[0];

        if (pedido.usuario_id !== usuario_id && !isAdmin) {
            return res.status(403).json({ message: 'Acceso denegado.' });
        }

        if (!pedido.recibo_xml) {
            return res.status(404).json({ message: 'Este pedido no tiene un recibo XML asociado.' });
        }

        res.header('Content-Type', 'application/xml');
        res.header('Content-Disposition', `attachment; filename="recibo-pedido-${id}.xml"`);
        res.send(pedido.recibo_xml);

    } catch (error) {
        console.error(`Error al descargar recibo para pedido ${id}:`, error);
        res.status(500).json({ message: 'Error interno del servidor al obtener el recibo.' });
    }
});



// Obtener todos los usuarios
app.get('/api/usuarios', requireAdmin, async (req, res) => {
    try {
        const [usuarios] = await pool.query('SELECT id, nombre, apellido, username, correo, telefono, rol, fecha_registro FROM usuarios');
        res.json(usuarios);
    } catch (error) {
        console.error('Error al obtener usuarios:', error);
        res.status(500).json({ message: 'Error interno del servidor al obtener usuarios.' });
    }
});

// Obtener un usuario por ID
app.get('/api/usuarios/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    try {
        const [usuarios] = await pool.query('SELECT id, nombre, apellido, username, correo, telefono, rol FROM usuarios WHERE id = ?', [id]);
        if (usuarios.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }
        res.json(usuarios[0]);
    } catch (error) {
        console.error(`Error al obtener usuario ${id}:`, error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// Crear un nuevo usuario
app.post('/api/usuarios', requireAdmin, async (req, res) => {
    const { nombre, apellido, username, correo, telefono, contrasena, rol } = req.body;

    if (!nombre || !username || !correo || !contrasena || !rol) {
        return res.status(400).json({ message: 'Nombre, username, correo, contraseña y rol son requeridos.' });
    }
    if (!validarContrasena(contrasena)) {
        return res.status(400).json({ message: 'La nueva contraseña no cumple los requisitos.' });
    }

    try {
        // ---- VALIDACIÓN DE UNICIDAD ----
        const [existingUsers] = await pool.query(
            'SELECT username, correo, telefono FROM usuarios WHERE username = ? OR correo = ? OR (telefono = ? AND telefono IS NOT NULL)',
            [username, correo, telefono]
        );

        if (existingUsers.length > 0) {
            if (existingUsers.some(u => u.username === username)) {
                return res.status(409).json({ message: 'El nombre de usuario ya está en uso.' });
            }
            if (existingUsers.some(u => u.correo === correo)) {
                return res.status(409).json({ message: 'El correo electrónico ya está registrado.' });
            }
            if (telefono && existingUsers.some(u => u.telefono === telefono)) {
                return res.status(409).json({ message: 'El número de teléfono ya está registrado.' });
            }
        }
        // ---- FIN DE VALIDACIÓN ----

        const salt = await bcrypt.genSalt(10);
        const contrasenaHasheada = await bcrypt.hash(contrasena, salt);

        const [resultado] = await pool.query(
            'INSERT INTO usuarios (nombre, apellido, username, correo, telefono, contrasena, rol) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [nombre, apellido, username, correo, telefono || null, contrasenaHasheada, rol]
        );
        res.status(201).json({ message: 'Usuario creado exitosamente.', usuarioId: resultado.insertId });

    } catch (error) {
        console.error('Error al crear usuario por admin:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// Actualizar un usuario
app.put('/api/usuarios/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    // El correo no se puede editar y se omite
    const { nombre, apellido, username, telefono, rol, contrasena } = req.body;

    if (!nombre || !username || !rol) {
        return res.status(400).json({ message: 'Nombre, nombre de usuario y rol son requeridos.' });
    }

    try {
        // --- INICIO DE LA VALIDACIÓN ---
        // 1. Buscamos conflictos de 'username' y 'telefono' excluyendo al usuario actual.
        const [conflicts] = await pool.query(
            'SELECT username, telefono FROM usuarios WHERE (username = ? OR (telefono = ? AND telefono IS NOT NULL)) AND id != ?',
            [username, telefono, id]
        );

        // 2. Si se encontraron conflictos, determinamos cuál fue y devolvemos un error específico.
        if (conflicts.length > 0) {
            if (conflicts[0].username === username) {
                return res.status(409).json({ message: 'El nombre de usuario ya está en uso por otra cuenta.' });
            }
            if (telefono && conflicts[0].telefono === telefono) {
                return res.status(409).json({ message: 'El número de teléfono ya está registrado en otra cuenta.' });
            }
        }
        // --- FIN DE LA VALIDACIÓN ---


        // 3. Si no hay conflictos, procedemos a actualizar los datos.
        let query = 'UPDATE usuarios SET nombre = ?, apellido = ?, username = ?, telefono = ?, rol = ?';
        const params = [nombre, apellido || null, username, telefono || null, rol];

        if (contrasena) {
            if (!validarContrasena(contrasena)) {
                return res.status(400).json({ message: 'La nueva contraseña no cumple los requisitos.' });
            }
            const salt = await bcrypt.genSalt(10);
            const contrasenaHasheada = await bcrypt.hash(contrasena, salt);
            query += ', contrasena = ?';
            params.push(contrasenaHasheada);
        }

        query += ' WHERE id = ?';
        params.push(id);

        const [resultado] = await pool.query(query, params);

        if (resultado.affectedRows === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }
        
        res.json({ message: 'Usuario actualizado exitosamente.' });

    } catch (error) {
        // Este bloque ahora solo se activará por errores inesperados de la base de datos.
        console.error(`Error al actualizar usuario ${id}:`, error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// Eliminar un usuario
app.delete('/api/usuarios/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;
    // Evitar que un admin se elimine a sí mismo
    if (parseInt(id, 10) === req.userId) {
        return res.status(400).json({ message: 'No puedes eliminar tu propia cuenta de administrador.' });
    }

    try {
        const [resultado] = await pool.query('DELETE FROM usuarios WHERE id = ?', [id]);
        if (resultado.affectedRows === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }
        res.json({ message: 'Usuario eliminado exitosamente.' });
    } catch (error) {
        console.error(`Error al eliminar usuario ${id}:`, error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});


// Obtener los datos del perfil del usuario actual
app.get('/api/perfil', requireAuth, async (req, res) => {
    try {
        const [usuarios] = await pool.query(
            'SELECT id, nombre, apellido, username, correo, telefono FROM usuarios WHERE id = ?', 
            [req.userId]
        );

        if (usuarios.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }
        res.json(usuarios[0]);
    } catch (error) {
        console.error('Error al obtener perfil:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// Actualizar el perfil del usuario actual
app.put('/api/perfil', requireAuth, async (req, res) => {
    // El correo no se incluye aquí, por lo que no se puede editar
    const { nombre, apellido, username, telefono, contrasena } = req.body;

    if (!nombre || !username) {
        return res.status(400).json({ message: 'Nombre y nombre de usuario son requeridos.' });
    }

    try {
        // --- 1. VALIDACIÓN DE UNICIDAD ---
        // Buscamos si el nuevo 'username' O 'telefono' ya existen en la base de datos,
        // pero EXCLUYENDO el registro del propio usuario que está haciendo la petición (id != ?).
        const [existing] = await pool.query(
            'SELECT id, username, telefono FROM usuarios WHERE (username = ? OR (telefono = ? AND telefono IS NOT NULL)) AND id != ?',
            [username, telefono, req.userId]
        );

        // Si la consulta anterior encontró algo, significa que hay un conflicto.
        if (existing.length > 0) {
            // Verificamos específicamente qué campo está duplicado para dar un mensaje claro.
            if (existing[0].username === username) {
                return res.status(409).json({ message: 'El nombre de usuario ya está en uso por otra cuenta.' });
            }
            if (telefono && existing[0].telefono === telefono) {
                return res.status(409).json({ message: 'El número de teléfono ya está registrado en otra cuenta.' });
            }
        }
        // --- FIN DE LA VALIDACIÓN ---


        // --- 2. ACTUALIZACIÓN DE DATOS (si no hubo errores) ---
        let query = 'UPDATE usuarios SET nombre = ?, apellido = ?, username = ?, telefono = ?';
        const params = [nombre, apellido || null, username, telefono || null];

        if (contrasena) {
            if (!validarContrasena(contrasena)) {
                return res.status(400).json({ message: 'La nueva contraseña no cumple los requisitos.' });
            }
            const salt = await bcrypt.genSalt(10);
            const contrasenaHasheada = await bcrypt.hash(contrasena, salt);
            query += ', contrasena = ?';
            params.push(contrasenaHasheada);
        }
        
        query += ' WHERE id = ?';
        params.push(req.userId);

        await pool.query(query, params);
        
        // Devolvemos el usuario actualizado para refrescar los datos en el frontend
        const [usuarios] = await pool.query('SELECT * FROM usuarios WHERE id = ?', [req.userId]);
        const { contrasena: _, ...usuarioActualizado } = usuarios[0];

        res.json({ message: 'Perfil actualizado exitosamente.', usuario: usuarioActualizado });

    } catch (error) {
        console.error(`Error al actualizar perfil para usuario ${req.userId}:`, error);
        res.status(500).json({ message: 'Error interno del servidor al actualizar el perfil.' });
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