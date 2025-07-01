import { CarritoItem } from './carrito-item';

export interface Pedido {
    id: number;
    pago_id: string;
    fecha_pedido: string;
    total_pagado: number;
    detalles_pedido: CarritoItem[];
    estado: string;
    correo_usuario?: string; // Opcional, solo para la vista de admin
}
