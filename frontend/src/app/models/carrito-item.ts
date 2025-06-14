export interface CarritoItem {
  carritoId: number;
  cantidadEnCarrito: number;
  producto_id: number;
  nombre: string;
  precio: number;
  imagen?: string;
  stock: number;
}