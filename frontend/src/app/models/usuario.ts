export interface Usuario {
  id: number;
  nombre: string;
  apellido: string;
  username: string; // Nuevo
  correo: string;
  telefono?: string; // Nuevo y opcional
  rol: 'cliente' | 'administrador';
  fecha_registro?: string;
}
  