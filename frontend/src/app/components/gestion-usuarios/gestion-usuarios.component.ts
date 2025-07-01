import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { UsuarioService } from '../../services/usuario.service';
import { Usuario } from '../../models/usuario';
import { HeaderComponent } from '../header/header.component';

@Component({
  selector: 'app-gestion-usuarios',
  standalone: true,
  imports: [CommonModule, FormsModule, HeaderComponent],
  templateUrl: './gestion-usuarios.component.html',
  styleUrls: ['./gestion-usuarios.component.css']
})
export class GestionUsuariosComponent implements OnInit {
  usuarios: Usuario[] = [];
  usuarioSeleccionado: any = null;
  mostrarModal = false;
  esEdicion = false;
  mensajeExito: string | null = null;
  mensajeError: string | null = null;

  constructor(private usuarioService: UsuarioService) {}

  ngOnInit(): void {
    this.cargarUsuarios();
  }

  cargarUsuarios(): void {
    this.usuarioService.getUsuarios().subscribe({
      next: (data) => this.usuarios = data,
      error: (err) => {
        // Muestra el error en la página principal si falla la carga inicial
        this.mensajeError = err.message;
        setTimeout(() => this.mensajeError = null, 4000);
      }
    });
  }

  abrirModalParaCrear(): void {
    this.esEdicion = false;
    this.usuarioSeleccionado = { rol: 'cliente' };
    this.limpiarMensajes();
    this.mostrarModal = true;
  }

  abrirModalParaEditar(usuario: Usuario): void {
    this.esEdicion = true;
    this.usuarioSeleccionado = { ...usuario };
    this.limpiarMensajes();
    this.mostrarModal = true;
  }

  cerrarModal(): void {
    this.mostrarModal = false;
    this.usuarioSeleccionado = null;
  }

  guardarUsuario(): void {
    this.limpiarMensajes();
    const datosUsuario = { ...this.usuarioSeleccionado };
    
    if (this.esEdicion && !datosUsuario.contrasena) {
      delete datosUsuario.contrasena;
    }

    const peticion = this.esEdicion
      ? this.usuarioService.actualizarUsuario(datosUsuario.id, datosUsuario)
      : this.usuarioService.crearUsuario(datosUsuario);

    peticion.subscribe({
      next: () => {
        const mensaje = this.esEdicion ? 'Usuario actualizado correctamente.' : 'Usuario creado correctamente.';
        this.mensajeExito = mensaje;
        this.cargarUsuarios();
        setTimeout(() => this.cerrarModal(), 2000); 
      },
      error: (err) => {
        // Con esto, veremos en la consola la estructura exacta del error
        console.log('Error completo recibido en el componente:', err);
        console.log('Cuerpo del error (err.error):', err.error);

        // Extraemos el mensaje de forma segura.
        // El backend envía { "message": "..." }, por eso accedemos a err.error.message
        if (err.error && typeof err.error === 'object' && err.error.message) {
          this.mensajeError = err.error.message;
        } else {
          // Si por alguna razón el cuerpo del error no es un objeto JSON, mostramos un genérico.
          this.mensajeError = 'Ocurrió un error inesperado al procesar la respuesta del servidor.';
        }
      }
    });
  }

  eliminarUsuario(id: number): void {
    if (confirm('¿Estás seguro de que deseas eliminar este usuario?')) {
      this.usuarioService.eliminarUsuario(id).subscribe({
        next: () => {
          alert('Usuario eliminado correctamente.');
          this.cargarUsuarios();
        },
        error: (err) => alert(err.error?.message || 'Error al eliminar el usuario.')
      });
    }
  }
  
  private limpiarMensajes(): void {
    this.mensajeExito = null;
    this.mensajeError = null;
  }
}