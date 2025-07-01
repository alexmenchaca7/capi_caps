import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule, NgForm } from '@angular/forms';
import { AuthService } from '../../services/auth.service';
import { Usuario } from '../../models/usuario';
import { HeaderComponent } from '../header/header.component';
import { Router } from '@angular/router';

@Component({
  selector: 'app-perfil',
  standalone: true,
  imports: [CommonModule, FormsModule, HeaderComponent],
  templateUrl: './perfil.component.html',
  styleUrls: ['./perfil.component.css']
})
export class PerfilComponent implements OnInit {
  usuario: any = {};
  mensajeExito: string | null = null;
  mensajeError: string | null = null;

  constructor(private authService: AuthService, private router: Router) {}

  ngOnInit(): void {
    this.cargarDatosUsuario();
  }

  cargarDatosUsuario(): void {
    this.authService.getPerfil().subscribe({
      next: (data) => {
        this.usuario = data;
      },
      error: (err) => {
        this.mostrarMensajeError('Error al cargar los datos del perfil.');
        console.error(err);
      }
    });
  }

  onSubmit(perfilForm: NgForm): void {
    if (perfilForm.invalid) {
      return;
    }

    const datosAActualizar = { ...this.usuario };
    // No enviar la contraseña si el campo está vacío para no sobreescribirla
    if (!datosAActualizar.contrasena) {
      delete datosAActualizar.contrasena;
    }

    this.authService.updatePerfil(datosAActualizar).subscribe({
      next: (response) => {
        this.mostrarMensajeExito(response.message);
        setTimeout(() => {
          this.mensajeExito = null;
          // Opcional: Redirigir después de un tiempo
          // this.router.navigate(['/productos']); 
        }, 3000);
      },
      error: (err) => {
        this.mostrarMensajeError(err.error?.message || 'Ocurrió un error al actualizar.');
      }
    });
  }

  private mostrarMensajeExito(mensaje: string): void {
    this.mensajeError = null;
    this.mensajeExito = mensaje;
  }

  private mostrarMensajeError(mensaje: string): void {
    this.mensajeExito = null;
    this.mensajeError = mensaje;
  }
}