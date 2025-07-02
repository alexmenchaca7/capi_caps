import { Component } from '@angular/core';
import { Router, RouterModule } from '@angular/router'; // RouterModule para routerLink en la plantilla
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { AuthService, AuthResponseSimple } from '../../services/auth.service'; // Ajusta la ruta si es necesario
import { HeaderComponent } from '../header/header.component'; // Si lo usas

@Component({
  selector: 'app-registro',
  standalone: true,
  imports: [
    FormsModule,
    CommonModule,
    RouterModule, // Para routerLink
    // HeaderComponent // Solo si usas <app-header> dentro de la plantilla de registro
  ],
  templateUrl: './registro.component.html', // Asegúrate que el path sea correcto
  styleUrls: ['./registro.component.css']   // Asegúrate que el path sea correcto
})
export class RegistroComponent {
  datosUsuario = {
    nombre: '',
    apellido: '',
    username: '', 
    correo: '',
    telefono: '', 
    contrasena: '',
    confirmarContrasena: ''
  };

  errorMessage: string | null = null;
  successMessage: string | null = null;
  isLoading: boolean = false;

  constructor(private authService: AuthService, private router: Router) {}

  onSubmit(): void {
    this.errorMessage = null;
    this.successMessage = null;
    this.isLoading = true;

    // --- VALIDACIONES ---
    if (!this.datosUsuario.nombre?.trim() ||
        !this.datosUsuario.apellido?.trim() ||
        !this.datosUsuario.username?.trim() || 
        !this.datosUsuario.correo?.trim() ||
        !this.datosUsuario.contrasena) {
      this.errorMessage = "Nombre, apellido, nombre de usuario, correo y contraseña son requeridos.";
      this.isLoading = false;
      return;
    }

    if (this.datosUsuario.contrasena !== this.datosUsuario.confirmarContrasena) {
        this.errorMessage = "Las contraseñas no coinciden.";
        this.isLoading = false;
        return;
    }

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(this.datosUsuario.username)) {
        this.errorMessage = 'Nombre de usuario inválido (3-20 caracteres alfanuméricos/guion bajo).';
        this.isLoading = false;
        return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(this.datosUsuario.correo)) {
        this.errorMessage = 'Formato de correo inválido.';
        this.isLoading = false;
        return;
    }
    if (!this.isPasswordValid(this.datosUsuario.contrasena)) {
        this.errorMessage = "La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula y un número.";
        this.isLoading = false;
        return;
    }

    this.authService.registro(this.datosUsuario).subscribe({
      next: (response: AuthResponseSimple) => {
        this.isLoading = false;
        this.successMessage = response.message + " Ahora puedes iniciar sesión.";
        setTimeout(() => {
          if (!this.errorMessage) { this.router.navigate(['/login']); }
        }, 2500);
      },
      error: (err) => {
        this.isLoading = false;
        this.errorMessage = err.message || 'Ocurrió un error durante el registro.';
      }
    });
  }

  isPasswordValid(password: string): boolean {
    if (password.length < 8) return false;
    if (!/[A-Z]/.test(password)) return false;
    if (!/[a-z]/.test(password)) return false;
    if (!/[0-9]/.test(password)) return false;
    return true;
  }
}