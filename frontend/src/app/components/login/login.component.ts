// src/app/components/login/login.component.ts
import { Component, OnInit, Inject, PLATFORM_ID } from '@angular/core'; // Añadir OnInit
import { Router, ActivatedRoute, RouterModule } from '@angular/router'; // Añadir ActivatedRoute
import { FormsModule } from '@angular/forms';
import { CommonModule, isPlatformBrowser } from '@angular/common';
import { AuthService, AuthResponseSimple } from '../../services/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [
    FormsModule,
    CommonModule,
    RouterModule
  ],
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css'] // Asegúrate de tener este archivo o coméntalo
})
export class LoginComponent implements OnInit {
  credenciales = { loginIdentifier: '', contrasena: '' };
  errorMessage: string | null = null;
  isLoading: boolean = false;
  private returnUrl: string = '/productos';

  constructor(
    private authService: AuthService,
    private router: Router,
    private route: ActivatedRoute,
    @Inject(PLATFORM_ID) private platformId: Object // Necesario para isPlatformBrowser
  ) {}

  ngOnInit(): void {
    if (isPlatformBrowser(this.platformId)) { // Proteger acceso a snapshot en SSR si fuera necesario
      this.returnUrl = this.route.snapshot.queryParams['returnUrl'] || '/productos';
    }
  }

  onSubmit(): void {
    this.errorMessage = null;
    this.isLoading = true;

    if (!this.credenciales.loginIdentifier?.trim() || !this.credenciales.contrasena) {
        this.errorMessage = "Identificador (correo/username) y contraseña son requeridos.";
        this.isLoading = false;
        return;
    }

    this.authService.login(this.credenciales).subscribe({
      next: (response: AuthResponseSimple) => { // Especificar el tipo de la respuesta
        this.isLoading = false;
        if (response.usuario) {
          console.log('Login exitoso, usuario:', response.usuario);
          let navigateToUrl = this.returnUrl;
          if (response.usuario.rol === 'administrador') {
            // Si es admin y la returnUrl es genérica o la raíz, mandarlo a inventario
            // O si la returnUrl ya es inventario, déjalo ir allí.
            if (navigateToUrl === '/' || navigateToUrl === '/productos' || !navigateToUrl.startsWith('/')) {
              navigateToUrl = '/inventario';
            }
          }
          // Para clientes, o si returnUrl ya es específica, ir a la returnUrl
          this.router.navigateByUrl(navigateToUrl);
        } else {
          this.errorMessage = response.message || 'Respuesta inesperada del servidor.';
        }
      },
      error: (err) => {
        this.isLoading = false;
        console.error('Error en login:', err);
        this.errorMessage = err.message || 'Error al iniciar sesión. Verifique sus credenciales.';
      }
    });
  }
}