// src/app/components/home/home.component.ts
import { Component, OnInit, Inject, PLATFORM_ID } from '@angular/core';
import { Router } from '@angular/router';
import { CommonModule, isPlatformBrowser } from '@angular/common';
import { AuthService } from '../../services/auth.service'; // Ajusta la ruta

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule], // No necesita mucho más
  template: '<p>Redirigiendo...</p>', // O un spinner de carga
  // No necesita CSS si solo redirige
})
export class HomeComponent implements OnInit {
  constructor(
    private router: Router,
    private authService: AuthService,
    @Inject(PLATFORM_ID) private platformId: Object
  ) {}

  ngOnInit(): void {
    // Solo ejecutar lógica de redirección en el navegador
    if (isPlatformBrowser(this.platformId)) {
      if (this.authService.isLoggedIn) {
        const userRole = this.authService.userRole;
        if (userRole === 'administrador') {
          console.log('HomeComponent: Usuario admin logueado, redirigiendo a /inventario');
          this.router.navigate(['/inventario']);
        } else {
          console.log('HomeComponent: Usuario cliente logueado, redirigiendo a /productos');
          this.router.navigate(['/productos']);
        }
      } else {
        console.log('HomeComponent: Usuario no logueado, redirigiendo a /login');
        this.router.navigate(['/login']);
      }
    }
    // En SSR, este componente simplemente se renderizará con "Redirigiendo..."
    // La redirección real ocurrirá cuando el cliente tome el control.
    // O, si quieres que SSR también redirija, la lógica sería más compleja y
    // necesitarías usar el response del servidor desde `server.ts`.
    // Por simplicidad, la redirección principal la maneja el cliente.
  }
}