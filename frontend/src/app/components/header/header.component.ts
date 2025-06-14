import { Component, OnInit, OnDestroy } from '@angular/core';
import { Router, RouterModule } from '@angular/router'; // Importar RouterModule para routerLink
import { CommonModule } from '@angular/common'; // Importar CommonModule para *ngIf, etc.
import { AuthService } from '../../services/auth.service'; // Ajusta la ruta si es necesario
import { Usuario } from '../../models/usuario'; // Ajusta la ruta si es necesario
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-header',
  standalone: true, // Asumiendo que sigue siendo standalone
  imports: [
    RouterModule, // Para directivas como routerLink
    CommonModule  // Para directivas como *ngIf, *ngFor
  ],
  templateUrl: './header.component.html',
  styleUrl: './header.component.css'
})
export class HeaderComponent implements OnInit, OnDestroy {
  currentUser: Usuario | null = null;
  private authSubscription: Subscription | undefined;

  constructor(
    public authService: AuthService, // Hacerlo público si la plantilla lo necesita directamente
    private router: Router
  ) {}

  ngOnInit(): void {
    this.authSubscription = this.authService.currentUser$.subscribe(user => {
      this.currentUser = user;
    });
  }

  ngOnDestroy(): void {
    if (this.authSubscription) {
      this.authSubscription.unsubscribe();
    }
  }

  // Método para verificar si el usuario es administrador (usado en la plantilla)
  isAdmin(): boolean {
    return !!this.currentUser && this.currentUser.rol === 'administrador';
  }

  // Método para verificar si el usuario está logueado (usado en la plantilla)
  isLoggedIn(): boolean {
    return this.authService.isLoggedIn; // Usar el getter del servicio
  }

  logout(): void {
    this.authService.logout();
    // No es necesario redirigir aquí, AuthService ya lo hace.
    // Opcional: this.router.navigate(['/login']); si quieres un comportamiento específico aquí.
  }
}