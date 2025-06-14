import { inject } from '@angular/core';
import { CanActivateFn, Router, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { AuthService } from '../services/auth.service'; // Ajusta la ruta

export const adminGuard: CanActivateFn = (
  route: ActivatedRouteSnapshot,
  state: RouterStateSnapshot
) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isLoggedIn && authService.userRole === 'administrador') {
    return true; // Usuario logueado y es admin, permitir acceso
  }

  // Si no es admin o no está logueado
  if (!authService.isLoggedIn) {
    console.log('AdminGuard: Usuario no logueado, redirigiendo a /login');
    router.navigate(['/login'], { queryParams: { returnUrl: state.url } });
  } else {
    // Logueado pero no es admin
    console.log('AdminGuard: Usuario no es administrador, redirigiendo a /productos');
    router.navigate(['/productos']); // O a una página de "Acceso Denegado"
  }
  return false;
};