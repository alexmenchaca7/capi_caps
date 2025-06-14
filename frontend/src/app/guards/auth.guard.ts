import { inject } from '@angular/core';
import { CanActivateFn, Router, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { AuthService } from '../services/auth.service'; // Ajusta la ruta a tu AuthService

export const authGuard: CanActivateFn = (
  route: ActivatedRouteSnapshot,
  state: RouterStateSnapshot
) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (authService.isLoggedIn) {
    return true; // Usuario logueado, permitir acceso
  }

  // Usuario no logueado, redirigir a login guardando la URL a la que intentaba acceder
  console.log('AuthGuard: Usuario no logueado, redirigiendo a /login');
  router.navigate(['/login'], { queryParams: { returnUrl: state.url } });
  return false;
};