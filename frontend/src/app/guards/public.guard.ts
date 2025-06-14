import { inject } from '@angular/core';
import { CanActivateFn, Router, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { AuthService } from '../services/auth.service'; // Ajusta la ruta

export const publicGuard: CanActivateFn = (
  route: ActivatedRouteSnapshot,
  state: RouterStateSnapshot
) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  if (!authService.isLoggedIn) {
    return true; // Usuario NO logueado, permitir acceso (ej. a /login o /registro)
  }

  // Usuario YA logueado, redirigir a la página principal de productos (o su dashboard)
  console.log('PublicGuard: Usuario ya logueado, redirigiendo a /productos');
  router.navigate(['/productos']);
  return false;
};