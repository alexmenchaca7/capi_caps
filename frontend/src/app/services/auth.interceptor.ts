import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent } from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuthService } from './auth.service';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {

  constructor(private authService: AuthService) {}

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    // Obtenemos el objeto del usuario actual desde el servicio
    const currentUser = this.authService.currentUserValue;

    // Si hay un usuario logueado y tiene un ID
    if (currentUser && currentUser.id) {
      // Clonamos la petición para añadirle la nueva cabecera
      const cloned = req.clone({
        // Establecemos la cabecera 'x-user-id', que es la que el backend espera
        headers: req.headers.set('x-user-id', currentUser.id.toString())
      });
      // Dejamos que la petición clonada continúe su camino
      return next.handle(cloned);
    }

    // Si no hay usuario, la petición continúa sin modificarse
    return next.handle(req);
  }
}