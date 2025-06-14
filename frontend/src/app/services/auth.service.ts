import { Injectable, Inject, PLATFORM_ID } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { BehaviorSubject, Observable, throwError } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { Router } from '@angular/router';
import { isPlatformBrowser } from '@angular/common';
import { Usuario } from '../models/usuario';

export interface AuthResponseSimple { // Interfaz para la respuesta del backend
  message: string;
  usuario?: Usuario;
  usuarioId?: number; 
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'http://localhost:8080/api/auth';
  private usuarioKey = 'currentUserEcommerce'; // Cambiar key para evitar conflictos si tienes otra app

  private currentUserSubject: BehaviorSubject<Usuario | null>;
  public currentUser$: Observable<Usuario | null>;

  constructor(
    private http: HttpClient,
    private router: Router,
    @Inject(PLATFORM_ID) private platformId: Object
  ) {
    let storedUser = null;
    if (isPlatformBrowser(this.platformId)) {
      const userJson = localStorage.getItem(this.usuarioKey);
      if (userJson) {
        try {
          storedUser = JSON.parse(userJson);
        } catch (e) {
          localStorage.removeItem(this.usuarioKey);
        }
      }
    }
    this.currentUserSubject = new BehaviorSubject<Usuario | null>(storedUser);
    this.currentUser$ = this.currentUserSubject.asObservable();
  }

  getToken(): string | null {
    return localStorage.getItem('token');
  }

  public get currentUserValue(): Usuario | null {
    return this.currentUserSubject.value;
  }

  public get isLoggedIn(): boolean {
    return !!this.currentUserValue; // Simplemente verifica si hay un usuario en el BehaviorSubject
  }

  public get userRole(): string | null {
    return this.currentUserValue ? this.currentUserValue.rol : null;
  }

  registro(datosUsuario: any): Observable<AuthResponseSimple> {
    return this.http.post<AuthResponseSimple>(`${this.apiUrl}/registro`, datosUsuario).pipe(
      catchError(this.handleError)
    );
  }

  login(credenciales: { loginIdentifier: string, contrasena: string }): Observable<AuthResponseSimple> {
    return this.http.post<AuthResponseSimple>(`${this.apiUrl}/login`, credenciales).pipe(
      tap((response) => {
        if (response.usuario && isPlatformBrowser(this.platformId)) {
          // Asegurar que el usuario tenga ID
          if (!response.usuario.id) {
            throw new Error('Usuario sin ID en la respuesta');
          }
          localStorage.setItem(this.usuarioKey, JSON.stringify(response.usuario));
          this.currentUserSubject.next(response.usuario);
        } else if (!response.usuario) { this.logoutSilently(); }
      }),
      catchError(err => {
        this.logoutSilently();
        return this.handleError(err);
      })
    );
  }

  private logoutSilently(): void {
    if (isPlatformBrowser(this.platformId)) {
      localStorage.removeItem(this.usuarioKey);
    }
    this.currentUserSubject.next(null);
  }

  logout(): void {
    localStorage.removeItem(this.usuarioKey);
    this.currentUserSubject.next(null);
    // Eliminar cookie de sesión
    document.cookie = 'session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    this.router.navigate(['/login']);
  }


  recuperarContrasenaSimple(datosRecuperacion: { loginIdentifier: string, nuevaContrasena: string }): Observable<AuthResponseSimple> {
    return this.http.post<AuthResponseSimple>(`${this.apiUrl}/recuperar-simple`, datosRecuperacion).pipe(
      catchError(this.handleError)
    );
  }

  cambiarContrasenaAdmin(idUsuarioAModificar: number, nuevaContrasena: string, credencialesAdmin: any): Observable<any> {
    const payload = { nuevaContrasena, ...credencialesAdmin };
    return this.http.put(`${this.apiUrl}/actualizar-contrasena-admin/${idUsuarioAModificar}`, payload)
      .pipe(catchError(this.handleError));
  }
  
  private handleError(error: HttpErrorResponse) {
    let errorMessage = 'Ocurrió un error.';
    if (error.error && typeof error.error.message === 'string') {
      errorMessage = error.error.message;
    } else if (error.status === 0) {
      errorMessage = 'No se pudo conectar con el servidor.';
    } else {
      errorMessage = `Error ${error.status}: ${error.statusText || 'Error del servidor'}`;
    }
    console.error('AuthService Error:', errorMessage, error);
    return throwError(() => new Error(errorMessage));
  }
}