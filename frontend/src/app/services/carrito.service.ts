import { Injectable, Inject, PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { Producto } from '../models/producto';
import { CarritoItem } from '../models/carrito-item'; 
import { InventarioService } from './inventario.service';
import { Observable, throwError, of, BehaviorSubject } from 'rxjs';
import { map, catchError, tap, switchMap } from 'rxjs/operators';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root'
})

export class CarritoService {
  private carritoSubject = new BehaviorSubject<CarritoItem[]>([]);
  public carrito$ = this.carritoSubject.asObservable();
  public tiendaNombre = 'CapiCaps';
  private readonly API_URL = 'http://localhost:8080/api';
  public readonly serverBaseUrl: string;

  constructor(
    private inventarioService: InventarioService,
    private http: HttpClient,
    private authService: AuthService,
    @Inject(PLATFORM_ID) private platformId: Object
  ) {
    this.serverBaseUrl = this.inventarioService.serverBaseUrl;

    // Escuchamos los cambios en el estado de autenticación
    this.authService.currentUser$.subscribe(usuario => {
      if (usuario) {
        // Si hay un usuario, cargamos su carrito desde el servidor
        console.log(`Usuario ${usuario.username} ha iniciado sesión. Cargando su carrito.`);
        this.obtenerCarritoDeServidor().subscribe();
      } else {
        // Si no hay usuario (logout), limpiamos el carrito local
        console.log('Usuario ha cerrado sesión. Limpiando carrito.');
        this.carritoSubject.next([]);
      }
    });
  }

  private obtenerCarritoDeServidor(): Observable<CarritoItem[]> {
    return this.http.get<CarritoItem[]>(`${this.API_URL}/carrito`, {
      headers: this.getAuthHeaders()
    }).pipe(
      tap(carrito => this.carritoSubject.next(carrito)),
      catchError(err => {
        console.error('Error cargando carrito', err);
        return of([]);
      })
    );
  }

  private getAuthHeaders(): HttpHeaders {
    const userId = this.authService.currentUserValue?.id;
    return new HttpHeaders().set('x-user-id', userId ? userId.toString() : '');
  }

  eliminarProducto(carritoId: number): void {
    this.http.delete(`${this.API_URL}/carrito/${carritoId}`, { headers: this.getAuthHeaders() }).pipe(
      switchMap(() => this.obtenerCarritoDeServidor()), // Simplemente refrescamos el carrito
      catchError(err => {
        console.error('Error en el proceso de eliminar producto:', err);
        return throwError(() => err);
      })
    ).subscribe();
  }

  agregarProducto(producto: Producto): void {
    if (!this.authService.isLoggedIn) {
      console.error('Usuario no autenticado');
      return;
    }
    
    this.http.post(`${this.API_URL}/carrito`, {
      producto_id: producto.id,
      cantidad: 1
    }, { headers: this.getAuthHeaders() }).pipe(
      switchMap(() => this.obtenerCarritoDeServidor()),
      catchError(err => {
        console.error('Error en el proceso de agregar al carrito:', err);
        alert(`Error: ${err.error?.message || 'No se pudo agregar el producto.'}`);
        return throwError(() => err);
      })
    ).subscribe({
      next: () => console.log('Producto agregado al carrito.'),
      error: (err) => console.error('Flujo de agregarProducto completado con error.')
    });
  }

  actualizarCantidad(carritoId: number, nuevaCantidad: number): void {
  }


  actualizarInventario(id: number, cantidadAfectada: number, operacion: 'sumar' | 'restar'): Observable<any> {
    return this.http.patch(`${this.API_URL}/productos/${id}/stock`, {
      cantidadAfectada,
      operacion
    }).pipe(
      tap(() => {
        console.log(`Petición de actualizar inventario enviada para producto ID ${id}`);
      }),
      catchError(err => {
        console.error(`Fallo al actualizar inventario en el servidor para producto ID ${id}:`, err);
        return throwError(() => err);
      })
    );
  }


  obtenerCarrito(): CarritoItem[] {
    return this.carritoSubject.value;
  }

  generarXML(): string {
    let subtotal = this.calcularSubtotal();
    let iva = subtotal * 0.16;
    let total = subtotal + iva;
    let xml = `<?xml version="1.0" encoding="UTF-8"?>\n<recibo>\n`;
    xml += `  <tienda>${this.tiendaNombre}</tienda>\n`;
    this.carritoSubject.value.forEach((producto) => {
      xml += `    <producto id="${producto.producto_id}">\n`; // Usar producto_id
      xml += `      <nombre>${producto.nombre}</nombre>\n`;
      xml += `      <precio>${producto.precio}</precio>\n`;
      xml += `      <cantidad>${producto.cantidadEnCarrito}</cantidad>\n`; // Usar cantidadEnCarrito
    });
    xml += `  <subtotal>$${subtotal}</subtotal>\n`;
    xml += `  <iva>$${iva.toFixed(2)}</iva>\n`;
    xml += `  <total>$${total.toFixed(2)}</total>\n`;
    xml += `</recibo>`;
    return xml;
  }

  private calcularSubtotal(): number {
    return this.carritoSubject.value.reduce((acc, producto) => acc + (producto.precio ?? 0) * (producto.cantidadEnCarrito ?? 0), 0);
  }

  limpiarCarrito(): void {
    this.http.delete(`${this.API_URL}/carrito`, {
      headers: this.getAuthHeaders()
    }).pipe(
      tap(() => this.carritoSubject.next([]))
    ).subscribe();
  }
}
