// src/app/services/carrito.service.ts
import { Injectable, Inject, PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { BehaviorSubject, Observable, of, throwError } from 'rxjs';
import { HttpClient } from '@angular/common/http';
import { tap, catchError } from 'rxjs/operators';
import { Producto } from '../models/producto';
import { CarritoItem } from '../models/carrito-item';

@Injectable({
  providedIn: 'root'
})
export class CarritoService {
  private carritoKey = 'miCarritoCapiCaps';
  private carritoSubject = new BehaviorSubject<CarritoItem[]>([]);
  public carrito$ = this.carritoSubject.asObservable();
  
  private API_URL = 'http://localhost:8080/api';
  public tiendaNombre = 'CapiCaps';

  constructor(
    private http: HttpClient,
    @Inject(PLATFORM_ID) private platformId: Object
  ) {
    this.cargarCarritoDesdeLocalStorage();
  }

  private cargarCarritoDesdeLocalStorage(): void {
    if (isPlatformBrowser(this.platformId)) {
      const carritoJson = localStorage.getItem(this.carritoKey);
      let items: CarritoItem[] = carritoJson ? JSON.parse(carritoJson) : [];
      
      // SOLUCIÓN: Convertir explícitamente los valores a números al cargar
      items = items.map(item => ({
        ...item,
        precio: Number(item.precio),
        cantidadEnCarrito: Number(item.cantidadEnCarrito),
        stock: Number(item.stock)
      }));

      this.carritoSubject.next(items);
    }
  }

  private guardarCarritoEnLocalStorage(items: CarritoItem[]): void {
    if (isPlatformBrowser(this.platformId)) {
      localStorage.setItem(this.carritoKey, JSON.stringify(items));
      this.carritoSubject.next(items);
    }
  }

  agregarProducto(producto: Producto): void {
    const carritoActual = [...this.carritoSubject.value];
    const itemExistente = carritoActual.find(item => item.producto_id === producto.id);

    if (itemExistente) {
      if (itemExistente.cantidadEnCarrito < (producto.cantidad ?? 0)) {
        itemExistente.cantidadEnCarrito++;
      } else {
        alert(`No puedes agregar más unidades de "${producto.nombre}", has alcanzado el stock disponible.`);
      }
    } else {
      const nuevoItem: CarritoItem = {
        carritoId: Date.now(),
        producto_id: producto.id,
        nombre: producto.nombre,
        precio: Number(producto.precio) || 0,
        cantidadEnCarrito: 1,
        stock: Number(producto.cantidad) || 0,
        imagen: producto.imagen
      };
      carritoActual.push(nuevoItem);
    }
    this.guardarCarritoEnLocalStorage(carritoActual);
  }

  actualizarCantidad(productoId: number, nuevaCantidad: number): void {
    let carritoActual = this.carritoSubject.value.map(item => {
      if (item.producto_id === productoId) {
        const cantidadAjustada = Math.min(nuevaCantidad, item.stock);
        return { ...item, cantidadEnCarrito: cantidadAjustada > 0 ? cantidadAjustada : 1 };
      }
      return item;
    });
    this.guardarCarritoEnLocalStorage(carritoActual);
  }

  eliminarProducto(productoId: number): void {
    const carritoActual = this.carritoSubject.value.filter(item => item.producto_id !== productoId);
    this.guardarCarritoEnLocalStorage(carritoActual);
  }

  limpiarCarrito(): void {
    this.guardarCarritoEnLocalStorage([]);
  }

  obtenerCarrito(): CarritoItem[] {
    return this.carritoSubject.value;
  }
  
  crearPedido(pagoId: string, totalPagado: number, detalles: CarritoItem[]): Observable<any> {
    const payload = {
      pago_id: pagoId,
      total_pagado: totalPagado,
      detalles_pedido: detalles
    };
    return this.http.post(`${this.API_URL}/pedidos`, payload).pipe(
      catchError(err => {
        console.error("Error al crear el pedido en el backend", err);
        return throwError(() => new Error(err.error?.message || 'No se pudo registrar la compra.'));
      })
    );
  }
}