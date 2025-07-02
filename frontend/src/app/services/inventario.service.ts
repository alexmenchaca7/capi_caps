import { Injectable, Inject, PLATFORM_ID } from '@angular/core';
import { isPlatformBrowser, isPlatformServer } from '@angular/common';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, BehaviorSubject, throwError } from 'rxjs';
import { tap, catchError, switchMap, map, first } from 'rxjs/operators';

import { Producto } from '../models/producto';

@Injectable({
  providedIn: 'root'
})
export class InventarioService {
  private apiUrl = 'http://localhost:8080/api';
  public serverBaseUrl = 'http://localhost:8080';

  // El BehaviorSubject ahora almacena el tipo de dato que los componentes esperan
  private productosSubject = new BehaviorSubject<(Producto & { displayUrl?: string })[]>([]);
  productos$ = this.productosSubject.asObservable();

  // Nuevo Subject para el inventario completo
  private inventarioSubject = new BehaviorSubject<(Producto & { displayUrl?: string })[]>([]);
  inventario$ = this.inventarioSubject.asObservable();

  private isLoading = new BehaviorSubject<boolean>(false);
  isLoading$ = this.isLoading.asObservable();

  constructor(
    private http: HttpClient,
    @Inject(PLATFORM_ID) private platformId: Object
  ) {
    // La carga inicial se puede manejar en los componentes directamente
    // para mayor claridad de qué se está cargando y cuándo.
  }

  // Este método procesa los productos crudos de la API para añadirles la displayUrl
  private procesarProductosParaDisplay(productos: Producto[]): (Producto & { displayUrl?: string })[] {
    return productos.map(p => {
      let displayUrl = 'assets/default.webp'; // Asegúrate que esta imagen exista
      if (p.imagen) {
        if (p.imagen.startsWith('uploads/')) {
          displayUrl = this.serverBaseUrl + '/' + p.imagen;
        } else if (p.imagen.startsWith('assets/')) {
          displayUrl = p.imagen;
        } else {
          console.warn(`InventarioService: Patrón de imagen no reconocido para '${p.imagen}', usando imagen por defecto.`);
        }
      }
      return { ...p, displayUrl: displayUrl };
    });
  }

  private cargarProductosDesdeHttp(): void {
    if (this.isLoading.value && isPlatformBrowser(this.platformId)) {
      // En el cliente, si ya está cargando, no hacer otra petición.
      // En el servidor, cada renderizado es independiente, así que esta guarda es menos efectiva para el ciclo SSR.
      console.log('InventarioService: Carga de productos ya en progreso (cliente), omitiendo.');
      return;
    }
    this.isLoading.next(true);
    const entorno = isPlatformBrowser(this.platformId) ? 'Browser' : 'Server';
    console.log(`InventarioService (HTTP - ${entorno}): Intentando cargar productos desde ${this.apiUrl}/productos`);

    this.http.get<Producto[]>(`${this.apiUrl}/productos`) // HttpClient se encarga del TransferState
    .pipe(
      map(productosApi => { // Recibe los productos crudos
        if (!Array.isArray(productosApi)) {
          console.warn(`InventarioService (HTTP - ${entorno}): La respuesta de /api/productos no es un array. Respuesta:`, productosApi);
          throw new Error('Formato de respuesta de API incorrecto: no es un array.');
        }
        return productosApi; // Devolver productos crudos
      }),
      catchError(this.handleError.bind(this)),
      // first() // Considera si realmente lo necesitas. HttpClient.get() emite una vez y completa.
               // Podría ser útil si temes múltiples emisiones por alguna razón externa.
    ).subscribe({
      next: (productosCargados) => { // productosCargados son los crudos de la API
        console.log(`InventarioService (HTTP - ${entorno}): ${productosCargados.length} productos crudos recibidos.`);
        // Procesar para añadir displayUrl antes de emitir al BehaviorSubject
        this.productosSubject.next(this.procesarProductosParaDisplay(productosCargados));
        this.isLoading.next(false);
        if (isPlatformServer(this.platformId)) {
            console.log('InventarioService (Servidor): Petición GET a /productos completada. HttpClient se encarga de TransferState.');
        }
      },
      error: (error) => {
        console.error(`InventarioService (HTTP - ${entorno}): Error CRÍTICO al cargar productos:`, error.message || error);
        this.productosSubject.next([]);
        this.isLoading.next(false);
      }
    });
  }

  refrescarProductos(): void {
    console.log('InventarioService: Solicitud de refrescarProductos().');
    // Forzar una nueva carga desde HTTP. Si TransferState está activo para GETs,
    // el cliente podría seguir obteniendo del cache si la URL es idéntica y no ha expirado.
    // Para un refresco real, a veces se añaden query params únicos (ej. timestamp) si el cache es agresivo.
    // Pero para el SSR, el servidor siempre hará la petición.
    this.cargarProductosDesdeHttp();
  }

  obtenerProductos(): Observable<(Producto & { displayUrl?: string })[]> {
    // El BehaviorSubject ya tiene el último valor o se cargará.
    // La lógica de recarga si está vacío en el cliente se puede simplificar
    // ya que el constructor se encarga de la carga inicial.
    return this.productos$;
  }

  obtenerProductoPorId(id: number): Observable<Producto> {
    return this.http.get<Producto>(`${this.apiUrl}/productos/${id}`).pipe(
      map(p => ({...p})),
      catchError(this.handleError.bind(this))
    );
  }

  // Para agregar, actualizar, eliminar, y saveFile, el TransferState automático de GET no aplica.
  // Estos son métodos que modifican datos.
  agregarProducto(productoData: Omit<Producto, 'id'>): Observable<Producto> {
    return this.http.post<Producto>(`${this.apiUrl}/productos`, productoData).pipe(
      tap(() => this.refrescarProductos()), // Refrescar la lista después de la operación
      catchError(this.handleError.bind(this))
    );
  }

  actualizarProducto(id: number, productoData: Partial<Omit<Producto, 'id'>>): Observable<Producto> {
    return this.http.put<Producto>(`${this.apiUrl}/productos/${id}`, productoData).pipe(
      tap(() => this.refrescarProductos()),
      catchError(this.handleError.bind(this))
    );
  }

  eliminarProducto(id: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/productos/${id}`).pipe(
      tap(() => this.refrescarProductos()),
      catchError(this.handleError.bind(this))
    );
  }

  actualizarProductoCantidadServidor(id: number, cantidadAfectada: number, operacion: 'sumar' | 'restar'): Observable<Producto> {
    return this.obtenerProductoPorId(id).pipe(
      switchMap(productoActual => {
        if (!productoActual) {
          return throwError(() => new Error(`Producto con ID ${id} no encontrado.`));
        }
        let nuevaCantidadStock = productoActual.cantidad || 0;
        if (operacion === 'sumar') {
          nuevaCantidadStock += Math.abs(cantidadAfectada);
        } else {
          nuevaCantidadStock -= Math.abs(cantidadAfectada);
          if (nuevaCantidadStock < 0) {
            this.isLoading.next(false);
            return throwError(() => new Error(`Stock insuficiente para ${productoActual.nombre}. Solicitado: ${Math.abs(cantidadAfectada)}, Disponible: ${productoActual.cantidad}, Resultante: ${nuevaCantidadStock}`));
          }
        }
        const updatePayload: Producto = { 
          id: productoActual.id, 
          nombre: productoActual.nombre,
          precio: productoActual.precio,
          imagen: productoActual.imagen, 
          cantidad: nuevaCantidadStock 
        };
  
        // Llamar a http.put directamente en lugar de this.actualizarProducto para evitar un ciclo de refresco si no es necesario
        return this.http.put<Producto>(`${this.apiUrl}/productos/${id}`, updatePayload).pipe(
          tap((productoActualizadoDelBackend) => {
              console.log('InventarioService: Cantidad de producto actualizada en backend, refrescando lista global.');
              this.refrescarProductos(); 
          })
      );
      }),
      catchError(err => {
        console.error(`Error en actualizarProductoCantidadServidor para ID ${id}:`, err.message || err);
        return throwError(() => err instanceof Error ? err : new Error(String(err.message || err)));
      })
    );
  }

  saveFile(file: File): Observable<{ path: string }> {
    const formData = new FormData();
    formData.append('file', file, file.name);
    return this.http.post<{ path: string }>(`${this.apiUrl}/upload`, formData).pipe(
      catchError(this.handleError.bind(this))
    );
  }

  deleteFile(filename: string): Observable<void> {
    const justFilename = filename.includes('/') ? filename.substring(filename.lastIndexOf('/') + 1) : filename;
    return this.http.delete<void>(`${this.apiUrl}/files/${encodeURIComponent(justFilename)}`).pipe(
      catchError(this.handleError.bind(this))
    );
  }

  private handleError(error: HttpErrorResponse) {
    let errorMessage = `Error desconocido en InventarioService. Status: ${error.status}. URL: ${error.url || 'No URL'}`;
    const entorno = isPlatformBrowser(this.platformId) ? 'Browser' : 'Server';

    if (isPlatformBrowser(this.platformId)) {
      if (error.error instanceof ErrorEvent) {
        errorMessage = `Error del cliente (${entorno}): ${error.error.message}`;
      } else if (error.name === 'HttpErrorResponse' && error.status === 0) {
        errorMessage = `Error de red o CORS (${entorno}) al intentar alcanzar ${error.url}. (Status: 0)`;
      } else if (error.error && typeof error.error.message === 'string') {
        errorMessage = `Error del servidor (API) (${entorno}): ${error.error.message} (Status: ${error.status})`;
      } else if (typeof error.message === 'string') {
        errorMessage = `Error (${entorno}): ${error.message} (Status: ${error.status})`;
      }
    } else { // Server-side
        // ... (lógica de error del servidor sin cambios)
      if (error.error && typeof error.error.message === 'string') {
        errorMessage = `Error del servidor (API) durante SSR: ${error.error.message} (Status: ${error.status})`;
      } else if (typeof error.message === 'string') {
        errorMessage = `Error durante SSR: ${error.message} (Status: ${error.status})`;
      } else if (error.name === 'HttpErrorResponse' && error.url) {
        errorMessage = `Fallo de petición HTTP durante SSR a ${error.url}. Status: ${error.status}, StatusText: ${error.statusText}`;
      }
    }
    console.error('InventarioService handleError:', errorMessage, error);
    return throwError(() => new Error(errorMessage));
  }

  // Método para obtener solo los productos con stock para el catálogo público
  cargarProductosPublicos(): void {
    this.isLoading.next(true);
    this.http.get<Producto[]>(`${this.apiUrl}/productos`).pipe(
      map(productosApi => this.procesarProductosParaDisplay(productosApi)),
      catchError(this.handleError.bind(this))
    ).subscribe({
      next: (productosProcesados) => {
        this.productosSubject.next(productosProcesados);
        this.isLoading.next(false);
      },
      error: (error) => {
        this.productosSubject.next([]);
        this.isLoading.next(false);
      }
    });
  }
  
  // Método para obtener TODOS los productos para el inventario
  cargarInventarioCompleto(): void {
    this.isLoading.next(true);
    // Apuntamos a la nueva ruta de inventario que trae TODOS los productos
    this.http.get<Producto[]>(`${this.apiUrl}/inventario`).pipe(
      map(productosApi => this.procesarProductosParaDisplay(productosApi)),
      catchError(this.handleError.bind(this))
    ).subscribe({
      next: (productosProcesados) => {
        this.inventarioSubject.next(productosProcesados);
        this.isLoading.next(false);
      },
      error: (error) => {
        this.inventarioSubject.next([]);
        this.isLoading.next(false);
      }
    });
  }
}