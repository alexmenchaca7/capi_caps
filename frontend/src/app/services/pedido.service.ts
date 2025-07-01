import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Pedido } from '../models/pedido';

@Injectable({
  providedIn: 'root'
})
export class PedidoService {
  private API_URL = 'http://localhost:8080/api/pedidos';

  constructor(private http: HttpClient) { }

  obtenerMisPedidos(): Observable<Pedido[]> {
    return this.http.get<Pedido[]>(`${this.API_URL}/mis-pedidos`);
  }

  obtenerTodosLosPedidos(): Observable<Pedido[]> {
    return this.http.get<Pedido[]>(`${this.API_URL}/todos`);
  }

  descargarRecibo(pedidoId: number): Observable<Blob> {
    return this.http.get(`${this.API_URL}/${pedidoId}/recibo`, {
      responseType: 'blob' // Muy importante: le decimos a HttpClient que esperamos un archivo
    });
  }
}
