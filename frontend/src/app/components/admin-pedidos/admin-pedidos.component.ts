import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { PedidoService } from '../../services/pedido.service';
import { Pedido } from '../../models/pedido';
import { HeaderComponent } from '../header/header.component';

@Component({
  selector: 'app-admin-pedidos',
  standalone: true,
  imports: [CommonModule, HeaderComponent],
  templateUrl: './admin-pedidos.component.html',
  styleUrls: ['./admin-pedidos.component.css']
})
export class AdminPedidosComponent implements OnInit {
  pedidos: Pedido[] = [];
  isLoading = true;
  error: string | null = null;
  
  private readonly backendUrl = 'http://localhost:8080/api'; 

  constructor(private pedidoService: PedidoService) { }

  ngOnInit(): void {
    this.pedidoService.obtenerTodosLosPedidos().subscribe({
      next: (data) => {
        this.pedidos = data.map(pedido => ({
          ...pedido,
          detalles_pedido: typeof pedido.detalles_pedido === 'string' 
            ? JSON.parse(pedido.detalles_pedido) 
            : pedido.detalles_pedido
        }));
        this.isLoading = false;
      },
      error: (err) => {
        this.error = 'No se pudo cargar el historial de pedidos. Asegúrate de tener permisos de administrador.';
        this.isLoading = false;
        console.error(err);
      }
    });
  }

  obtenerUrlRecibo(pedidoId: number): string {
    return `${this.backendUrl}/pedidos/${pedidoId}/recibo`;
  }

  descargar(pedidoId: number): void {
    this.pedidoService.descargarRecibo(pedidoId).subscribe({
      next: (blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `recibo-pedido-${pedidoId}.xml`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      },
      error: (err) => {
        console.error('Error al descargar el recibo:', err);
        alert('No se pudo descargar el recibo.');
      }
    });
  }
}