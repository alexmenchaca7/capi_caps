import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common'; 
import { PedidoService } from '../../services/pedido.service';
import { Pedido } from '../../models/pedido';
import { HeaderComponent } from '../header/header.component';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-historial-pedidos',
  standalone: true,
  imports: [CommonModule, HeaderComponent],
  templateUrl: './historial-pedidos.component.html',
  styleUrls: ['./historial-pedidos.component.css']
})
export class HistorialPedidosComponent implements OnInit {
  pedidos: Pedido[] = [];
  isLoading = true;
  error: string | null = null;
  
  private readonly backendUrl = 'http://localhost:8080/api'; 

  constructor(
    private pedidoService: PedidoService,
    private authService: AuthService
  ) { }

  ngOnInit(): void {
    this.pedidoService.obtenerMisPedidos().subscribe({
      next: (data) => {
        // Asegurarse de que detalles_pedido sea un array
        this.pedidos = data.map(pedido => ({
          ...pedido,
          detalles_pedido: typeof pedido.detalles_pedido === 'string' 
            ? JSON.parse(pedido.detalles_pedido) 
            : pedido.detalles_pedido
        }));
        this.isLoading = false;
      },
      error: (err) => {
        this.error = 'No se pudo cargar el historial de pedidos. Inténtalo más tarde.';
        this.isLoading = false;
        console.error(err);
      }
    });
  }

  obtenerUrlRecibo(pedidoId: number): string {
    // El interceptor se encarga de añadir el token de autenticación.
    return `${this.backendUrl}/pedidos/${pedidoId}/recibo`;
  }

  descargar(pedidoId: number): void {
    this.pedidoService.descargarRecibo(pedidoId).subscribe(blob => {
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `recibo-pedido-${pedidoId}.xml`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    });
  }
}