import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HeaderComponent } from '../header/header.component';
import { Producto } from '../../models/producto';
import { InventarioService } from '../../services/inventario.service';
import { CarritoService } from '../../services/carrito.service'; // Importar CarritoService
import { CarritoItem } from '../../models/carrito-item'; // Importar CarritoItem
import { Router } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-producto',
  standalone: true,
  imports: [CommonModule, FormsModule, HeaderComponent],
  templateUrl: './producto.component.html',
  styleUrls: ['./producto.component.css']
})
export class ProductoComponent implements OnInit, OnDestroy {
  productos: (Producto & { displayUrl?: string })[] = [];
  private productosSub: Subscription | undefined;
  
  // Propiedades para manejar el estado del carrito
  private carrito: CarritoItem[] = [];
  private carritoSub: Subscription | undefined;

  mensajeExito: boolean = false;
  mensajeError: string | null = null;

  constructor(
    public inventarioService: InventarioService,
    private carritoService: CarritoService, // Inyectar CarritoService
    private router: Router
  ) {}

  ngOnInit(): void {
    this.productosSub = this.inventarioService.obtenerProductos().subscribe({
      next: (productosConDisplayUrl) => {
        this.productos = productosConDisplayUrl;
      },
      error: (error) => {
        this.mensajeError = `Error al cargar productos: ${error.message || 'Error desconocido'}`;
      }
    });

    // 3. Nos suscribimos a los cambios del carrito
    this.carritoSub = this.carritoService.carrito$.subscribe(items => {
      this.carrito = items;
    });
  }

  ngOnDestroy(): void {
    if (this.productosSub) this.productosSub.unsubscribe();
    if (this.carritoSub) this.carritoSub.unsubscribe(); // Limpiar suscripción
  }

  agregarAlCarrito(producto: Producto & { displayUrl?: string }): void {
    const itemEnCarrito = this.carrito.find(item => item.producto_id === producto.id);
    const cantidadActualEnCarrito = itemEnCarrito ? itemEnCarrito.cantidadEnCarrito : 0;

    // Verificamos si agregar uno más superaría el stock total
    if (cantidadActualEnCarrito >= (producto.cantidad ?? 0)) {
      this.mensajeError = '¡Has alcanzado el límite de stock para este producto!';
      setTimeout(() => this.mensajeError = null, 3000);
      return;
    }

    this.carritoService.agregarProducto(producto);
    this.mensajeExito = true;
    setTimeout(() => this.mensajeExito = false, 3000);
  }

  irAlCarrito(): void {
    this.router.navigate(['/carrito']);
  }

  irAlInventario(): void {
    this.router.navigate(['/inventario']);
  }
}