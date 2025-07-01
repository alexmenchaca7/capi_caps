// src/app/components/carrito/carrito.component.ts

import { Component, OnInit, OnDestroy, ChangeDetectorRef, Inject, PLATFORM_ID, NgZone } from '@angular/core';
import { CommonModule, isPlatformBrowser } from '@angular/common';
import { Router } from '@angular/router';
import { FormsModule } from '@angular/forms'; // Necesario para ngModel
import { Subscription, lastValueFrom } from 'rxjs';

import { CarritoService } from '../../services/carrito.service';
import { CarritoItem } from '../../models/carrito-item';
import { HeaderComponent } from '../header/header.component'; // Importar Header

declare var paypal: any;

// Interface para los detalles de la compra en el modal
interface DetallesCompraParaModal {
  transactionId: string;
  totalPagado: number;
  itemsComprados: CarritoItem[];
  reciboXML: string;
}

@Component({
  selector: 'app-carrito',
  standalone: true,
  imports: [
    CommonModule, 
    FormsModule, // Añadir FormsModule
    HeaderComponent // Añadir HeaderComponent
  ],
  templateUrl: './carrito.component.html',
  styleUrls: ['./carrito.component.css']
})
export class CarritoComponent implements OnInit, OnDestroy {
  public carrito: CarritoItem[] = [];
  private carritoSubscription!: Subscription;

  // Propiedades de estado y PayPal
  private paypalButtonRendered = false;
  private paypalScriptLoading = false;
  public errorPayPalInit = false;

  // Propiedades del Modal
  public mostrarModalConfirmacion = false;
  public detallesCompra: DetallesCompraParaModal | null = null;

  constructor(
    public carritoService: CarritoService,
    private cdr: ChangeDetectorRef,
    private router: Router,
    private zone: NgZone,
    @Inject(PLATFORM_ID) private platformId: Object
  ) {}

  ngOnInit(): void {
    this.carritoSubscription = this.carritoService.carrito$.subscribe(items => {
      this.carrito = items;
      this.cdr.detectChanges();
      if (isPlatformBrowser(this.platformId)) {
        // Usamos setTimeout para asegurar que el DOM esté listo
        setTimeout(() => this.renderPayPalButton(), 0);
      }
    });
  }

  ngOnDestroy(): void {
    if (this.carritoSubscription) {
      this.carritoSubscription.unsubscribe();
    }
  }
  
  private loadPayPalScript() {
    if (!isPlatformBrowser(this.platformId) || this.paypalScriptLoading || typeof paypal !== 'undefined') return;

    this.paypalScriptLoading = true;
    const script = document.createElement('script');
    script.src = `https://www.paypal.com/sdk/js?client-id=ARN4q4xSLo9k19e845bV04QIgO1_gELqDi913C7UyJppQdNYZ_Wug1AIkttyJUCBoqwIIhCFlVLyf3KS&currency=MXN&commit=true`;
    script.onload = () => {
      this.paypalScriptLoading = false;
      this.renderPayPalButton();
    };
    script.onerror = () => {
      this.paypalScriptLoading = false;
      this.errorPayPalInit = true;
      console.error("ERROR: No se pudo cargar el script de PayPal.");
      this.cdr.detectChanges();
    };
    document.body.appendChild(script);
  }

  private renderPayPalButton() {
    if (!isPlatformBrowser(this.platformId)) return;
    
    const container = document.getElementById('paypal-button-container');
    if (!container) return;

    if (this.carrito.length === 0 || this.mostrarModalConfirmacion) {
        container.innerHTML = '';
        this.paypalButtonRendered = false;
        return;
    }

    if (typeof paypal === 'undefined') {
        if (!this.paypalScriptLoading) this.loadPayPalScript();
        return;
    }
    
    // Lógica clave: Siempre limpiar el contenedor antes de renderizar para evitar conflictos.
    container.innerHTML = '';
    
    this.zone.run(() => {
        paypal.Buttons({
            createOrder: (data: any, actions: any) => {
              return actions.order.create({
                  purchase_units: [{
                      amount: {
                          value: this.calcularTotal().toFixed(2),
                          currency_code: 'MXN',
                          breakdown: {
                              item_total: { value: this.calcularSubtotal().toFixed(2), currency_code: 'MXN' },
                              tax_total: { value: this.calcularIVA().toFixed(2), currency_code: 'MXN' }
                          }
                      },
                      items: this.carrito.map((item: CarritoItem) => ({
                          name: item.nombre.substring(0, 127),
                          unit_amount: { value: (Number(item.precio) ?? 0).toFixed(2), currency_code: 'MXN' },
                          quantity: (item.cantidadEnCarrito ?? 0).toString(),
                          sku: item.producto_id.toString(),
                          category: 'PHYSICAL_GOODS'
                      }))
                  }]
              });
            },
            onApprove: async (data: any, actions: any) => {
              try {
                const details = await actions.order.capture();
                const itemsComprados = [...this.carrito];
                const totalPagado = this.calcularTotal();

                await lastValueFrom(this.carritoService.crearPedido(
                  details.id,
                  totalPagado,
                  itemsComprados
                ));
                
                const reciboXMLGenerado = this.generarReciboXMLConItems(itemsComprados, totalPagado, this.calcularIVAconItems(itemsComprados), details.id);

                this.detallesCompra = {
                  transactionId: details.id, 
                  totalPagado, 
                  itemsComprados, 
                  reciboXML: reciboXMLGenerado
                };
                
                this.mostrarModalConfirmacion = true;
                this.cdr.detectChanges();

              } catch (err: any) {
                console.error('Error crítico en el proceso de pago (onApprove):', err);
                alert('Hubo un error al procesar tu pago. Por favor, intenta de nuevo.');
              }
            }
        }).render('#paypal-button-container').then(() => {
            this.paypalButtonRendered = true;
        });
    });
  }

  private generarReciboXMLConItems(items: CarritoItem[], total: number, iva: number, transactionId: string): string {
    const subtotal = total - iva;
    let xml = `<?xml version="1.0" encoding="UTF-8"?>\n<recibo>\n`;
    xml += `  <tienda>${this.carritoService.tiendaNombre}</tienda>\n`;
    xml += `  <transactionId>${transactionId}</transactionId>\n`;
    xml += `  <fecha>${new Date().toISOString()}</fecha>\n`;
    xml += `  <productos>\n`;
    items.forEach((producto) => {
      xml += `    <producto id="${producto.producto_id}">\n`;
      xml += `      <nombre>${this.escapeXml(producto.nombre)}</nombre>\n`;
      xml += `      <precio>${(Number(producto.precio) ?? 0).toFixed(2)}</precio>\n`;
      xml += `      <cantidad>${producto.cantidadEnCarrito ?? 0}</cantidad>\n`;
      xml += `    </producto>\n`;
    });
    xml += `  </productos>\n`;
    xml += `  <resumen>\n`;
    xml += `    <subtotal>${subtotal.toFixed(2)}</subtotal>\n`;
    xml += `    <iva>${iva.toFixed(2)}</iva>\n`;
    xml += `    <total>${total.toFixed(2)}</total>\n`;
    xml += `  </resumen>\n`;
    xml += `</recibo>`;
    return xml;
  }

  cerrarModalConfirmacionYRedirigir(): void {
    this.mostrarModalConfirmacion = false;
    this.detallesCompra = null;
    this.carritoService.limpiarCarrito();
    this.router.navigate(['/productos']);
  }
  
  descargarReciboDelModal(): void {
    if (!this.detallesCompra) return;
    const blob = new Blob([this.detallesCompra.reciboXML], { type: 'application/xml' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recibo-${this.detallesCompra.transactionId}.xml`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }

  actualizarCantidad(carritoId: number, nuevaCantidad: number): void {
    if (nuevaCantidad === null || isNaN(nuevaCantidad)) {
      return;
    }
    
    const item = this.carrito.find(p => p.carritoId === carritoId);
    if (!item) return;

    const cantidadFinal = Math.max(1, nuevaCantidad);

    if (cantidadFinal > item.stock) {
      alert(`Lo sentimos, solo quedan ${item.stock} unidades de "${item.nombre}".`);
      item.cantidadEnCarrito = item.stock;
    } else {
      item.cantidadEnCarrito = cantidadFinal;
    }
    
    this.carritoService.actualizarCantidad(item.producto_id, item.cantidadEnCarrito);
    
    setTimeout(() => this.renderPayPalButton(), 0);
  }

  eliminarProducto(carritoId: number): void {
    if (confirm('¿Estás seguro de que quieres eliminar este producto del carrito?')) {
      const item = this.carrito.find(p => p.carritoId === carritoId);
      if (item) {
        this.carritoService.eliminarProducto(item.producto_id);
      }
    }
  }

  irAProductos(): void {
    this.router.navigate(['/productos']);
  }

  calcularSubtotal(): number {
    return this.carrito.reduce((acc, item) => acc + (Number(item.precio) || 0) * item.cantidadEnCarrito, 0);
  }

  calcularIVA(): number {
    return this.calcularSubtotal() * 0.16;
  }

  calcularIVAconItems(items: CarritoItem[]): number {
    const subtotal = items.reduce((acc, item) => acc + (Number(item.precio) || 0) * item.cantidadEnCarrito, 0);
    return subtotal * 0.16;
  }

  calcularTotal(): number {
    return this.calcularSubtotal() + this.calcularIVA();
  }

  private escapeXml(unsafe: string): string {
    if (typeof unsafe !== 'string') { return ''; }
    return unsafe.replace(/[<>&"']/g, function (c) {
      switch (c) {
        case '<': return '&lt;';
        case '>': return '&gt;';
        case '&': return '&amp;';
        case '"': return '&quot;';
        case '\'': return '&apos;';
        default: return c;
      }
    });
  }
}