import { Component, OnInit, OnDestroy, ChangeDetectorRef, Inject, PLATFORM_ID, NgZone } from '@angular/core';
import { isPlatformBrowser, CommonModule } from '@angular/common';
import { CarritoService } from '../../services/carrito.service';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { HeaderComponent } from '../header/header.component';
import { CarritoItem } from '../../models/carrito-item';
import { forkJoin, of, lastValueFrom, Subscription } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

declare var paypal: any;

interface DetallesCompraParaModal {
  transactionId: string;
  totalPagado: number;
  itemsComprados: CarritoItem[];
  reciboXML: string;
  fallosStock?: { productoNombre: string; mensajeError?: string }[];
}

@Component({
  selector: 'app-carrito',
  standalone: true,
  imports: [CommonModule, FormsModule, HeaderComponent],
  templateUrl: './carrito.component.html',
  styleUrls: ['./carrito.component.css']
})
export class CarritoComponent implements OnInit, OnDestroy {
  public carrito: CarritoItem[] = [];
  private carritoSubscription: Subscription | undefined;

  // Propiedades para PayPal y el modal
  private paypalButtonRendered = false;
  private paypalScriptLoading = false;
  public errorPayPalInit = false;
  public mostrarModalConfirmacion: boolean = false;
  public detallesCompra: DetallesCompraParaModal | null = null;

  constructor(
    public carritoService: CarritoService,
    private router: Router,
    private cdr: ChangeDetectorRef,
    @Inject(PLATFORM_ID) private platformId: Object,
    private zone: NgZone
  ) {}

  ngOnInit() {
    this.carritoSubscription = this.carritoService.carrito$.subscribe(carritoItems => {
      this.carrito = carritoItems;
      this.cdr.detectChanges();
      if (isPlatformBrowser(this.platformId)) {
        this.renderPayPalButton();
      }
    });
  }

  ngOnDestroy(): void {
    if (this.carritoSubscription) {
      this.carritoSubscription.unsubscribe();
    }
  }

  // ==================================================================
  // ===== INICIO DE LA CORRECCIÓN CON ENFOQUE INMUTABLE ======
  // ==================================================================
  actualizarCantidad(carritoId: number, nuevaCantidad: number | null) {
    if (nuevaCantidad === null || isNaN(nuevaCantidad)) {
      return;
    }
  
    const itemIndex = this.carrito.findIndex(p => p.carritoId === carritoId);
    if (itemIndex === -1) return;
  
    const item = this.carrito[itemIndex];
  
    // Si la cantidad nueva supera el stock, mostramos alerta y revertimos
    if (nuevaCantidad > item.stock) {
      alert(`Lo sentimos, solo quedan ${item.stock} unidades de "${item.nombre}". No puedes agregar más.`);
  
      // CREAMOS UN NUEVO ARRAY: Esta es la forma más robusta de notificar a Angular de un cambio.
      this.carrito = this.carrito.map((cartItem, index) => {
        if (index === itemIndex) {
          // Creamos un nuevo objeto para el item modificado
          return { ...cartItem, cantidadEnCarrito: item.stock };
        }
        // Devolvemos los otros items sin cambios
        return cartItem;
      });
  
      this.renderPayPalButton(); // Actualizamos el total para PayPal
      return;
    }
  
    // Si la cantidad es válida, simplemente la actualizamos en el modelo local
    if (item.cantidadEnCarrito !== nuevaCantidad) {
      const cantidadFinal = Math.max(1, nuevaCantidad);
      if (item.cantidadEnCarrito !== cantidadFinal) {
        item.cantidadEnCarrito = cantidadFinal;
        this.renderPayPalButton();
      }
    }
  }
  // ================================================================
  // ========= FIN DE LA CORRECCIÓN CON ENFOQUE INMUTABLE ===========
  // ================================================================

  calcularSubtotal(): number {
    return this.carrito.reduce((sub, prod) => sub + (Number(prod.precio) ?? 0) * (prod.cantidadEnCarrito ?? 0), 0);
  }
  calcularIVA(): number { return this.calcularSubtotal() * 0.16; }
  calcularTotal(): number { return this.calcularSubtotal() + this.calcularIVA(); }
  
  eliminarProducto(carritoId: number) {
    this.carritoService.eliminarProducto(carritoId);
  }

  private renderPayPalButton() {
    if (!isPlatformBrowser(this.platformId)) return;
    
    if (this.carrito.length === 0 || this.mostrarModalConfirmacion) {
        const container = document.getElementById('paypal-button-container');
        if (container) container.innerHTML = '';
        this.paypalButtonRendered = false;
        return;
    }

    if (typeof paypal === 'undefined') {
        if (!this.paypalScriptLoading) this.loadPayPalScript();
        return;
    }
    
    const container = document.getElementById('paypal-button-container');
    if (!container) return;

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

                const actualizacionesObservables = itemsComprados.map(item =>
                  this.carritoService.actualizarInventario(item.producto_id, item.cantidadEnCarrito, 'restar').pipe(
                    map(() => ({ success: true, productoNombre: item.nombre })),
                    catchError(err => of({ success: false, productoNombre: item.nombre, mensajeError: err.error?.message || 'Error desconocido' }))
                  )
                );
                const resultadosStock = await lastValueFrom(forkJoin(actualizacionesObservables));
                const fallosStock = resultadosStock.filter(r => !r.success);
                
                const reciboXMLGenerado = this.generarReciboXMLConItems(itemsComprados, totalPagado, this.calcularIVAconItems(itemsComprados), details.id);

                this.detallesCompra = {
                  transactionId: details.id, totalPagado, itemsComprados, reciboXML: reciboXMLGenerado,
                  fallosStock: fallosStock.length > 0 ? fallosStock : undefined
                };

                if (fallosStock.length === 0) {
                  this.carritoService.limpiarCarrito();
                } else {
                  alert('¡Atención! Tu pago fue exitoso, pero hubo un problema al reservar algunos productos. Por favor, contacta a soporte.');
                }
                this.mostrarModalConfirmacion = true;
                this.cdr.detectChanges();
              } catch (err) {
                console.error('Error crítico en el proceso de pago (onApprove):', err);
                alert('Hubo un error al procesar tu pago. Por favor, intenta de nuevo.');
              }
            }
        }).render('#paypal-button-container').then(() => {
            this.paypalButtonRendered = true;
        });
    });
  }

  private loadPayPalScript() {
    if (this.paypalScriptLoading || typeof paypal !== 'undefined') return;

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
      console.error("No se pudo cargar el script de PayPal.");
    };
    document.body.appendChild(script);
  }

  descargarReciboDelModal() {
    if (!isPlatformBrowser(this.platformId) || !this.detallesCompra?.reciboXML) return;
    const blob = new Blob([this.detallesCompra.reciboXML], { type: 'application/xml' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `recibo_${this.detallesCompra.transactionId}.xml`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
  }

  irAProductos(): void {
    this.router.navigate(['/productos']);
  }

  cerrarModalConfirmacionYRedirigir(): void {
    this.mostrarModalConfirmacion = false;
    this.detallesCompra = null;
    this.router.navigate(['/productos']);
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

  private calcularIVAconItems(items: CarritoItem[]): number {
    const subtotal = items.reduce((sub, prod) => sub + (Number(prod.precio) ?? 0) * (prod.cantidadEnCarrito ?? 0), 0);
    return subtotal * 0.16;
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