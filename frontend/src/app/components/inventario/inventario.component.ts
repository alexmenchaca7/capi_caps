import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { HeaderComponent } from '../header/header.component';
import { InventarioService } from '../../services/inventario.service';
import { Producto } from '../../models/producto';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-inventario',
  standalone: true,
  imports: [CommonModule, FormsModule, HeaderComponent],
  templateUrl: './inventario.component.html',
  styleUrls: ['./inventario.component.css']
})
export class InventarioComponent implements OnInit, OnDestroy {
  productos: (Producto & { displayUrl?: string })[] = [];
  private productosSub: Subscription | undefined;

  nuevoProducto: Producto = new Producto(0, '', undefined, undefined, '');
  nuevoProductoImagenPreview: string | ArrayBuffer | null = null;

  productoSeleccionado: (Producto & { tempImagenPreview?: string; displayUrl?: string; }) = 
    new Producto(0, '', undefined, undefined, '');

  mostrarModal: boolean = false;
  selectedFile: File | null = null;
  mensajeExito: string | null = null;
  mensajeError: string | null = null;

  constructor(public inventarioService: InventarioService, private router: Router) {}

  ngOnInit(): void {
    this.productosSub = this.inventarioService.obtenerProductos().subscribe({
      next: (productosConDisplayUrl) => {
        this.productos = productosConDisplayUrl;
      },
      error: (error) => {
        console.error('Error al cargar productos en InventarioComponent:', error);
        this.mostrarMensajeError(error.message || 'Error al cargar productos.');
      }
    });
  }

  ngOnDestroy(): void {
    if (this.productosSub) {
      this.productosSub.unsubscribe();
    }
  }

  onFileSelected(event: Event, isUpdate: boolean = false): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      this.selectedFile = input.files[0];
      const reader = new FileReader();
      reader.onload = () => {
        if (isUpdate && this.productoSeleccionado) {
          this.productoSeleccionado.tempImagenPreview = reader.result as string;
        } else {
          this.nuevoProductoImagenPreview = reader.result;
        }
      };
      reader.readAsDataURL(this.selectedFile);
    } else {
      this.selectedFile = null;
      if (isUpdate && this.productoSeleccionado) {
        this.productoSeleccionado.tempImagenPreview = this.productoSeleccionado.displayUrl;
      } else {
        this.nuevoProductoImagenPreview = null;
      }
    }
  }

  agregarProducto(): void {
    if (!this.nuevoProducto.nombre?.trim() || this.nuevoProducto.cantidad === undefined || this.nuevoProducto.precio === undefined) {
      this.mostrarMensajeError('Nombre, cantidad y precio son obligatorios.');
      return;
    }
    if (Number(this.nuevoProducto.precio) <= 0 || Number(this.nuevoProducto.cantidad) < 0) {
        this.mostrarMensajeError('Precio debe ser mayor a 0 y cantidad no puede ser negativa.');
        return;
    }
    if (!this.selectedFile) {
      this.mostrarMensajeError('Debe seleccionar una imagen para el nuevo producto.');
      return;
    }

    this.inventarioService.saveFile(this.selectedFile).subscribe({
      next: (uploadResponse) => {
        const productoParaGuardar: Omit<Producto, 'id'> = {
          nombre: this.nuevoProducto.nombre!,
          cantidad: Number(this.nuevoProducto.cantidad),
          precio: Number(this.nuevoProducto.precio),
          imagen: uploadResponse.path
        };

        this.inventarioService.agregarProducto(productoParaGuardar).subscribe({
          next: () => {
            this.mostrarMensajeExito('Producto agregado con éxito!');
            this.nuevoProducto = new Producto(0, '', undefined, undefined, '');
            this.selectedFile = null;
            this.nuevoProductoImagenPreview = null;
          },
          error: (error) => this.mostrarMensajeError(`Error al guardar el producto: ${error.message || 'Error desconocido'}`)
        });
      },
      error: (error) => {
        console.error('Error subiendo imagen al agregar:', error);
        this.mostrarMensajeError(`Error al subir la imagen: ${error.message || 'Error desconocido'}`);
      }
    });
  }

  // abrirModal ahora solo toma un argumento 'producto'
  abrirModal(producto: Producto & { displayUrl?: string }): void {
    this.productoSeleccionado = {
        ...producto,
        precio: producto.precio !== undefined ? Number(producto.precio) : undefined,
        cantidad: producto.cantidad !== undefined ? Number(producto.cantidad) : undefined,
        tempImagenPreview: producto.displayUrl || 'assets/default.webp'
    };
    this.mostrarModal = true;
    this.selectedFile = null;
    document.body.style.overflow = 'hidden';
  }

  cerrarModal(event?: MouseEvent): void {
    if (event) {
      const target = event.target as HTMLElement;
      if (target.classList.contains('modal')) {
        this.mostrarModal = false;
        document.body.style.overflow = 'auto';
      }
    } else {
      this.mostrarModal = false;
      document.body.style.overflow = 'auto';
    }
    this.selectedFile = null;
    if (this.productoSeleccionado) {
        this.productoSeleccionado.tempImagenPreview = undefined;
    }
  }

  actualizarProducto(): void {
    if (!this.productoSeleccionado || !this.productoSeleccionado.id) {
        this.mostrarMensajeError('No hay producto seleccionado para actualizar o falta ID.');
        return;
    }
    if (!this.productoSeleccionado.nombre?.trim() || this.productoSeleccionado.cantidad === undefined || this.productoSeleccionado.precio === undefined) {
      this.mostrarMensajeError('Nombre, cantidad y precio son obligatorios.');
      return;
    }
    if (Number(this.productoSeleccionado.precio) <= 0 || Number(this.productoSeleccionado.cantidad) < 0) {
        this.mostrarMensajeError('Precio debe ser mayor a 0 y cantidad no puede ser negativa.');
        return;
    }

    const datosActualizados: Partial<Omit<Producto, 'id'>> = {
        nombre: this.productoSeleccionado.nombre,
        cantidad: Number(this.productoSeleccionado.cantidad),
        precio: Number(this.productoSeleccionado.precio),
        imagen: this.productoSeleccionado.imagen
    };

    const proceedWithActualUpdate = (nuevaRutaImagenRelativa?: string) => {
        if (nuevaRutaImagenRelativa) {
            datosActualizados.imagen = nuevaRutaImagenRelativa;
        }

        this.inventarioService.actualizarProducto(this.productoSeleccionado.id, datosActualizados).subscribe({
            next: () => {
                this.mostrarMensajeExito('Producto actualizado con éxito!');
                this.cerrarModal();
            },
            error: (error) => this.mostrarMensajeError(`Error al actualizar el producto: ${error.message || 'Error desconocido'}`)
        });
    };

    if (this.selectedFile) {
        this.inventarioService.saveFile(this.selectedFile).subscribe({
            next: (uploadResponse) => {
                const imagenOriginalRelativa = this.productoSeleccionado.imagen;
                if (imagenOriginalRelativa && imagenOriginalRelativa !== uploadResponse.path && imagenOriginalRelativa.startsWith('uploads/')) {
                    const nombreArchivoOriginal = imagenOriginalRelativa.split('/').pop();
                    if (nombreArchivoOriginal) {
                        this.inventarioService.deleteFile(nombreArchivoOriginal).subscribe({
                            next: () => console.log('Archivo de imagen anterior eliminado: ' + nombreArchivoOriginal),
                            error: (err) => console.warn('No se pudo eliminar el archivo de imagen anterior:', err.message)
                        });
                    }
                }
                proceedWithActualUpdate(uploadResponse.path);
            },
            error: (error) => {
                console.error('Error subiendo nueva imagen al actualizar:', error);
                this.mostrarMensajeError(`Error al subir la nueva imagen: ${error.message || 'Error desconocido'}`);
            }
        });
    } else {
        proceedWithActualUpdate();
    }
  }

  eliminarProducto(productoId: number): void {
    if (!confirm('¿Estás seguro de que quieres eliminar este producto?')) {
        return;
    }
    const productoAEliminar = this.productos.find(p => p.id === productoId);
    this.inventarioService.eliminarProducto(productoId).subscribe({
      next: () => {
        this.mostrarMensajeExito('Producto eliminado con éxito!');
        if (productoAEliminar && productoAEliminar.imagen && productoAEliminar.imagen.startsWith('uploads/')) {
          const nombreArchivo = productoAEliminar.imagen.split('/').pop();
          if (nombreArchivo) {
            this.inventarioService.deleteFile(nombreArchivo).subscribe({
              next: () => console.log(`Archivo de imagen ${nombreArchivo} eliminado del servidor.`),
              error: (err) => console.warn(`No se pudo eliminar el archivo de imagen ${nombreArchivo} de uploads:`, err.message)
            });
          }
        }
      },
      error: (error) => {
        console.error("Error completo al eliminar:", error);
        this.mostrarMensajeError(`Error al eliminar: ${error.message || 'Error desconocido'}`);
      }
    });
  }

  irAProductos(): void {
    this.router.navigate(['/productos']);
  }

  private mostrarMensajeExito(mensaje: string): void {
    this.mensajeExito = mensaje;
    this.mensajeError = null;
    setTimeout(() => this.mensajeExito = null, 3000);
  }

  private mostrarMensajeError(mensaje: string): void {
    this.mensajeError = mensaje;
    this.mensajeExito = null;
    setTimeout(() => this.mensajeError = null, 3000);
  }

  validarNumero(event: Event): void {
    const input = event.target as HTMLInputElement;
    input.value = input.value.replace(/[^0-9.]/g, '').replace(/(\..*)\./g, '$1');
  }
}