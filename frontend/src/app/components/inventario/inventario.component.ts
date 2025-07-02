import { Component, OnInit, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { HeaderComponent } from '../header/header.component';
import { InventarioService } from '../../services/inventario.service';
import { Producto } from '../../models/producto';
import { Subscription, Observable } from 'rxjs';

@Component({
  selector: 'app-inventario',
  standalone: true,
  imports: [CommonModule, FormsModule, HeaderComponent],
  templateUrl: './inventario.component.html',
  styleUrls: ['./inventario.component.css']
})
export class InventarioComponent implements OnInit, OnDestroy {
  // --- Propiedades para la Tabla y Datos ---
  productos: (Producto & { displayUrl?: string })[] = [];
  private inventarioSub!: Subscription;
  isLoading$: Observable<boolean>;

  // --- Propiedades para el Modal y el Formulario ---
  mostrarModal = false;
  productoActual: Partial<Producto & { tempImagenPreview?: string }> = {};
  isEditMode = false;
  
  // --- Propiedades para el Manejo de Archivos ---
  selectedFile: File | null = null;
  
  // --- Propiedades para Mensajes de Feedback ---
  mensaje = '';
  mensajeError = '';

  constructor(
    public inventarioService: InventarioService, 
    private router: Router
  ) {
    this.isLoading$ = this.inventarioService.isLoading$;
  }

  ngOnInit(): void {
    this.inventarioSub = this.inventarioService.inventario$.subscribe({
      next: (productosDelInventario) => {
        this.productos = productosDelInventario;
      },
      error: (error) => {
        this.mostrarMensajeError(error.message || 'Error al cargar el inventario.');
      }
    });

    this.inventarioService.cargarInventarioCompleto();
  }

  ngOnDestroy(): void {
    if (this.inventarioSub) {
      this.inventarioSub.unsubscribe();
    }
     // Asegurarnos de limpiar la clase del body si el componente se destruye
    document.body.classList.remove('modal-open');
  }

  // --- Métodos para el Modal ---

  abrirModal(producto?: Producto & { displayUrl?: string }): void {
    this.limpiarMensajes();
    this.selectedFile = null;

    if (producto) {
      this.isEditMode = true;
      this.productoActual = { 
        ...producto,
        tempImagenPreview: producto.displayUrl || 'assets/default.webp'
      };
    } else {
      this.isEditMode = false;
      this.productoActual = {
        nombre: '',
        precio: undefined,
        cantidad: undefined,
        imagen: '',
        tempImagenPreview: 'assets/default.webp'
      };
    }
    this.mostrarModal = true;
    // Añadimos la clase al body para bloquear el scroll
    document.body.classList.add('modal-open');
  }

  cerrarModal(): void {
    this.mostrarModal = false;
    this.productoActual = {};
    // Quitamos la clase del body para restaurar el scroll
    document.body.classList.remove('modal-open');
  }

  // --- Métodos para el Formulario y CRUD ---

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      this.selectedFile = input.files[0];
      const reader = new FileReader();
      reader.onload = () => {
        if (this.productoActual) {
          this.productoActual.tempImagenPreview = reader.result as string;
        }
      };
      reader.readAsDataURL(this.selectedFile);
    }
  }

  guardarProducto(): void {
    if (!this.productoActual.nombre?.trim() || this.productoActual.cantidad === undefined || this.productoActual.precio === undefined) {
      this.mostrarMensajeError('Nombre, cantidad y precio son obligatorios.');
      return;
    }
    if (Number(this.productoActual.precio) <= 0 || Number(this.productoActual.cantidad) < 0) {
      this.mostrarMensajeError('El precio debe ser mayor a 0 y la cantidad no puede ser negativa.');
      return;
    }
    if (!this.isEditMode && !this.selectedFile) {
        this.mostrarMensajeError('Debe seleccionar una imagen para el nuevo producto.');
        return;
    }

    const guardarDatosProducto = (rutaImagen?: string) => {
      const datosParaGuardar: Partial<Producto> = {
        nombre: this.productoActual.nombre,
        cantidad: Number(this.productoActual.cantidad),
        precio: Number(this.productoActual.precio),
        imagen: rutaImagen ?? this.productoActual.imagen
      };

      const accion$ = this.isEditMode
        ? this.inventarioService.actualizarProducto(this.productoActual.id!, datosParaGuardar)
        : this.inventarioService.agregarProducto(datosParaGuardar as Producto);

      accion$.subscribe({
        next: () => {
          this.mostrarMensaje(`Producto ${this.isEditMode ? 'actualizado' : 'agregado'} con éxito.`);
          this.cerrarModal();
        },
        error: (err) => this.mostrarMensajeError(err.message || 'Ocurrió un error al guardar.')
      });
    };

    if (this.selectedFile) {
      this.inventarioService.saveFile(this.selectedFile).subscribe({
        next: (uploadResponse) => {
          guardarDatosProducto(uploadResponse.path);
        },
        error: (err) => this.mostrarMensajeError(err.message || 'Error al subir la imagen.')
      });
    } else {
      guardarDatosProducto();
    }
  }

  eliminarProducto(productoId?: number): void {
    if (productoId === undefined) return;

    if (confirm('¿Estás seguro de que deseas eliminar este producto? Esta acción no se puede deshacer.')) {
      this.inventarioService.eliminarProducto(productoId).subscribe({
        next: () => {
          this.mostrarMensaje('Producto eliminado con éxito.');
        },
        error: (err) => this.mostrarMensajeError(err.message || 'Error al eliminar el producto.')
      });
    }
  }

  // --- Métodos de Utilidad (Feedback al usuario) ---

  private mostrarMensaje(mensaje: string): void {
    this.limpiarMensajes();
    this.mensaje = mensaje;
    setTimeout(() => this.mensaje = '', 4000);
  }

  private mostrarMensajeError(mensaje: string): void {
    this.limpiarMensajes();
    this.mensajeError = mensaje;
    setTimeout(() => this.mensajeError = '', 5000);
  }
  
  private limpiarMensajes(): void {
      this.mensaje = '';
      this.mensajeError = '';
  }
}