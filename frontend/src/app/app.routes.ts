import { Routes } from '@angular/router';
import { ProductoComponent } from './components/producto/producto.component';
import { CarritoComponent } from './components/carrito/carrito.component';
import { InventarioComponent } from './components/inventario/inventario.component';
import { LoginComponent } from './components/login/login.component'; 
import { RegistroComponent } from './components/registro/registro.component'; 
import { RecuperarContrasenaComponent } from './components/recuperar-contrasena/recuperar-contrasena.component';
import { HomeComponent } from './components/home/home.component';
import { GestionUsuariosComponent } from './components/gestion-usuarios/gestion-usuarios.component'; 
import { PerfilComponent } from './components/perfil/perfil.component';

// Importar los guards
import { authGuard } from './guards/auth.guard';
import { adminGuard } from './guards/admin.guard';
import { publicGuard } from './guards/public.guard';

export const routes: Routes = [
  // Rutas públicas (accesibles por todos, o solo por no logueados)
  { path: 'login', component: LoginComponent, canActivate: [publicGuard] }, // Solo si NO está logueado
  { path: 'registro', component: RegistroComponent, canActivate: [publicGuard] }, // Solo si NO está logueado
  { path: 'recuperar-contrasena', component: RecuperarContrasenaComponent, canActivate: [publicGuard] }, // Solo si NO está logueado

  // Rutas que pueden ser accesibles por todos (logueados o no)
  { path: 'productos', component: ProductoComponent },

  // Rutas que requieren estar logueado (cualquier rol)
  { path: 'carrito', component: CarritoComponent, canActivate: [authGuard] },
  { path: 'perfil', component: PerfilComponent, canActivate: [authGuard] },

  // Rutas que requieren ser administrador
  { path: 'inventario', component: InventarioComponent, canActivate: [adminGuard] }, // Requiere login Y rol admin
  { path: 'gestion-usuarios', component: GestionUsuariosComponent, canActivate: [adminGuard] },


  // Redirecciones
  {
    path: '',
    component: HomeComponent, // Carga HomeComponent para la ruta raíz
    pathMatch: 'full'
  },
  {
    path: '**', // Cualquier otra ruta no encontrada
    redirectTo: '/productos' // O redirigir a la raíz para que HomeComponent decida
  }
];