import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { AuthService } from '../../services/auth.service';
import { Usuario } from '../../models/usuario';

@Component({
  selector: 'app-footer',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './footer.component.html',
  styleUrls: ['./footer.component.css']
})
export class FooterComponent implements OnInit {
  currentYear = new Date().getFullYear();
  isLoggedIn$!: Observable<boolean>;
  isAdmin$!: Observable<boolean>;

  constructor(private authService: AuthService) {}

  ngOnInit(): void {
    // Se utiliza la propiedad pública 'currentUser$' del AuthService.
    this.isLoggedIn$ = this.authService.currentUser$.pipe(
      map(usuario => !!usuario)
    );

    // Se deriva el estado de admin a partir del rol en el observable del usuario.
    this.isAdmin$ = this.authService.currentUser$.pipe(
      map(usuario => usuario?.rol === 'administrador')
    );
  }
}
