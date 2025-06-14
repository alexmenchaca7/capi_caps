import { ApplicationConfig, provideZoneChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { routes } from './app.routes';
import { AuthInterceptor } from './services/auth.interceptor';
import { provideHttpClient, withFetch, withInterceptorsFromDi  } from '@angular/common/http';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { provideClientHydration, withHttpTransferCacheOptions } from '@angular/platform-browser';

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideRouter(routes),
    provideHttpClient(withInterceptorsFromDi()),
    provideHttpClient(
      withFetch()
    ),
    provideClientHydration(
      withHttpTransferCacheOptions({
        includePostRequests: false
      })
    )
  ]
};