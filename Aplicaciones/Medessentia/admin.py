from django.contrib import admin
from .models import PerfilUsuario

@admin.register(PerfilUsuario)
class PerfilUsuarioAdmin(admin.ModelAdmin):
    list_display = ("user", "cedula_usuario", "telefono_usuario", "direccion_usuario", "fecha_registro_usuario")
    search_fields = ("user__username", "cedula_usuario", "telefono_usuario")
    list_filter = ("genero_usuario", "fecha_registro_usuario")
