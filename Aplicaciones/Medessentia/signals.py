from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import PerfilUsuario

@receiver(post_save, sender=User)
def crear_perfil_usuario(sender, instance, created, **kwargs):
    """
    Crea automáticamente un PerfilUsuario solo si aún no existe.
    La cédula NO se autogenera aquí porque debe ser ingresada en el registro.
    """
    if created:
        # No asignamos cédula aquí porque debe venir del formulario de registro
        if not hasattr(instance, "perfil"):
            PerfilUsuario.objects.create(
                user=instance,
                cedula_usuario="0000000000"  # valor temporal si no se pasó en el registro
            )
            print(f"PerfilUsuario creado automáticamente para: {instance.username}")
