from django.apps import AppConfig

class MedessentiaConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Aplicaciones.Medessentia'  # Debe coincidir con tu app

    def ready(self):
        import Aplicaciones.Medessentia.signals  # Importa tus signals aquí
