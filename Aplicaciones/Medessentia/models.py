from django.db import models

# Create your models here.
from django.db import models

class Rol(models.Model):
    id_rol = models.AutoField(primary_key=True)
    nombre_rol = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'Rol'

    def __str__(self):
        return self.nombre_rol


class Reglas(models.Model):
    id_reglas = models.AutoField(primary_key=True)
    nombre_reglas = models.CharField(max_length=100)
    descripcion_reglas = models.TextField(blank=True, null=True)
    id_rol = models.ForeignKey(
        'Rol',
        on_delete=models.DO_NOTHING,
        db_column='id_rol',
        blank=True,
        null=True
    )

    class Meta:
        managed = False
        db_table = 'Reglas'

    def __str__(self):
        return self.nombre_reglas


class Usuario(models.Model):
    id_usuario = models.AutoField(primary_key=True)
    nombre_usuario = models.CharField(max_length=100)
    apellido_usuario = models.CharField(max_length=100)
    genero_usuario = models.CharField(max_length=20, blank=True, null=True)
    cedula_usuario = models.CharField(max_length=20, blank=True, null=True)
    email_usuario = models.CharField(max_length=100, blank=True, null=True)
    telefono_usuario = models.CharField(max_length=20, blank=True, null=True)
    direccion_usuario = models.CharField(max_length=200, blank=True, null=True)
    password_usuario = models.CharField(max_length=200)
    fecha_registro_usuario = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'Usuario'

    def __str__(self):
        return f"{self.nombre_usuario} {self.apellido_usuario}"


class UsuarioRol(models.Model):
    # Requiere que en MySQL hayas agregado la PK 'id' (ver ALTER).
    id = models.AutoField(primary_key=True)
    id_usuario = models.ForeignKey(
        'Usuario',
        on_delete=models.DO_NOTHING,
        db_column='id_usuario'
    )
    id_rol = models.ForeignKey(
        'Rol',
        on_delete=models.DO_NOTHING,
        db_column='id_rol'
    )

    class Meta:
        managed = False
        db_table = 'Usuario_Rol'
        unique_together = (('id_usuario', 'id_rol'),)

    def __str__(self):
        return f"{self.id_usuario_id} - {self.id_rol_id}"


class Permisos(models.Model):
    # Requiere que en MySQL hayas agregado la PK 'id' (ver ALTER).
    id = models.AutoField(primary_key=True)
    id_reglas = models.ForeignKey(
        'Reglas',
        on_delete=models.DO_NOTHING,
        db_column='id_reglas'
    )
    id_rol = models.ForeignKey(
        'Rol',
        on_delete=models.DO_NOTHING,
        db_column='id_rol'
    )
    estado = models.BooleanField(default=False)

    class Meta:
        managed = False
        db_table = 'Permisos'
        unique_together = (('id_reglas', 'id_rol'),)

    def __str__(self):
        return f"{self.id_reglas_id} - {self.id_rol_id}: {self.estado}"
