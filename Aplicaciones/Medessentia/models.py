from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError


# --- Validador de cédula ecuatoriana ---
def validar_cedula_ecuatoriana(cedula):
    if len(cedula) != 10 or not cedula.isdigit():
        raise ValidationError("La cédula debe tener 10 dígitos numéricos.")

    provincia = int(cedula[:2])
    if provincia < 1 or provincia > 24:
        raise ValidationError("La cédula debe pertenecer a una provincia válida (01-24).")

    total = 0
    for i in range(9):
        num = int(cedula[i])
        if i % 2 == 0:  # posiciones pares (0-index)
            num *= 2
            if num > 9:
                num -= 9
        total += num

    verificador = 10 - (total % 10) if total % 10 != 0 else 0
    if verificador != int(cedula[9]):
        raise ValidationError("Cédula ecuatoriana no válida.")


# --- Modelo de PerfilUsuario ---
class PerfilUsuario(models.Model):
    GENEROS = [
        ('Masculino', 'Masculino'),
        ('Femenino', 'Femenino'),
        ('Otro', 'Otro'),
    ]

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="perfil"
    )
    genero_usuario = models.CharField(
        max_length=10, choices=GENEROS, blank=True, null=True
    )
    cedula_usuario = models.CharField(
        max_length=10, unique=True, validators=[validar_cedula_ecuatoriana]
    )
    # 🔴 Cambios clave:
    telefono_usuario = models.CharField(
        max_length=10, blank=True, null=False, default="0000000000"
    )
    direccion_usuario = models.CharField(
        max_length=200, blank=True, default=""
    )
    fecha_registro_usuario = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "perfil_usuario"
        managed = True

    def __str__(self):
        return f"{self.user.username} - {self.cedula_usuario or 'sin cédula'}"
# --- Modelo de Signos Vitales ---
class SignosVitales(models.Model):
    perfil_usuario = models.ForeignKey(PerfilUsuario, on_delete=models.CASCADE, related_name='signos_vitales')

    # --- ya existentes ---
    fecha_registro = models.DateTimeField()
    presion_arterial = models.CharField(max_length=20)  # seguimos guardando "120/80" por compatibilidad
    frecuencia_cardiaca = models.IntegerField()
    frecuencia_respiratoria = models.IntegerField()
    temperatura = models.DecimalField(max_digits=4, decimal_places=1)
    saturacion_oxigeno = models.IntegerField()
    peso = models.DecimalField(max_digits=5, decimal_places=2)
    talla = models.DecimalField(max_digits=4, decimal_places=2)
    imc = models.DecimalField(max_digits=4, decimal_places=2, blank=True, null=True)
    observaciones = models.TextField(blank=True, null=True)

    # --- NUEVOS CAMPOS ---
    pa_sistolica = models.IntegerField(blank=True, null=True)         # PAS
    pa_diastolica = models.IntegerField(blank=True, null=True)        # PAD
    pa_media = models.DecimalField(max_digits=5, decimal_places=2,    # PAM = (2*PAD + PAS)/3
                                   blank=True, null=True)

    glucosa_capilar = models.DecimalField(max_digits=6, decimal_places=1,
                                          blank=True, null=True)      # mg/dL (p. ej. 105.0)
    hemoglobina = models.DecimalField(max_digits=4, decimal_places=1,
                                      blank=True, null=True)          # g/dL (p. ej. 13.2)

    class Meta:
        db_table = "signos_vitales"
        managed = True
# ---Segunda parte de la BDD----
# tu_app/models.py
from django.conf import settings
from django.db import models


# 1) CIE-10
class Cie10(models.Model):
    id_cie10 = models.AutoField(primary_key=True)
    codigo = models.CharField(max_length=10, unique=True)
    descripcion = models.TextField()

    class Meta:
        managed = False
        db_table = "cie10"

    def __str__(self):
        return f"{self.codigo} - {self.descripcion[:60]}"


# Utilidades de choices (coinciden con tu SQL)
ESTADO_CIVIL_CHOICES = [
    ("SOLTERO", "Soltero"),
    ("CASADO", "Casado"),
    ("DIVORCIADO", "Divorciado"),
    ("VIUDO", "Viudo"),
    ("UNION_LIBRE", "Unión libre"),
    ("OTRO", "Otro"),
]

GRUPO_SANGUINEO_CHOICES = [
    ("A+", "A+"), ("A-", "A-"),
    ("B+", "B+"), ("B-", "B-"),
    ("AB+", "AB+"), ("AB-", "AB-"),
    ("O+", "O+"), ("O-", "O-"),
    ("DESCONOCIDO", "Desconocido"),
]

TIPO_DIAG_CHOICES = [
    ("PRINCIPAL", "Principal"),
    ("SECUNDARIO", "Secundario"),
    ("PRESUNTIVO", "Presuntivo"),
    ("DEFINITIVO", "Definitivo"),
]

CONDICION_CHOICES = [
    ("PRESUNTIVO", "Presuntivo"),
    ("DEFINITIVO_INICIAL", "Definitivo inicial"),
    ("DEFINITIVO_CONFIRMADO_LAB", "Definitivo confirmado lab"),
    ("DEFINITIVO_CONTROL", "Definitivo control"),
]

CRONOLOGIA_CHOICES = [
    ("PRIMERA", "Primera"),
    ("SUBSECUENTE", "Subsecuente"),
]

TIPO_CITA_CHOICES = [
    ("PRESENCIAL", "Presencial"),
    ("TELECONSULTA", "Teleconsulta"),
    ("DOMICILIO", "Domicilio"),
    ("OTRO", "Otro"),
]

ESTADO_CITA_CHOICES = [
    ("PENDIENTE", "Pendiente"),
    ("CONFIRMADA", "Confirmada"),
    ("ATENDIDA", "Atendida"),
    ("CANCELADA", "Cancelada"),
    ("NO_ASISTE", "No asiste"),
    ("REPROGRAMADA", "Reprogramada"),
]

MEDIO_NOTIF_CHOICES = [
    ("EMAIL", "Email"),
    ("SMS", "SMS"),
    ("WHATSAPP", "WhatsApp"),
    ("SISTEMA", "Sistema"),
]

ESTADO_NOTIF_CHOICES = [
    ("PENDIENTE", "Pendiente"),
    ("ENVIADO", "Enviado"),
    ("FALLIDO", "Fallido"),
    ("LEIDO", "Leído"),
]

DIA_SEMANA_CHOICES = [
    ("Lunes", "Lunes"),
    ("Martes", "Martes"),
    ("Miercoles", "Miércoles"),
    ("Jueves", "Jueves"),
    ("Viernes", "Viernes"),
    ("Sabado", "Sábado"),
    ("Domingo", "Domingo"),
]


# --- Historia Clínica ---
class HistoriaClinica(models.Model):
    id_historia = models.AutoField(primary_key=True)
    id_paciente = models.ForeignKey(
        User, 
        on_delete=models.RESTRICT, 
        related_name='historias_paciente', 
        db_column='id_paciente'
    )
    id_doctor = models.ForeignKey(
        User, 
        on_delete=models.RESTRICT, 
        related_name='historias_doctor', 
        db_column='id_doctor'
    )
    fecha_elaboracion = models.DateField()
    expediente_no = models.CharField(max_length=50, unique=True)
    
    # Datos demográficos
    edad = models.IntegerField(null=True, blank=True)
    ocupacion = models.CharField(max_length=100, blank=True, null=True)
    estado_civil = models.CharField(max_length=20, choices=ESTADO_CIVIL_CHOICES, blank=True, null=True)
    lugar_nacimiento = models.CharField(max_length=120, blank=True, null=True)
    grupo_sanguineo = models.CharField(max_length=15, choices=GRUPO_SANGUINEO_CHOICES, default='DESCONOCIDO')
    
    # Hábitos
    alimentacion = models.TextField(blank=True, null=True)
    higiene = models.TextField(blank=True, null=True)
    inmunizaciones = models.TextField(blank=True, null=True)
    
    # Antecedentes
    quirurgicos = models.TextField(blank=True, null=True)
    traumaticos = models.TextField(blank=True, null=True)
    transfusionales = models.TextField(blank=True, null=True)
    alergicos = models.TextField(blank=True, null=True)
    
    observaciones = models.TextField(blank=True, null=True)
    
    # Auditoría
    creado_por = models.ForeignKey(
        User, 
        on_delete=models.RESTRICT, 
        related_name='historias_creadas', 
        db_column='creado_por'
    )
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    actualizado_por = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='historias_actualizadas', 
        db_column='actualizado_por'
    )
    fecha_actualizacion = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'historia_clinica'
        managed = False
    
    def __str__(self):
        return f"Historia {self.expediente_no} - {self.id_paciente.get_full_name()}"