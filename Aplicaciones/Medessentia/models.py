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


# 2) Historia Clínica
class HistoriaClinica(models.Model):
    id_historia = models.AutoField(primary_key=True)

    # FK -> auth_user (paciente/doctor/creador/actualizador)
    paciente = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.RESTRICT,
        db_constraint=False,
        db_column="id_paciente",
        related_name="historias_como_paciente",
    )
    doctor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.RESTRICT,
        db_constraint=False,
        db_column="id_doctor",
        related_name="historias_como_doctor",
    )

    fecha_elaboracion = models.DateField()
    expediente_no = models.CharField(max_length=50, unique=True)

    edad = models.IntegerField(null=True, blank=True)
    ocupacion = models.CharField(max_length=100, null=True, blank=True)
    estado_civil = models.CharField(
        max_length=20, choices=ESTADO_CIVIL_CHOICES, null=True, blank=True
    )
    lugar_nacimiento = models.CharField(max_length=120, null=True, blank=True)
    grupo_sanguineo = models.CharField(
        max_length=15, choices=GRUPO_SANGUINEO_CHOICES, default="DESCONOCIDO"
    )

    alimentacion = models.TextField(null=True, blank=True)
    higiene = models.TextField(null=True, blank=True)
    inmunizaciones = models.TextField(null=True, blank=True)

    quirurgicos = models.TextField(null=True, blank=True)
    traumaticos = models.TextField(null=True, blank=True)
    transfusionales = models.TextField(null=True, blank=True)
    alergicos = models.TextField(null=True, blank=True)

    observaciones = models.TextField(null=True, blank=True)

    creado_por = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.RESTRICT,
        db_constraint=False,
        db_column="creado_por",
        related_name="historias_creadas",
    )
    fecha_creacion = models.DateTimeField()
    actualizado_por = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_constraint=False,
        db_column="actualizado_por",
        related_name="historias_actualizadas",
    )
    fecha_actualizacion = models.DateTimeField(null=True, blank=True)

    class Meta:
        managed = False
        db_table = "historia_clinica"
        indexes = [
            models.Index(fields=["fecha_elaboracion"], name="idx_historia_fecha"),
            models.Index(fields=["paciente"], name="idx_historia_paciente"),
            models.Index(fields=["doctor"], name="idx_historia_doctor"),
        ]

    def __str__(self):
        return f"{self.expediente_no} ({self.fecha_elaboracion})"


# 3) Diagnósticos asociados a la Historia
class HistoriaCie10(models.Model):
    # PK compuesto (id_historia, id_cie10)
    historia = models.ForeignKey(
        HistoriaClinica,
        on_delete=models.CASCADE,
        db_column="id_historia",
        related_name="diagnosticos",
    )
    cie10 = models.ForeignKey(
        Cie10,
        on_delete=models.RESTRICT,
        db_column="id_cie10",
        related_name="historias",
    )
    tipo = models.CharField(max_length=20, choices=TIPO_DIAG_CHOICES)
    condicion = models.CharField(max_length=30, choices=CONDICION_CHOICES, null=True, blank=True)
    cronologia = models.CharField(max_length=15, choices=CRONOLOGIA_CHOICES, null=True, blank=True)
    observacion = models.TextField(null=True, blank=True)

    class Meta:
        managed = False
        db_table = "historia_cie10"
        unique_together = (("historia", "cie10"),)
        indexes = [
            models.Index(fields=["tipo"], name="idx_histcie10_tipo"),
            models.Index(fields=["cie10"], name="idx_histcie10_cie"),
        ]

    def __str__(self):
        return f"{self.historia_id} - {self.cie10_id} ({self.tipo})"


# 4) Cita

class Cita(models.Model):
    TIPO_CITA = [
        ('PRESENCIAL', 'PRESENCIAL'),
        ('TELECONSULTA', 'TELECONSULTA'),
        ('DOMICILIO', 'DOMICILIO'),
        ('OTRO', 'OTRO'),
    ]
    
    ESTADO_CITA = [
        ('PENDIENTE', 'PENDIENTE'),
        ('CONFIRMADA', 'CONFIRMADA'),
        ('ATENDIDA', 'ATENDIDA'),
        ('CANCELADA', 'CANCELADA'),
        ('NO_ASISTE', 'NO_ASISTE'),
        ('REPROGRAMADA', 'REPROGRAMADA'),
    ]
    
    id_cita = models.AutoField(primary_key=True)
    id_paciente = models.ForeignKey(User, on_delete=models.RESTRICT, related_name='citas_paciente', db_column='id_paciente')
    id_doctor = models.ForeignKey(User, on_delete=models.RESTRICT, related_name='citas_doctor', db_column='id_doctor')
    fecha_hora = models.DateTimeField()
    tipo_cita = models.CharField(max_length=20, choices=TIPO_CITA, default='PRESENCIAL')
    estado = models.CharField(max_length=20, choices=ESTADO_CITA, default='PENDIENTE')
    motivo = models.TextField(null=True, blank=True)
    observaciones = models.TextField(null=True, blank=True)
    registrado_por = models.ForeignKey(User, on_delete=models.RESTRICT, related_name='citas_registradas', db_column='registrado_por')
    fecha_registro = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'cita'


# 5) Archivos de la Cita
class ArchivoCita(models.Model):
    id_archivo = models.AutoField(primary_key=True)
    cita = models.ForeignKey(Cita, on_delete=models.CASCADE, db_column="id_cita", related_name="archivos")
    nombre_archivo = models.CharField(max_length=255)
    tipo_archivo = models.CharField(max_length=100)
    fecha_subida = models.DateTimeField()
    subido_por = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.RESTRICT,
        db_column="subido_por",
        db_constraint=False,
        related_name="archivos_cita_subidos",
    )

    class Meta:
        managed = False
        db_table = "archivo_cita"
        indexes = [
            models.Index(fields=["cita"], name="idx_archivo_cita"),
            models.Index(fields=["subido_por"], name="idx_archivo_usuario"),
        ]


# 6) Encuesta de la Cita (una por cita)
class EncuestaCita(models.Model):
    id_encuesta = models.AutoField(primary_key=True)
    cita = models.OneToOneField(Cita, on_delete=models.CASCADE, db_column="id_cita", related_name="encuesta")
    calificacion = models.PositiveSmallIntegerField()  # validar 1..5 en forms
    comentarios = models.TextField(null=True, blank=True)
    fecha_respuesta = models.DateTimeField()

    class Meta:
        managed = False
        db_table = "encuesta_cita"


# 7) Atención (consulta)
class Atencion(models.Model):
    id_atencion = models.AutoField(primary_key=True)
    historia = models.ForeignKey(
        HistoriaClinica, on_delete=models.RESTRICT, db_column="id_historia", related_name="atenciones"
    )
    cita = models.ForeignKey(
        Cita, on_delete=models.SET_NULL, null=True, blank=True, db_column="id_cita", related_name="atenciones"
    )
    doctor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.RESTRICT,
        db_column="id_doctor",
        db_constraint=False,
        related_name="atenciones",
    )
    fecha = models.DateTimeField()
    diagnostico = models.TextField(null=True, blank=True)
    tratamiento = models.TextField(null=True, blank=True)

    class Meta:
        managed = False
        db_table = "atencion"
        indexes = [
            models.Index(fields=["historia"], name="idx_atencion_historia"),
            models.Index(fields=["cita"], name="idx_atencion_cita"),
            models.Index(fields=["doctor", "fecha"], name="idx_atencion_doctor_fecha"),
            models.Index(fields=["fecha"], name="idx_atencion_fecha"),
        ]

    def __str__(self):
        return f"Atención #{self.id_atencion} - {self.fecha}"


# 8) Diagnósticos por Atención
class AtencionCie10(models.Model):
    atencion = models.ForeignKey(
        Atencion, on_delete=models.CASCADE, db_column="id_atencion", related_name="diagnosticos"
    )
    cie10 = models.ForeignKey(
        Cie10, on_delete=models.RESTRICT, db_column="id_cie10", related_name="atenciones"
    )
    tipo = models.CharField(max_length=20, choices=TIPO_DIAG_CHOICES)
    condicion = models.CharField(max_length=30, choices=CONDICION_CHOICES, null=True, blank=True)
    cronologia = models.CharField(max_length=15, choices=CRONOLOGIA_CHOICES, null=True, blank=True)
    observacion = models.TextField(null=True, blank=True)

    class Meta:
        managed = False
        db_table = "atencion_cie10"
        unique_together = (("atencion", "cie10"),)
        indexes = [
            models.Index(fields=["cie10"], name="idx_atenciec_cie"),
        ]

    def __str__(self):
        return f"{self.atencion_id} - {self.cie10_id} ({self.tipo})"


# 9) Revisión por órganos y sistemas (por atención)
class RevisionSistemas(models.Model):
    id_revision = models.AutoField(primary_key=True)
    atencion = models.OneToOneField(
        Atencion, on_delete=models.CASCADE, db_column="id_atencion", related_name="revision"
    )
    organos_sentidos = models.TextField(null=True, blank=True)
    respiratorio = models.TextField(null=True, blank=True)
    cardiovascular = models.TextField(null=True, blank=True)
    digestivo = models.TextField(null=True, blank=True)
    genital = models.TextField(null=True, blank=True)
    urinario = models.TextField(null=True, blank=True)
    esqueletico = models.TextField(null=True, blank=True)
    muscular = models.TextField(null=True, blank=True)
    nervioso = models.TextField(null=True, blank=True)
    endocrino = models.TextField(null=True, blank=True)
    hemo_linfatico = models.TextField(null=True, blank=True)
    tegumentario = models.TextField(null=True, blank=True)

    class Meta:
        managed = False
        db_table = "revision_sistemas"
        constraints = [
            models.UniqueConstraint(fields=["atencion"], name="uq_revision_atencion"),
        ]


# 10) Examen físico (por atención)
class ExamenFisico(models.Model):
    id_examen = models.AutoField(primary_key=True)
    atencion = models.OneToOneField(
        Atencion, on_delete=models.CASCADE, db_column="id_atencion", related_name="examen_fisico"
    )
    frontal = models.TextField(null=True, blank=True)
    posterior = models.TextField(null=True, blank=True)
    general = models.TextField(null=True, blank=True)
    neurologico = models.TextField(null=True, blank=True)

    class Meta:
        managed = False
        db_table = "examen_fisico"
        constraints = [
            models.UniqueConstraint(fields=["atencion"], name="uq_examen_atencion"),
        ]


# 11) Notificación (por cita)
class Notificacion(models.Model):
    id_notificacion = models.AutoField(primary_key=True)
    cita = models.ForeignKey(Cita, on_delete=models.CASCADE, db_column="id_cita", related_name="notificaciones")
    usuario = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.RESTRICT,
        db_column="id_usuario",
        db_constraint=False,
        related_name="notificaciones",
    )
    medio = models.CharField(max_length=20, choices=MEDIO_NOTIF_CHOICES)
    mensaje = models.TextField()
    fecha_envio = models.DateTimeField()
    estado = models.CharField(max_length=20, choices=ESTADO_NOTIF_CHOICES, default="PENDIENTE")

    class Meta:
        managed = False
        db_table = "notificacion"
        indexes = [
            models.Index(fields=["cita"], name="idx_notif_cita"),
            models.Index(fields=["usuario"], name="idx_notif_usuario"),
            models.Index(fields=["fecha_envio"], name="idx_notif_fecha"),
        ]


# 12) Horario del doctor
class HorarioDoctor(models.Model):
    DIAS_SEMANA = [
        ('Lunes', 'Lunes'),
        ('Martes', 'Martes'),
        ('Miercoles', 'Miércoles'),
        ('Jueves', 'Jueves'),
        ('Viernes', 'Viernes'),
        ('Sabado', 'Sábado'),
        ('Domingo', 'Domingo'),
    ]
    
    id_horario = models.AutoField(primary_key=True)
    id_doctor = models.ForeignKey(User, on_delete=models.RESTRICT, related_name='horarios_doctor', db_column='id_doctor')
    dia_semana = models.CharField(max_length=10, choices=DIAS_SEMANA)
    hora_inicio = models.TimeField()
    hora_fin = models.TimeField()

    class Meta:
        db_table = 'horario_doctor'
        verbose_name = 'Horario Doctor'
        verbose_name_plural = 'Horarios Doctores'
        constraints = [
            models.UniqueConstraint(
                fields=['id_doctor', 'dia_semana', 'hora_inicio', 'hora_fin'],
                name='uq_horario_doctor_dia_tramo'
            )
        ]

    def __str__(self):
        return f"{self.id_doctor.get_full_name()} - {self.dia_semana} {self.hora_inicio} a {self.hora_fin}"


# 13) Archivos de la Atención
class ArchivoAtencion(models.Model):
    id_archivo = models.AutoField(primary_key=True)
    atencion = models.ForeignKey(
        Atencion, on_delete=models.CASCADE, db_column="id_atencion", related_name="archivos"
    )
    nombre_archivo = models.CharField(max_length=255)
    ruta_archivo = models.CharField(max_length=500)
    tipo_archivo = models.CharField(max_length=100)
    peso_bytes = models.BigIntegerField(null=True, blank=True)
    subido_por = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.RESTRICT,
        db_column="subido_por",
        db_constraint=False,
        related_name="archivos_atencion_subidos",
    )
    fecha_subida = models.DateTimeField()

    class Meta:
        managed = False
        db_table = "archivo_atencion"
        indexes = [
            models.Index(fields=["atencion"], name="idx_arcat_atencion"),
            models.Index(fields=["subido_por"], name="idx_arcat_usuario"),
        ]
