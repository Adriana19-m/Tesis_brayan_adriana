import re
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User, Group
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required, permission_required, user_passes_test
from django.contrib import messages
from .models import PerfilUsuario, SignosVitales
from decimal import Decimal
from django.http import JsonResponse
from django.utils.dateparse import parse_datetime
from django.db import IntegrityError, transaction
from django.db.models import Prefetch
from django.views.decorators.http import require_http_methods
from django.db import transaction
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.http import HttpResponse
from django.contrib.auth.forms import PasswordResetForm
from django.views.decorators.http import require_POST
from django.core.exceptions import MultipleObjectsReturned
from datetime import timedelta
from django.utils import timezone
from django.db.models import Max, Q, Case, When, Value, IntegerField
from decimal import Decimal, InvalidOperation

def home_publico(request):
    """Landing pública con Medilab."""
    return render(request, "public/index.html")

# ---------------------------------
# Helper: verificación de Administrador
# ---------------------------------
def es_admin(user):
    """Devuelve True si es superusuario o pertenece al grupo 'Administrador'."""
    return user.is_superuser or user.groups.filter(name="Administrador").exists()

# ---------------------------------
# Utilidad: garantizar perfil
# ---------------------------------
def ensure_perfil(user):
    """
    Devuelve un (único) PerfilUsuario para el user.
    - Si no existe, lo crea con placeholders válidos.
    - Si hay duplicados, conserva uno, fusiona datos básicos y elimina el resto.
    """
    try:
        return user.perfil  # si el campo es OneToOne y no hay duplicados
    except PerfilUsuario.DoesNotExist:
        with transaction.atomic():
            return PerfilUsuario.objects.create(
                user=user,
                genero_usuario=None,
                cedula_usuario="0000000000",
                telefono_usuario="0000000000",
                direccion_usuario="",
            )
    except (MultipleObjectsReturned, PerfilUsuario.MultipleObjectsReturned):
        # Hay más de un perfil para este user
        with transaction.atomic():
            perfiles = list(PerfilUsuario.objects.filter(user=user).order_by('id'))
            keeper = perfiles[0]
            extras = perfiles[1:]

            # Fusión simple de datos (si el keeper tiene placeholders)
            for dup in extras:
                if (not keeper.direccion_usuario) and dup.direccion_usuario:
                    keeper.direccion_usuario = dup.direccion_usuario
                if (not keeper.genero_usuario) and dup.genero_usuario:
                    keeper.genero_usuario = dup.genero_usuario
                if keeper.cedula_usuario in (None, "", "0000000000") and dup.cedula_usuario not in (None, "", "0000000000"):
                    keeper.cedula_usuario = dup.cedula_usuario
                if keeper.telefono_usuario in (None, "", "0000000000") and dup.telefono_usuario not in (None, "", "0000000000"):
                    keeper.telefono_usuario = dup.telefono_usuario
            keeper.save(update_fields=["direccion_usuario","genero_usuario","cedula_usuario","telefono_usuario"])

            # Borra los duplicados
            PerfilUsuario.objects.filter(id__in=[d.id for d in extras]).delete()
            return keeper
# -------------------------
# PERFIL DE USUARIO
# -------------------------
@login_required
def mi_perfil(request):
    perfil = ensure_perfil(request.user)
    return render(request, "public/mi_perfil.html", {"perfil": perfil})
@login_required
def editar_perfil(request):
    perfil = ensure_perfil(request.user)

    if request.method == "POST":
        ced = (request.POST.get("cedula_usuario") or "").strip()
        tel = (request.POST.get("telefono_usuario") or "").strip()

        if not (ced.isdigit() and len(ced) == 10):
            messages.error(request, "La cédula debe tener 10 dígitos (sin guiones).")
            return redirect("editar_perfil")

        # Permite dejarlo vacío, pero guardamos 0000000000 para cumplir NOT NULL
        if tel and not (tel.isdigit() and len(tel) == 10):
            messages.error(request, "El teléfono debe tener 10 dígitos.")
            return redirect("editar_perfil")
        if not tel:
            tel = "0000000000"

        perfil.genero_usuario   = (request.POST.get("genero_usuario") or "").strip() or None
        perfil.cedula_usuario   = ced
        perfil.telefono_usuario = tel                        # <- nunca None
        perfil.direccion_usuario = (request.POST.get("direccion_usuario") or "").strip()
        perfil.save()

        messages.success(request, "Perfil actualizado correctamente.")
        return redirect("mi_perfil")

    return render(request, "public/editar_perfil.html", {"perfil": perfil})

# -------------------------
# REGISTRO DE USUARIO (solo Admin)
def _sanear_telefono(valor):
    """
    Devuelve SIEMPRE 10 dígitos.
    - Si viene vacío o None -> '0000000000'
    - Si trae menos/más dígitos -> recorta/ajusta a 10
    """
    dig = "".join(ch for ch in str(valor or "") if ch.isdigit())
    if not dig:
        dig = "0000000000"
    if len(dig) < 10:
        dig = (dig + "0000000000")[:10]
    else:
        dig = dig[:10]
    return dig
# -------------------------
@user_passes_test(es_admin)
def registro(request):
    if request.method == "POST":
        username   = (request.POST.get("username") or "").strip()
        email      = (request.POST.get("email") or "").strip()
        first_name = (request.POST.get("first_name") or "").strip()
        last_name  = (request.POST.get("last_name") or "").strip()
        password   = (request.POST.get("password") or "")
        cedula     = (request.POST.get("cedula_usuario") or "").strip()

        # Teléfono: jamás NULL
        telefono_final = _sanear_telefono(request.POST.get("telefono_usuario"))

        direccion  = (request.POST.get("direccion_usuario") or "").strip()
        genero     = (request.POST.get("genero_usuario") or "").strip() or None
        auto_paciente = request.POST.get("asignar_paciente") == "on"

        # Validaciones mínimas
        errores = []
        if not username:
            errores.append("Debes ingresar un nombre de usuario.")
        if not email:
            errores.append("Debes ingresar un correo.")
        if not password or len(password) < 8:
            errores.append("La contraseña debe tener al menos 8 caracteres.")
        if not (cedula.isdigit() and len(cedula) == 10):
            errores.append("La cédula debe tener 10 dígitos.")
        # Si el admin escribió algo en el campo, valida 10 dígitos
        if request.POST.get("telefono_usuario"):
            if len("".join(ch for ch in request.POST.get("telefono_usuario") if ch.isdigit())) != 10:
                errores.append("El teléfono debe tener 10 dígitos.")

        if User.objects.filter(username=username).exists():
            errores.append("El nombre de usuario ya existe.")
        if PerfilUsuario.objects.filter(cedula_usuario=cedula).exists():
            errores.append("La cédula ya está registrada.")

        if errores:
            for e in errores:
                messages.error(request, e)
            return render(request, "admingen/registro.html", {
                "prefill": {
                    "username": username,
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "cedula_usuario": cedula,
                    "telefono_usuario": request.POST.get("telefono_usuario", ""),
                    "direccion_usuario": direccion,
                    "genero_usuario": (genero or ""),
                    "asignar_paciente": auto_paciente,
                }
            })

        with transaction.atomic():
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
            )
            PerfilUsuario.objects.create(
                user=user,
                genero_usuario=genero,
                cedula_usuario=cedula,
                telefono_usuario=telefono_final,  # <- NUNCA NULL
                direccion_usuario=direccion,
            )
            if auto_paciente:
                grupo, _ = Group.objects.get_or_create(name="Paciente")
                user.groups.add(grupo)

        messages.success(request, f"Usuario {username} creado correctamente.")
        return redirect("lista_usuarios")

    return render(request, "admingen/registro.html")
#------Perfil editar doctor 
# views.py
@login_required
def editar_cuenta(request):
    user = request.user
    if request.method == "POST":
        user.first_name = (request.POST.get("first_name") or "").strip()
        user.last_name  = (request.POST.get("last_name") or "").strip()
        user.email      = (request.POST.get("email") or "").strip()
        user.save()
        messages.success(request, "Datos de cuenta actualizados.")
        return redirect("editar_cuenta")
    return render(request, "cuenta/editar_cuenta.html", {"user": user})

#-----
@login_required
@user_passes_test(es_admin)
def lista_usuarios(request):
    """
    Admin: lista con filtros (rol, activo), búsqueda, orden y paginación.
    Incluye KPIs por rol y estado.
    """
    rol = request.GET.get("rol", "").strip()
    estado = request.GET.get("estado", "").strip()  # "activo", "inactivo" o ""
    q = request.GET.get("q", "").strip()
    order = request.GET.get("order", "date_joined_desc")  # opciones: username, date_joined_asc, _desc, last_login_...

    qs = User.objects.all().select_related("perfil").prefetch_related("groups")

    if rol:
        qs = qs.filter(groups__name=rol)

    if estado == "activo":
        qs = qs.filter(is_active=True)
    elif estado == "inactivo":
        qs = qs.filter(is_active=False)

    if q:
        qs = qs.filter(
            Q(username__icontains=q) |
            Q(first_name__icontains=q) |
            Q(last_name__icontains=q) |
            Q(email__icontains=q) |
            Q(perfil__cedula_usuario__icontains=q) |
            Q(perfil__telefono_usuario__icontains=q)
        )

    order_map = {
        "username_asc": "username",
        "username_desc": "-username",
        "date_joined_asc": "date_joined",
        "date_joined_desc": "-date_joined",
        "last_login_asc": "last_login",
        "last_login_desc": "-last_login",
    }
    qs = qs.order_by(order_map.get(order, "-date_joined")).distinct()

    # KPIs (conteos)
    kpis = {
        "total": User.objects.count(),
        "activos": User.objects.filter(is_active=True).count(),
        "inactivos": User.objects.filter(is_active=False).count(),
        "por_rol": dict(
            User.objects.values("groups__name")
            .annotate(n=Count("id"))
            .values_list("groups__name", "n")
        ),
    }

    paginator = Paginator(qs, 12)  # 12 por página
    page_obj = paginator.get_page(request.GET.get("page"))

    return render(request, "admingen/lista_usuarios.html", {
        "usuarios": page_obj.object_list,
        "page_obj": page_obj,
        "rol": rol,
        "estado": estado,
        "q": q,
        "order": order,
        "kpis": kpis,
    })
#----- activar y desactivar 
@require_POST
@login_required
@user_passes_test(es_admin)
def toggle_activo(request, user_id):
    if int(user_id) == request.user.id:
        messages.error(request, "No puedes desactivarte a ti mismo.")
        return redirect("lista_usuarios")

    u = get_object_or_404(User, id=user_id)
    u.is_active = not u.is_active
    u.save(update_fields=["is_active"])
    estado = "activado" if u.is_active else "desactivado"
    messages.success(request, f"Usuario '{u.username}' {estado}.")
    return redirect(request.META.get("HTTP_REFERER", "lista_usuarios"))
# _____ usuariios csv
@login_required
@user_passes_test(es_admin)
def exportar_usuarios_csv(request):
    import csv
    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = 'attachment; filename="usuarios.csv"'
    writer = csv.writer(response)

    # Reutiliza filtros básicos
    rol = request.GET.get("rol", "").strip()
    estado = request.GET.get("estado", "").strip()
    q = request.GET.get("q", "").strip()

    qs = User.objects.all().select_related("perfil").prefetch_related("groups")
    if rol:
        qs = qs.filter(groups__name=rol)
    if estado == "activo":
        qs = qs.filter(is_active=True)
    elif estado == "inactivo":
        qs = qs.filter(is_active=False)
    if q:
        qs = qs.filter(
            Q(username__icontains=q) |
            Q(first_name__icontains=q) |
            Q(last_name__icontains=q) |
            Q(email__icontains=q) |
            Q(perfil__cedula_usuario__icontains=q) |
            Q(perfil__telefono_usuario__icontains=q)
        ).distinct()

    writer.writerow([
        "username","first_name","last_name","email","roles",
        "is_active","last_login","date_joined",
        "genero","cedula","telefono","direccion","fecha_registro_perfil",
    ])

    for u in qs:
        roles = ", ".join(g.name for g in u.groups.all()) or "—"
        p = getattr(u, "perfil", None)
        writer.writerow([
            u.username, u.first_name, u.last_name, u.email, roles,
            "activo" if u.is_active else "inactivo",
            u.last_login or "", u.date_joined or "",
            getattr(p, "genero_usuario", "") or "—",
            getattr(p, "cedula_usuario", "") or "—",
            getattr(p, "telefono_usuario", "") or "—",
            getattr(p, "direccion_usuario", "") or "—",
            getattr(p, "fecha_registro_usuario", "") or "",
        ])
    return response

# -------------------------
# VISTAS CON ROLES/PERMISOS
# -------------------------
@login_required
@permission_required("Medessentia.view_perfilusuario", raise_exception=True)
def lista_perfiles(request):
    perfiles = PerfilUsuario.objects.all()
    return render(request, "lista_perfiles.html", {"perfiles": perfiles})


@login_required
@user_passes_test(es_admin)
def panel_admin(request):
    # Tu estructura real: Templates/admingen/admin_dashboard.html
    return render(request, "dashboards/panel_admin.html")



@login_required
@user_passes_test(lambda u: u.groups.filter(name="Doctor").exists())
def panel_doctor(request):
    """ Panel exclusivo para los doctores """
    signos = SignosVitales.objects.all()
    # Tienes Templates/panel_doctor.html (sin subcarpeta)
    return render(request, "dashboards/panel_doctor.html")


@login_required
@user_passes_test(lambda u: u.groups.filter(name="Paciente").exists())
def panel_paciente(request):
    perfil = ensure_perfil(request.user)

    # Si sigue con placeholders, mándalo a completar el perfil
    if perfil.cedula_usuario == "0000000000" or perfil.telefono_usuario == "0000000000":
        messages.warning(request, "Completa tu perfil antes de continuar.")
        return redirect("editar_perfil")

    signos = perfil.signos_vitales.all()
    return render(request, "public/panel_paciente.html", {"perfil": perfil, "signos": signos})
# ------tener en cuenta formulario para pacientes
@require_http_methods(["GET", "POST"])
def registro_paciente(request):
    # No permitir registrarse si ya está logueado
    if request.user.is_authenticated:
        messages.info(request, "Ya has iniciado sesión.")
        return redirect("redirigir_segun_rol")

    if request.method == "POST":
        # --- Capturar datos del formulario (sin forms.py) ---
        username   = (request.POST.get("username") or "").strip()
        email      = (request.POST.get("email") or "").strip()
        first_name = (request.POST.get("first_name") or "").strip()
        last_name  = (request.POST.get("last_name") or "").strip()
        password1  = request.POST.get("password1") or ""
        password2  = request.POST.get("password2") or ""
        cedula     = (request.POST.get("cedula_usuario") or "").strip()
        telefono   = (request.POST.get("telefono_usuario") or "").strip()
        direccion  = (request.POST.get("direccion_usuario") or "").strip()
        genero     = request.POST.get("genero_usuario") or None

        # --- Validaciones básicas ---
        errores = []
        if not username:
            errores.append("El usuario es obligatorio.")
        if not email:
            errores.append("El correo es obligatorio.")
        if password1 != password2:
            errores.append("Las contraseñas no coinciden.")
        if len(cedula) != 10 or not cedula.isdigit():
            errores.append("La cédula debe tener 10 dígitos numéricos.")
        if telefono and (len(telefono) != 10 or not telefono.isdigit()):
            errores.append("El teléfono debe tener 10 dígitos numéricos.")

        # Unicidad
        if User.objects.filter(username=username).exists():
            errores.append("El nombre de usuario ya existe.")
        if PerfilUsuario.objects.filter(cedula_usuario=cedula).exists():
            errores.append("La cédula ya está registrada.")

        if errores:
            for e in errores:
                messages.error(request, e)
            # Re-render con lo que el usuario escribió
            context = {
                "prefill": {
                    "username": username,
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "cedula_usuario": cedula,
                    "telefono_usuario": telefono,
                    "direccion_usuario": direccion,
                    "genero_usuario": genero or "",
                }
            }
            return render(request, "auth/registro_paciente.html", context)

        # --- Crear usuario + perfil + asignar grupo Paciente ---
        try:
            with transaction.atomic():
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password1,
                    first_name=first_name,
                    last_name=last_name,
                )
                # asegurar grupo
                grupo, _ = Group.objects.get_or_create(name="Paciente")
                user.groups.add(grupo)

                PerfilUsuario.objects.create(
                    user=user,
                    genero_usuario=genero,
                    cedula_usuario=cedula,        # tu validador de modelo validará la cédula
                    telefono_usuario=_sanear_telefono(telefono), 
                    direccion_usuario=direccion or "",
                )
        except Exception as e:
            messages.error(request, f"Ocurrió un error creando la cuenta: {e}")
            return render(request, "auth/registro_paciente.html", {"prefill": request.POST})

        # Login inmediato y redirección a su panel
        login(request, user)
        messages.success(request, "¡Cuenta creada correctamente! Bienvenido/a.")
        return redirect("redirigir_segun_rol")

    # GET
    return render(request, "auth/registro_paciente.html")
# -------------------------
# REDIRECCIÓN SEGÚN ROL
# -------------------------
@login_required
def redirigir_segun_rol(request):
    user = request.user
    if user.groups.filter(name="Administrador").exists():
        return redirect("panel_admin")
    elif user.groups.filter(name="Doctor").exists():
        return redirect("panel_doctor")
    elif user.groups.filter(name="Paciente").exists():
        return redirect("panel_paciente")
    else:
        messages.error(request, "No tienes un rol asignado. Contacta con el administrador.")
        return redirect("mi_perfil")
#------perfil del doctor administar pacientes 
@login_required
@user_passes_test(lambda u: u.groups.filter(name="Doctor").exists())
def pacientes_del_doctor(request):
    hoy = timezone.now()
    qs = (PerfilUsuario.objects
          .filter(user__groups__name="Paciente")
          .select_related("user")
          .annotate(
              ultimo_control=Max("signos_vitales__fecha_registro")
          ))

    # Calcular “estado_control” por días desde último control
    # 0=sin datos, 1=ok (<30d), 2=pronto (30–59d), 3=vencido (>=60d)
    treinta = hoy - timedelta(days=30)
    sesenta = hoy - timedelta(days=60)
    qs = qs.annotate(
        estado_control=Case(
            When(ultimo_control__isnull=True, then=Value(0)),
            When(ultimo_control__gte=treinta, then=Value(1)),
            When(ultimo_control__lt=treinta, ultimo_control__gte=sesenta, then=Value(2)),
            default=Value(3),
            output_field=IntegerField()
        )
    )

    # Búsqueda servidor (opcional)
    q = (request.GET.get("q") or "").strip()
    if q:
        qs = qs.filter(
            Q(user__first_name__icontains=q) |
            Q(user__last_name__icontains=q) |
            Q(user__username__icontains=q) |
            Q(cedulaUsuario__icontains=q) |
            Q(telefono_usuario__icontains=q)
        )

    # Orden
    order = request.GET.get("order") or "-ultimo_control"
    qs = qs.order_by(order, "user__username")

    # KPIs
    total = qs.count()
    con_datos = qs.filter(ultimo_control__isnull=False)
    kpis = {
        "total": total,
        "ok": con_datos.filter(ultimo_control__gte=treinta).count(),
        "pronto": con_datos.filter(ultimo_control__lt=treinta, ultimo_control__gte=sesenta).count(),
        "vencido": con_datos.filter(ultimo_control__lt=sesenta).count(),
        "sindatos": qs.filter(ultimo_control__isnull=True).count(),
    }

    paginator = Paginator(qs, 12)
    page_obj = paginator.get_page(request.GET.get("page"))

    return render(request, "doctor/lista_pacientes.html", {
        "perfiles": page_obj.object_list,
        "page_obj": page_obj,
        "kpis": kpis,
        "q": q,
        "order": order,
    })
# ----------- PARA PACIENTES 
@login_required
@user_passes_test(lambda u: u.groups.filter(name="Doctor").exists())
def pacientes_del_doctor(request):
    ...
    return render(request, "pacientes/lista_pacientes.html", {
        "perfiles": page_obj.object_list,
        "page_obj": page_obj,
        "kpis": kpis,
        "q": q,
        "order": order,
    })

@login_required
def historia_paciente(request, perfil_id):
    """Detalle simple de historia: lista de signos vitales del paciente."""
    perfil = get_object_or_404(PerfilUsuario, id=perfil_id)
    signos = perfil.signos_vitales.all().order_by("-fecha_registro")
    return render(request, "doctor/historia_paciente.html", {
        "perfil": perfil,
        "signos": signos,
    })

@login_required
def nuevo_signo(request, perfil_id):
    """
    Placeholder: aquí podrías mostrar un formulario para agregar signos.
    De momento, solo redirige a la historia con un mensaje.
    """
    get_object_or_404(PerfilUsuario, id=perfil_id)
    messages.info(request, "Formulario de 'Añadir signos' aún no implementado.")
    return redirect("historia_paciente", perfil_id=perfil_id)

@login_required
def perfil_paciente(request, perfil_id):
    """Ficha rápida del paciente (datos del perfil)."""
    perfil = get_object_or_404(PerfilUsuario, id=perfil_id)
    return render(request, "doctor/perfil_paciente.html", {
        "perfil": perfil,
    })
# -------------------------
# ASIGNAR ROLES (rol único)
# -------------------------
@login_required
@user_passes_test(es_admin)
def asignar_roles(request):
    usuarios = User.objects.all().order_by("username")
    grupos = Group.objects.all().order_by("name")

    if request.method == "POST":
        usuario_id = request.POST.get("usuario_id")
        rol = request.POST.get("rol")
        if usuario_id and rol:
            usuario = get_object_or_404(User, id=usuario_id)
            grupo = get_object_or_404(Group, name=rol)
            usuario.groups.clear()
            usuario.groups.add(grupo)
            messages.success(request, f"Rol '{rol}' asignado a {usuario.username}")
            return redirect("asignar_roles")

    # Tu estructura real: Templates/admingen/asignar_roles.html
    return render(request, "admingen/asignar_roles.html", {"usuarios": usuarios, "grupos": grupos})

@login_required
def lista_perfiles(request):
    """
    - Admin: ve todos los perfiles.
    - Doctor: ve SOLO perfiles cuyos usuarios estén en el grupo 'Paciente'.
    - Paciente: (opcional) solo ve su propio perfil.
    """
    qs = PerfilUsuario.objects.select_related("user")

    if request.user.groups.filter(name="Doctor").exists():
        qs = qs.filter(user__groups__name="Paciente").distinct()
        solo_pacientes = True
    elif request.user.groups.filter(name="Paciente").exists():
        qs = qs.filter(user=request.user)
        solo_pacientes = False
    else:
        # Admin u otros con permisos
        solo_pacientes = False

    perfiles = qs.order_by("user__username")
    return render(request, "lista_perfiles.html", {
        "perfiles": perfiles,
        "solo_pacientes": solo_pacientes,
    })
# -------------------------
# SIGNOS VITALES
# -------------------------
def es_doctor_o_admin(u):
    return u.is_authenticated and (u.groups.filter(name="Doctor").exists() or es_admin(u))

@login_required
@user_passes_test(es_doctor_o_admin)
def nuevo_signo(request, perfil_id):
    perfil = get_object_or_404(PerfilUsuario, id=perfil_id)

    if request.method == "POST":
        # --- Captura segura ---
        fecha_raw = (request.POST.get("fecha_registro") or "").strip()

        # Presión arterial desglosada
        pas_raw = (request.POST.get("pa_sistolica") or "").strip()
        pad_raw = (request.POST.get("pa_diastolica") or "").strip()
        pam_raw = (request.POST.get("pa_media") or "").strip()

        # Signos vitales
        temp_raw = (request.POST.get("temperatura") or "").strip()
        fr_raw   = (request.POST.get("frecuencia_respiratoria") or "").strip()
        fc_raw   = (request.POST.get("frecuencia_cardiaca") or "").strip()
        spo2_raw = (request.POST.get("saturacion_oxigeno") or "").strip()

        # Antropometría
        peso_raw  = (request.POST.get("peso") or "").strip()
        talla_raw = (request.POST.get("talla") or "").strip()
        imc_raw   = (request.POST.get("imc") or "").strip()

        # Capilares
        glucosa_raw    = (request.POST.get("glucosa_capilar") or "").strip()
        hemoglobina_raw = (request.POST.get("hemoglobina") or "").strip()

        obs = (request.POST.get("observaciones") or "").strip()

        errores = []

        # Fecha/hora
        fecha_registro = parse_datetime(fecha_raw) if fecha_raw else timezone.now()
        if fecha_raw and not fecha_registro:
            errores.append("Fecha inválida. Usa el formato YYYY-MM-DD HH:MM.")

        # Enteros
        def to_int(name, raw, obligatorio=True):
            if raw == "" and not obligatorio:
                return None
            try:
                return int(raw)
            except ValueError:
                errores.append(f"{name} debe ser un número entero.")
                return None

        # Decimales
        def to_dec(name, raw, ndigits=None, obligatorio=True):
            if raw == "" and not obligatorio:
                return None
            try:
                d = Decimal(raw)
                return d if ndigits is None else d.quantize(Decimal(ndigits))
            except (InvalidOperation, ValueError):
                errores.append(f"{name} debe ser un número válido.")
                return None

        # PAS/PAD/PAM
        pas = to_int("Presión sistólica (PAS)", pas_raw, obligatorio=False)
        pad = to_int("Presión diastólica (PAD)", pad_raw, obligatorio=False)
        pam = to_dec("Presión arterial media (PAM)", pam_raw, "0.01", obligatorio=False)

        # Vitals
        fc  = to_int("Frecuencia cardiaca", fc_raw, obligatorio=True)
        fr  = to_int("Frecuencia respiratoria", fr_raw, obligatorio=True)
        spo2 = to_int("Saturación de oxígeno", spo2_raw, obligatorio=True)
        temp = to_dec("Temperatura", temp_raw, "0.1", obligatorio=True)

        # Antropometría
        peso  = to_dec("Peso",  peso_raw,  "0.01", obligatorio=True)
        talla = to_dec("Talla", talla_raw, "0.01", obligatorio=True)
        imc   = to_dec("IMC",   imc_raw,   "0.01", obligatorio=False)

        # Capilares
        glucosa     = to_dec("Glucosa capilar", glucosa_raw, "0.1", obligatorio=False)
        hemoglobina = to_dec("Hemoglobina",     hemoglobina_raw, "0.1", obligatorio=False)

        # Reglas sanidad
        if temp is not None and not (Decimal("30.0") <= temp <= Decimal("45.0")):
            errores.append("Temperatura fuera de rango razonable (30.0 – 45.0 °C).")
        if spo2 is not None and not (50 <= spo2 <= 100):
            errores.append("SpO₂ debe estar entre 50 y 100.")
        if peso is not None and peso <= 0:
            errores.append("El peso debe ser > 0.")
        if talla is not None and talla <= 0:
            errores.append("La talla debe ser > 0.")

        # Calcular PAM si no viene pero sí hay PAS/PAD
        if pam is None and (pas is not None and pad is not None):
            pam = (Decimal(2) * Decimal(pad) + Decimal(pas)) / Decimal(3)
            pam = pam.quantize(Decimal("0.01"))

        # Calcular IMC si no viene y hay peso/talla
        if imc is None and (peso is not None and talla is not None and talla > 0):
            imc = (peso / (talla * talla)).quantize(Decimal("0.01"))

        # Para compatibilidad, construimos presion_arterial "120/80" si hay PAS/PAD
        presion_compuesta = ""
        if pas is not None and pad is not None:
            presion_compuesta = f"{pas}/{pad}"

        if errores:
            for e in errores:
                messages.error(request, e)
            return render(request, "doctor/nuevo_signo.html", {
                "perfil": perfil,
                "prefill": {
                    "fecha_registro": fecha_raw,
                    "pa_sistolica": pas_raw,
                    "pa_diastolica": pad_raw,
                    "pa_media": pam_raw or (str(pam) if pam is not None else ""),
                    "temperatura": temp_raw,
                    "frecuencia_respiratoria": fr_raw,
                    "frecuencia_cardiaca": fc_raw,
                    "saturacion_oxigeno": spo2_raw,
                    "peso": peso_raw,
                    "talla": talla_raw,
                    "imc": imc_raw or (str(imc) if imc is not None else ""),
                    "glucosa_capilar": glucosa_raw,
                    "hemoglobina": hemoglobina_raw,
                    "observaciones": obs,
                },
            })

        # Crear registro
        SignosVitales.objects.create(
            perfil_usuario=perfil,
            fecha_registro=fecha_registro,
            presion_arterial=presion_compuesta,   # mantiene compatibilidad
            frecuencia_cardiaca=fc,
            frecuencia_respiratoria=fr,
            temperatura=temp,
            saturacion_oxigeno=spo2,
            peso=peso,
            talla=talla,
            imc=imc,
            observaciones=obs,
            pa_sistolica=pas,
            pa_diastolica=pad,
            pa_media=pam,
            glucosa_capilar=glucosa,
            hemoglobina=hemoglobina,
        )

        messages.success(request, "Signos vitales añadidos correctamente.")
        return redirect("historia_paciente", perfil_id=perfil.id)

    # GET inicial
    return render(request, "doctor/nuevo_signo.html", {
        "perfil": perfil,
        "prefill": {
            "fecha_registro": timezone.now().strftime("%Y-%m-%d %H:%M"),
        },
    })
@login_required
def signos_vitales(request):
    """Listado general de signos vitales.
       - Doctor: ve todos
       - Paciente: ve solo los suyos
    """
    if request.user.groups.filter(name="Doctor").exists() or request.user.is_superuser:
        signos = (SignosVitales.objects
                  .select_related("perfil_usuario", "perfil_usuario__user")
                  .order_by("-fecha_registro"))
    else:
        perfil = ensure_perfil(request.user)
        signos = (perfil.signos_vitales
                  .select_related("perfil_usuario__user")
                  .order_by("-fecha_registro"))
    return render(request, "vistasignos/signos_vitales.html", {"signos": signos})


@login_required
def listado_signos_vitales(request):
    """Alias si quieres otra ruta/lista; puedes eliminarla si no la usas."""
    return signos_vitales(request)


@login_required
def guardar_signos_vitales(request):
    if request.method != "POST":
        return JsonResponse({"success": False, "message": "Solo se permite POST."})

    perfil = ensure_perfil(request.user)
    try:
        fecha_registro = parse_datetime(request.POST.get("fecha_registro")) or timezone.now()
        fc  = int(request.POST.get("frecuencia_cardiaca", 0))
        fr  = int(request.POST.get("frecuencia_respiratoria", 0))
        temp = Decimal(request.POST.get("temperatura", "0.0"))
        spo2 = int(request.POST.get("saturacion_oxigeno", 0))
        peso = Decimal(request.POST.get("peso", "0.0"))
        talla = Decimal(request.POST.get("talla", "0.0"))
        imc_raw = request.POST.get("imc")
        imc = Decimal(imc_raw) if imc_raw else None

        # nuevos (opcionales)
        pas_raw = request.POST.get("pa_sistolica") or ""
        pad_raw = request.POST.get("pa_diastolica") or ""
        pam_raw = request.POST.get("pa_media") or ""
        gluc_raw = request.POST.get("glucosa_capilar") or ""
        hb_raw   = request.POST.get("hemoglobina") or ""

        pas = int(pas_raw) if pas_raw else None
        pad = int(pad_raw) if pad_raw else None
        pam = Decimal(pam_raw) if pam_raw else None
        glucosa = Decimal(gluc_raw) if gluc_raw else None
        hb = Decimal(hb_raw) if hb_raw else None

        presion_compuesta = f"{pas}/{pad}" if (pas is not None and pad is not None) else ""

        SignosVitales.objects.create(
            perfil_usuario=perfil,
            fecha_registro=fecha_registro,
            presion_arterial=presion_compuesta,
            frecuencia_cardiaca=fc,
            frecuencia_respiratoria=fr,
            temperatura=temp,
            saturacion_oxigeno=spo2,
            peso=peso,
            talla=talla,
            imc=imc,
            observaciones=request.POST.get("observaciones",""),

            pa_sistolica=pas,
            pa_diastolica=pad,
            pa_media=pam,
            glucosa_capilar=glucosa,
            hemoglobina=hb,
        )
        return JsonResponse({"success": True, "message": "Signos vitales guardados correctamente."})
    except Exception as e:
        return JsonResponse({"success": False, "message": f"Error: {e}"})

@login_required
def editar_signo_vital(request, id):
    signo = get_object_or_404(SignosVitales, id=id)
    perfil_id = signo.perfil_usuario_id

    if request.method == "POST":
        try:
            # ... (tu lógica de actualización)
            signo.save()
            messages.success(request, "Registro actualizado correctamente.")
        except Exception as e:
            messages.error(request, f"Error al actualizar: {e}")
        return redirect("historia_paciente", perfil_id=perfil_id)

    return render(request, "signos_vitales/editar.html", {"signo": signo})

@login_required
def eliminar_signo_vital(request, id):
    signo = get_object_or_404(SignosVitales, id=id)
    perfil_id = signo.perfil_usuario_id
    signo.delete()
    messages.success(request, "Registro eliminado correctamente.")
    return redirect("historia_paciente", perfil_id=perfil_id)

#-------------SEGUNDA PARTE BDD-------
#-------------------------------------
# tu_app/views.py
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.db import transaction, connection
from django.http import JsonResponse
from django.utils import timezone

from .models import (
    Cie10, HistoriaClinica, HistoriaCie10, Cita, ArchivoCita, EncuestaCita,
    Atencion, AtencionCie10, RevisionSistemas, ExamenFisico,
    Notificacion, HorarioDoctor, ArchivoAtencion
)

# ---------------- Utilidades JSON ----------------
def ok(data=None, message="OK", status=200):
    return JsonResponse({"ok": True, "message": message, "data": data or {}}, status=status)

def bad(message="Error de validación", data=None, status=400):
    return JsonResponse({"ok": False, "message": message, "data": data or {}}, status=status)

def require(method, request):
    if request.method != method:
        return bad(f"Solo {method}", status=405)
    return None




# ========== 1) CIE-10 ==========
@login_required
def cie10_index(request):
    return render(request, "cie10/index.html")

@login_required
def cie10_listar(request):
    q = (request.GET.get("q") or "").strip()
    qs = Cie10.objects.all()
    if q:
        qs = qs.filter(codigo__icontains=q) | qs.filter(descripcion__icontains=q)
    data = [{"id_cie10":x.id_cie10, "codigo":x.codigo, "descripcion":x.descripcion} for x in qs.order_by("codigo")[:1000]]
    return ok({"rows": data})

@login_required
def cie10_formulario(request):
    _id = request.GET.get("id")
    item = Cie10.objects.filter(pk=_id).first() if _id else None
    return render(request, "cie10/_form.html", {"item": item})

@login_required
@csrf_exempt
def cie10_guardar(request):
    if (err := require("POST", request)): return err
    codigo = (request.POST.get("codigo") or "").strip()
    descripcion = (request.POST.get("descripcion") or "").strip()
    if not codigo or not descripcion: return bad("Código y descripción son obligatorios")
    _id = request.POST.get("id_cie10")
    try:
        with transaction.atomic():
            if _id:
                obj = Cie10.objects.select_for_update().get(pk=_id)
                obj.codigo, obj.descripcion = codigo, descripcion
                obj.save(update_fields=["codigo","descripcion"])
            else:
                obj = Cie10.objects.create(codigo=codigo, descripcion=descripcion)
    except Exception as e:
        return bad(f"No se pudo guardar: {e}")
    return ok({"id": obj.id_cie10}, "Guardado")

@login_required
@csrf_exempt
def cie10_eliminar(request):
    if (err := require("POST", request)): return err
    _id = request.POST.get("id")
    if not _id: return bad("Falta id")
    try:
        Cie10.objects.filter(pk=_id).delete()
    except Exception as e:
        return bad(f"No se pudo eliminar: {e}")
    return ok(message="Eliminado")


# ========== 2) Historia Clínica ==========
@login_required
def historia_index(request):
    return render(request, "historia/index.html")

@login_required
def historia_listar(request):
    q = (request.GET.get("q") or "").strip()
    qs = HistoriaClinica.objects.all()
    if q:
        qs = qs.filter(expediente_no__icontains=q)
    data = [{
        "id_historia": x.id_historia,
        "id_paciente": x.paciente_id,
        "id_doctor": x.doctor_id,
        "fecha_elaboracion": x.fecha_elaboracion.strftime("%Y-%m-%d"),
        "expediente_no": x.expediente_no,
        "edad": x.edad,
        "grupo_sanguineo": x.grupo_sanguineo,
    } for x in qs.order_by("-fecha_elaboracion")[:500]]
    return ok({"rows": data})

@login_required
def historia_formulario(request):
    _id = request.GET.get("id")
    item = HistoriaClinica.objects.filter(pk=_id).first() if _id else None
    return render(request, "historia/_form.html", {"item": item})

@login_required
@csrf_exempt
def historia_guardar(request):
    if (err := require("POST", request)): return err
    d = request.POST
    campos = ["id_paciente","id_doctor","fecha_elaboracion","expediente_no","edad","ocupacion","estado_civil",
              "lugar_nacimiento","grupo_sanguineo","alimentacion","higiene","inmunizaciones","quirurgicos",
              "traumaticos","transfusionales","alergicos","observaciones"]
    vals = [d.get(k) or None for k in campos]
    _id = d.get("id_historia")
    ahora = timezone.now()
    uid = request.user.id if request.user.is_authenticated else 1
    try:
        with connection.cursor() as cur:
            if _id:
                sets = ", ".join([f"{k}=%s" for k in campos] + ["actualizado_por=%s","fecha_actualizacion=%s"])
                cur.execute(f"UPDATE historia_clinica SET {sets} WHERE id_historia=%s",
                            [*vals, uid, ahora, _id])
            else:
                cols = ", ".join(campos + ["creado_por","fecha_creacion"])
                marks = ", ".join(["%s"]*(len(campos)+2))
                cur.execute(f"INSERT INTO historia_clinica ({cols}) VALUES ({marks})",
                            [*vals, uid, ahora])
                _id = cur.lastrowid
    except Exception as e:
        return bad(f"No se pudo guardar: {e}")
    return ok({"id": _id}, "Guardado")

@login_required
@csrf_exempt
def historia_eliminar(request):
    if (err := require("POST", request)): return err
    _id = request.POST.get("id")
    if not _id: return bad("Falta id")
    try:
        with connection.cursor() as cur:
            cur.execute("DELETE FROM historia_clinica WHERE id_historia=%s", [_id])
    except Exception as e:
        return bad(f"No se pudo eliminar: {e}")
    return ok(message="Eliminado")


# ========== 3) Historia-CIE10 ==========
@login_required
def historia_cie10_index(request):
    return render(request, "historia_cie10/index.html")

@login_required
def historia_cie10_listar(request):
    id_historia = request.GET.get("id_historia")
    if not id_historia: return ok({"rows":[]})
    rows = (HistoriaCie10.objects
            .filter(historia_id=id_historia)
            .select_related("cie10")
            .order_by("tipo","cie10__codigo"))
    data = [{
        "id_historia": r.historia_id,
        "id_cie10": r.cie10_id,
        "codigo": r.cie10.codigo,
        "descripcion": r.cie10.descripcion,
        "tipo": r.tipo,
        "condicion": r.condicion,
        "cronologia": r.cronologia,
        "observacion": r.observacion or "",
    } for r in rows]
    return ok({"rows": data})

@login_required
def historia_cie10_formulario(request):
    return render(request, "historia_cie10/_form.html", {
        "id_historia": request.GET.get("id_historia"),
    })

@login_required
@csrf_exempt
def historia_cie10_guardar(request):
    if (err := require("POST", request)): return err
    d = request.POST
    try:
        with connection.cursor() as cur:
            cur.execute("""REPLACE INTO historia_cie10 (id_historia,id_cie10,tipo,condicion,cronologia,observacion)
                           VALUES (%s,%s,%s,%s,%s,%s)""",
                        [d.get("id_historia"), d.get("id_cie10"), d.get("tipo"),
                         d.get("condicion") or None, d.get("cronologia") or None, d.get("observacion") or None])
    except Exception as e:
        return bad(f"No se pudo guardar: {e}")
    return ok(message="Guardado")

@login_required
@csrf_exempt
def historia_cie10_eliminar(request):
    if (err := require("POST", request)): return err
    try:
        with connection.cursor() as cur:
            cur.execute("DELETE FROM historia_cie10 WHERE id_historia=%s AND id_cie10=%s",
                        [request.POST.get("id_historia"), request.POST.get("id_cie10")])
    except Exception as e:
        return bad(f"No se pudo eliminar: {e}")
    return ok(message="Eliminado")


# ========== 4) Cita ==========
from django.http import JsonResponse
from datetime import datetime, timedelta, time
from .models import Cita

def horario_disponibilidad(request):
    doctor_id = request.GET.get('doctor_id')
    start = request.GET.get('start')
    end = request.GET.get('end')
    slot_minutes = int(request.GET.get('slot_minutes', 30))

    start_dt = datetime.fromisoformat(start[:19])  # Ignora zona horaria
    end_dt = datetime.fromisoformat(end[:19])

    horario_inicio = time(8, 0)
    horario_fin = time(18, 0)

    citas = Cita.objects.filter(
        id_doctor=doctor_id,
        fecha_hora__gte=start_dt,
        fecha_hora__lt=end_dt
    )

    eventos = []
    fecha = start_dt
    while fecha < end_dt:
        actual = datetime.combine(fecha.date(), horario_inicio)
        fin_dia = datetime.combine(fecha.date(), horario_fin)
        while actual < fin_dia:
            ocupado = citas.filter(fecha_hora=actual).exists()
            if not ocupado and actual >= datetime.now():
                eventos.append({
                    "title": "Disponible",
                    "start": actual.isoformat(),
                    "end": (actual + timedelta(minutes=slot_minutes)).isoformat(),
                    "tipo": "disponible",
                    "doctor_id": doctor_id,
                    "backgroundColor": "#28a745",
                    "borderColor": "#28a745",
                    "textColor": "#fff",
                })
            actual += timedelta(minutes=slot_minutes)
        fecha += timedelta(days=1)

    for cita in citas:
        eventos.append({
            "title": f"Cita con {cita.id_paciente.get_full_name()}",
            "start": cita.fecha_hora.isoformat(),
            "end": (cita.fecha_hora + timedelta(minutes=slot_minutes)).isoformat(),
            "tipo": "cita",
            "cita_id": cita.id_cita,
            "doctor_id": doctor_id,
            "backgroundColor": "#dc3545",
            "borderColor": "#dc3545",
            "textColor": "#fff",
        })

    return JsonResponse(eventos, safe=False)
@login_required
def cita_index(request):
    # Definir los estados disponibles
    estados = ['PENDIENTE', 'CONFIRMADA', 'ATENDIDA', 'CANCELADA', 'NO_ASISTE', 'REPROGRAMADA']
    
    # Acceder al rol del usuario
    is_admin = request.user.groups.filter(name="Administrador").exists()
    is_doctor = request.user.groups.filter(name="Doctor").exists()
    is_paciente = request.user.groups.filter(name="Paciente").exists()
    
    doctores = User.objects.filter(groups__name='Doctor')
    return render(request, "cita/index.html", {
        'estados': estados,
        'is_admin': is_admin,
        'is_doctor': is_doctor,
        'is_paciente': is_paciente,
        'doctores': doctores,
        'user_id': request.user.id
    })


@login_required
def cita_listar(request):
    estado = (request.GET.get("estado") or "").strip()
    qs = Cita.objects.all().select_related('id_paciente', 'id_doctor')

    # Restringir visibilidad para pacientes: solo ver sus propias citas
    is_paciente = request.user.groups.filter(name="Paciente").exists()
    is_doctor = request.user.groups.filter(name="Doctor").exists()
    is_admin = request.user.groups.filter(name="Administrador").exists()
    if is_paciente and not (is_doctor or is_admin):
        qs = qs.filter(id_paciente=request.user)
    
    if estado:
        qs = qs.filter(estado=estado)
    
    data = [{
        "id_cita": x.id_cita,
        "id_paciente": x.id_paciente.id,
        "id_doctor": x.id_doctor.id,
        "fecha_hora": x.fecha_hora.strftime("%Y-%m-%d %H:%M"),
        "tipo_cita": x.tipo_cita,
        "estado": x.estado,
        "motivo": (x.motivo or "")[:120],
    } for x in qs.order_by("-fecha_hora")[:500]]
    
    return JsonResponse({"data": data})

@login_required
def cita_formulario(request):
    _id = request.GET.get("id")
    item = None
    if _id:
        try:
            item = Cita.objects.get(id_cita=_id)
        except Cita.DoesNotExist:
            pass
    
    # Verificar el rol del usuario
    is_admin = request.user.groups.filter(name="Administrador").exists()
    is_doctor = request.user.groups.filter(name="Doctor").exists()
    is_paciente = request.user.groups.filter(name="Paciente").exists()

    return render(request, "cita/form.html", {
        "cita": item,
        "is_admin": is_admin,
        "is_doctor": is_doctor,
        "is_paciente": is_paciente,
        "user_id": request.user.id
    })


@login_required
@csrf_exempt
def cita_guardar(request):
    if request.method == "POST":
        try:
            d = request.POST
            _id = d.get("id_cita")
            
            paciente_id = d.get("id_paciente")
            doctor_id = d.get("id_doctor")
            
            is_paciente = request.user.groups.filter(name="Paciente").exists()
            if is_paciente:
                paciente_id = request.user.id

            # Validar que los IDs lleguen correctamente
            try:
                paciente_id = int(paciente_id) if paciente_id else None
                doctor_id = int(doctor_id) if doctor_id else None
            except (ValueError, TypeError):
                return JsonResponse({"message": "IDs inválidos"}, status=400)
            
            try:
                paciente = User.objects.get(id=paciente_id)
                doctor = User.objects.get(id=doctor_id)
            except User.DoesNotExist:
                return JsonResponse({"message": "Paciente o doctor no encontrado"}, status=400)

            is_admin = request.user.groups.filter(name="Administrador").exists()
            is_doctor = request.user.groups.filter(name="Doctor").exists()

            datos = {
                "id_paciente": paciente,
                "id_doctor": doctor,
                "tipo_cita": d.get("tipo_cita"),
                "motivo": d.get("motivo"),
                "observaciones": d.get("observaciones") or None,
                "registrado_por": request.user
            }

            # Validación de fecha robusta
            fecha_str = d.get('fecha_hora')
            if not fecha_str:
                return JsonResponse({"message": "Fecha y hora es requerida"}, status=400)
            fecha_dt = parse_datetime(fecha_str)
            if fecha_dt is None:
                try:
                    fecha_dt = datetime.strptime(fecha_str, '%Y-%m-%d %H:%M')
                    fecha_dt = timezone.make_aware(fecha_dt, timezone.get_default_timezone())
                except Exception:
                    return JsonResponse({"message": "Formato de fecha_hora inválido"}, status=400)
            else:
                if timezone.is_naive(fecha_dt):
                    fecha_dt = timezone.make_aware(fecha_dt, timezone.get_default_timezone())
                else:
                    fecha_dt = timezone.localtime(fecha_dt, timezone.get_default_timezone())
            datos["fecha_hora"] = fecha_dt

            slot_minutes = 30
            slot_end = fecha_dt + timedelta(minutes=slot_minutes)

            # Solapamiento robusto
            conflicting = Cita.objects.filter(
                id_doctor=doctor,
                fecha_hora__lt=slot_end,
                fecha_hora__gte=fecha_dt - timedelta(minutes=slot_minutes)
            )
            if _id:
                conflicting = conflicting.exclude(id_cita=_id)
            if conflicting.exists():
                return JsonResponse({"message": "El horario seleccionado ya está reservado"}, status=400)

            # Estado por defecto si no es admin/doctor
            if is_admin or is_doctor:
                datos["estado"] = d.get("estado")
            else:
                datos["estado"] = "PENDIENTE"

            if _id:
                cita = Cita.objects.filter(id_cita=_id).first()
                if cita:
                    for key, value in datos.items():
                        if hasattr(cita, key):
                            setattr(cita, key, value)
                    cita.save()
                else:
                    return JsonResponse({"message": "Cita no encontrada"}, status=404)
            else:
                cita = Cita.objects.create(**datos)
                _id = cita.id_cita
            
            return JsonResponse({"id": _id, "message": "Guardado"})
        except Exception as e:
            return JsonResponse({"message": f"No se pudo guardar: {str(e)}"}, status=400)
    
    return JsonResponse({"message": "Método no permitido"}, status=405)

@login_required
@csrf_exempt
def cita_eliminar(request):
    if request.method == "POST":
        _id = request.POST.get("id")
        try:
            cita = Cita.objects.filter(id_cita=_id).first()
            if cita:
                cita.delete()
                return JsonResponse({"message": "Eliminado"})
            else:
                return JsonResponse({"message": "Cita no encontrada"}, status=404)
        except Exception as e:
            return JsonResponse({"message": f"No se pudo eliminar: {str(e)}"}, status=400)
    return JsonResponse({"message": "Método no permitido"}, status=405)
# ========== 5) Archivo de cita ==========
@login_required
def archivo_cita_index(request):
    return render(request, "archivo_cita/index.html")

@login_required
def archivo_cita_listar(request):
    id_cita = request.GET.get("id_cita")
    if not id_cita: return ok({"rows":[]})
    qs = ArchivoCita.objects.filter(cita_id=id_cita).order_by("-fecha_subida")
    data = [{
        "id_archivo": a.id_archivo,
        "id_cita": a.cita_id,
        "nombre_archivo": a.nombre_archivo,
        "tipo_archivo": a.tipo_archivo,
        "fecha_subida": a.fecha_subida.strftime("%Y-%m-%d %H:%M"),
        "subido_por": a.subido_por_id
    } for a in qs]
    return ok({"rows": data})

@login_required
def archivo_cita_formulario(request):
    return render(request, "archivo_cita/_form.html", {
        "id_cita": request.GET.get("id_cita")
    })

@login_required
@csrf_exempt
def archivo_cita_guardar(request):
    if (err := require("POST", request)): return err
    d = request.POST
    try:
        with connection.cursor() as cur:
            cur.execute("""INSERT INTO archivo_cita (id_cita,nombre_archivo,tipo_archivo,fecha_subida,subido_por)
                           VALUES (%s,%s,%s,NOW(),%s)""",
                        [d.get("id_cita"), d.get("nombre_archivo"), d.get("tipo_archivo"), d.get("subido_por")])
    except Exception as e:
        return bad(f"No se pudo guardar: {e}")
    return ok(message="Guardado")

@login_required
@csrf_exempt
def archivo_cita_eliminar(request):
    if (err := require("POST", request)): return err
    _id = request.POST.get("id")
    try:
        with connection.cursor() as cur:
            cur.execute("DELETE FROM archivo_cita WHERE id_archivo=%s", [_id])
    except Exception as e:
        return bad(f"No se pudo eliminar: {e}")
    return ok(message="Eliminado")


# ========== 6) Encuesta de cita ==========
@login_required
def encuesta_cita_index(request):
    return render(request, "encuesta_cita/index.html")

@login_required
def encuesta_cita_listar(request):
    id_cita = request.GET.get("id_cita")
    qs = EncuestaCita.objects.filter(cita_id=id_cita) if id_cita else EncuestaCita.objects.all()
    qs = qs.order_by("-fecha_respuesta")[:500]
    data = [{
        "id_encuesta": e.id_encuesta,
        "id_cita": e.cita_id,
        "calificacion": e.calificacion,
        "comentarios": (e.comentarios or "")[:120],
        "fecha_respuesta": e.fecha_respuesta.strftime("%Y-%m-%d %H:%M"),
    } for e in qs]
    return ok({"rows": data})

@login_required
def encuesta_cita_formulario(request):
    _id = request.GET.get("id")
    item = EncuestaCita.objects.filter(pk=_id).first() if _id else None
    return render(request, "encuesta_cita/_form.html", {"item": item})

@login_required
@csrf_exempt
def encuesta_cita_guardar(request):
    if (err := require("POST", request)): return err
    d = request.POST
    _id = d.get("id_encuesta")
    try:
        with connection.cursor() as cur:
            if _id:
                cur.execute("""UPDATE encuesta_cita SET id_cita=%s,calificacion=%s,comentarios=%s WHERE id_encuesta=%s""",
                            [d.get("id_cita"), d.get("calificacion"), d.get("comentarios") or None, _id])
            else:
                cur.execute("""INSERT INTO encuesta_cita (id_cita,calificacion,comentarios,fecha_respuesta)
                               VALUES (%s,%s,%s,NOW())""",
                            [d.get("id_cita"), d.get("calificacion"), d.get("comentarios") or None])
                _id = cur.lastrowid
    except Exception as e:
        return bad(f"No se pudo guardar: {e}")
    return ok({"id": _id}, "Guardado")

@login_required
@csrf_exempt
def encuesta_cita_eliminar(request):
    if (err := require("POST", request)): return err
    _id = request.POST.get("id")
    try:
        with connection.cursor() as cur:
            cur.execute("DELETE FROM encuesta_cita WHERE id_encuesta=%s", [_id])
    except Exception as e:
        return bad(f"No se pudo eliminar: {e}")
    return ok(message="Eliminado")


# ========== 7) Atención ==========
@login_required
def atencion_index(request):
    return render(request, "atencion/index.html")

@login_required
def atencion_listar(request):
    id_historia = (request.GET.get("id_historia") or "").strip()
    qs = Atencion.objects.all()
    if id_historia:
        qs = qs.filter(historia_id=id_historia)
    data = [{
        "id_atencion": a.id_atencion,
        "id_historia": a.historia_id,
        "id_cita": a.cita_id,
        "id_doctor": a.doctor_id,
        "fecha": a.fecha.strftime("%Y-%m-%d %H:%M"),
    } for a in qs.order_by("-fecha")[:500]]
    return ok({"rows": data})

@login_required
def atencion_formulario(request):
    _id = request.GET.get("id")
    item = Atencion.objects.filter(pk=_id).first() if _id else None
    return render(request, "atencion/_form.html", {"item": item})

@login_required
@csrf_exempt
def atencion_guardar(request):
    if (err := require("POST", request)): return err
    d = request.POST
    campos = ["id_historia","id_cita","id_doctor","fecha","diagnostico","tratamiento"]
    vals = [d.get(k) or None for k in campos]
    _id = d.get("id_atencion")
    try:
        with connection.cursor() as cur:
            if _id:
                cur.execute("""UPDATE atencion SET id_historia=%s,id_cita=%s,id_doctor=%s,fecha=%s,diagnostico=%s,tratamiento=%s
                               WHERE id_atencion=%s""", [*vals, _id])
            else:
                cur.execute("""INSERT INTO atencion (id_historia,id_cita,id_doctor,fecha,diagnostico,tratamiento)
                               VALUES (%s,%s,%s,%s,%s,%s)""", vals)
                _id = cur.lastrowid
    except Exception as e:
        return bad(f"No se pudo guardar: {e}")
    return ok({"id": _id}, "Guardado")

@login_required
@csrf_exempt
def atencion_eliminar(request):
    if (err := require("POST", request)): return err
    _id = request.POST.get("id")
    try:
        with connection.cursor() as cur:
            cur.execute("DELETE FROM atencion WHERE id_atencion=%s", [_id])
    except Exception as e:
        return bad(f"No se pudo eliminar: {e}")
    return ok(message="Eliminado")


# ========== 8) Atención-CIE10 ==========
@login_required
def atencion_cie10_index(request):
    return render(request, "atencion_cie10/index.html")

@login_required
def atencion_cie10_listar(request):
    id_atencion = request.GET.get("id_atencion")
    if not id_atencion: return ok({"rows":[]})
    rows = (AtencionCie10.objects
            .filter(atencion_id=id_atencion)
            .select_related("cie10")
            .order_by("tipo","cie10__codigo"))
    data = [{
        "id_atencion": r.atencion_id,
        "id_cie10": r.cie10_id,
        "codigo": r.cie10.codigo,
        "descripcion": r.cie10.descripcion,
        "tipo": r.tipo,
        "condicion": r.condicion,
        "cronologia": r.cronologia,
        "observacion": r.observacion or "",
    } for r in rows]
    return ok({"rows": data})

@login_required
def atencion_cie10_formulario(request):
    return render(request, "atencion_cie10/_form.html", {
        "id_atencion": request.GET.get("id_atencion")
    })

@login_required
@csrf_exempt
def atencion_cie10_guardar(request):
    if (err := require("POST", request)): return err
    d = request.POST
    try:
        with connection.cursor() as cur:
            cur.execute("""REPLACE INTO atencion_cie10 (id_atencion,id_cie10,tipo,condicion,cronologia,observacion)
                           VALUES (%s,%s,%s,%s,%s,%s)""",
                        [d.get("id_atencion"), d.get("id_cie10"), d.get("tipo"),
                         d.get("condicion") or None, d.get("cronologia") or None, d.get("observacion") or None])
    except Exception as e:
        return bad(f"No se pudo guardar: {e}")
    return ok(message="Guardado")

@login_required
@csrf_exempt
def atencion_cie10_eliminar(request):
    if (err := require("POST", request)): return err
    try:
        with connection.cursor() as cur:
            cur.execute("DELETE FROM atencion_cie10 WHERE id_atencion=%s AND id_cie10=%s",
                        [request.POST.get("id_atencion"), request.POST.get("id_cie10")])
    except Exception as e:
        return bad(f"No se pudo eliminar: {e}")
    return ok(message="Eliminado")


# ========== 9) Revisión por sistemas ==========
@login_required
def revision_index(request):
    return render(request, "revision/index.html")

@login_required
def revision_formulario(request):
    id_atencion = request.GET.get("id_atencion")
    item = RevisionSistemas.objects.filter(atencion_id=id_atencion).first()
    if not item:
        item = {"id_atencion": id_atencion}
    return render(request, "revision/_form.html", {"item": item})

@login_required
@csrf_exempt
def revision_guardar(request):
    if (err := require("POST", request)): return err
    d = request.POST
    id_atencion = d.get("id_atencion")
    campos = ["organos_sentidos","respiratorio","cardiovascular","digestivo","genital","urinario",
              "esqueletico","muscular","nervioso","endocrino","hemo_linfatico","tegumentario"]
    vals = [d.get(k) or None for k in campos]
    try:
        with connection.cursor() as cur:
            sets = ", ".join([f"{k}=%s" for k in campos])
            cur.execute(
                f"INSERT INTO revision_sistemas (id_atencion,{','.join(campos)}) "
                f"VALUES (%s,{','.join(['%s']*len(campos))}) "
                f"ON DUPLICATE KEY UPDATE {sets}",
                [id_atencion, *vals, *vals]
            )
    except Exception as e:
        return bad(f"No se pudo guardar: {e}")
    return ok(message="Guardado")


# ========== 10) Examen físico ==========
@login_required
def examen_index(request):
    return render(request, "examenes/index.html")

@login_required
def examen_formulario(request):
    id_atencion = request.GET.get("id_atencion")
    item = ExamenFisico.objects.filter(atencion_id=id_atencion).first()
    if not item:
        item = {"id_atencion": id_atencion}
    return render(request, "examenes/_form.html", {"item": item})

@login_required
@csrf_exempt
def examen_guardar(request):
    if (err := require("POST", request)): return err
    d = request.POST
    id_atencion = d.get("id_atencion")
    campos = ["frontal","posterior","general","neurologico"]
    vals = [d.get(k) or None for k in campos]
    try:
        with connection.cursor() as cur:
            sets = ", ".join([f"{k}=%s" for k in campos])
            cur.execute(
                f"INSERT INTO examen_fisico (id_atencion,{','.join(campos)}) "
                f"VALUES (%s,{','.join(['%s']*len(campos))}) "
                f"ON DUPLICATE KEY UPDATE {sets}",
                [id_atencion, *vals, *vals]
            )
    except Exception as e:
        return bad(f"No se pudo guardar: {e}")
    return ok(message="Guardado")


# ========== 11) Notificación ==========
@login_required
def notificacion_index(request):
    return render(request, "notificacion/index.html")

@login_required
def notificacion_listar(request):
    estado = (request.GET.get("estado") or "").strip()
    qs = Notificacion.objects.all()
    if estado:
        qs = qs.filter(estado=estado)
    data = [{
        "id_notificacion": n.id_notificacion,
        "id_cita": n.cita_id,
        "id_usuario": n.usuario_id,
        "medio": n.medio,
        "estado": n.estado,
        "fecha_envio": n.fecha_envio.strftime("%Y-%m-%d %H:%M")
    } for n in qs.order_by("-fecha_envio")[:500]]
    return ok({"rows": data})

@login_required
def notificacion_formulario(request):
    _id = request.GET.get("id")
    item = Notificacion.objects.filter(pk=_id).first() if _id else None
    return render(request, "notificacion/_form.html", {"item": item})

@login_required
@csrf_exempt
def notificacion_guardar(request):
    if (err := require("POST", request)): return err
    d = request.POST
    _id = d.get("id_notificacion")
    campos = ["id_cita","id_usuario","medio","mensaje","estado"]
    vals = [d.get(k) or None for k in campos]
    try:
        with connection.cursor() as cur:
            if _id:
                cur.execute("""UPDATE notificacion SET id_cita=%s,id_usuario=%s,medio=%s,mensaje=%s,estado=%s
                               WHERE id_notificacion=%s""", [*vals, _id])
            else:
                cur.execute("""INSERT INTO notificacion (id_cita,id_usuario,medio,mensaje,fecha_envio,estado)
                               VALUES (%s,%s,%s,%s,NOW(),%s)""", vals)
                _id = cur.lastrowid
    except Exception as e:
        return bad(f"No se pudo guardar: {e}")
    return ok({"id": _id}, "Guardado")

@login_required
@csrf_exempt
def notificacion_eliminar(request):
    if (err := require("POST", request)): return err
    _id = request.POST.get("id")
    try:
        with connection.cursor() as cur:
            cur.execute("DELETE FROM notificacion WHERE id_notificacion=%s", [_id])
    except Exception as e:
        return bad(f"No se pudo eliminar: {e}")
    return ok(message="Eliminado")


# ========== 12) Horario doctor ==========
# ========== 5) Horario Doctor ==========
@login_required
def horario_index(request):
    is_admin = request.user.groups.filter(name="Administrador").exists()
    is_doctor = request.user.groups.filter(name="Doctor").exists()
    
    # Obtener doctores para el filtro
    doctores = User.objects.filter(groups__name='Doctor')
    
    return render(request, "horario/index.html", {
        'is_admin': is_admin, 
        'is_doctor': is_doctor,
        'doctores': doctores
    })

@login_required
def horario_listar(request):
    doctor_id = request.GET.get("doctor_id")
    qs = HorarioDoctor.objects.all().select_related('id_doctor')
    
    if doctor_id:
        qs = qs.filter(id_doctor_id=doctor_id)
    
    data = [{
        "id_horario": x.id_horario,
        "id_doctor": x.id_doctor.id,
        "nombre_doctor": f"{x.id_doctor.first_name} {x.id_doctor.last_name}",
        "dia_semana": x.dia_semana,
        "hora_inicio": x.hora_inicio.strftime("%H:%M"),
        "hora_fin": x.hora_fin.strftime("%H:%M"),
        "color": get_color_for_doctor(x.id_doctor.id),
    } for x in qs.order_by("id_doctor", "dia_semana", "hora_inicio")]
    
    return JsonResponse({"data": data})

@login_required
def horario_formulario(request):
    _id = request.GET.get("id")
    item = None
    if _id:
        try:
            item = HorarioDoctor.objects.get(id_horario=_id)
        except HorarioDoctor.DoesNotExist:
            pass
    
    is_admin = request.user.groups.filter(name="Administrador").exists()
    is_doctor = request.user.groups.filter(name="Doctor").exists()

    # Si es doctor, solo puede ver sus propios horarios
    doctores = User.objects.filter(groups__name='Doctor')
    if is_doctor and not is_admin:
        doctores = doctores.filter(id=request.user.id)

    return render(request, "horario/form.html", {
        "horario": item,
        "doctores": doctores,
        "is_admin": is_admin,
        "is_doctor": is_doctor
    })

@login_required
@csrf_exempt
def horario_guardar(request):
    if request.method == "POST":
        try:
            d = request.POST
            _id = d.get("id_horario")
            
            # Si es un nuevo registro, _id vendrá vacío, eso es correcto
            if _id == '':
                _id = None

            # Validar que el doctor existe
            doctor_id = d.get("id_doctor")
            try:
                doctor = User.objects.get(id=doctor_id)
            except User.DoesNotExist:
                return JsonResponse({"message": "Doctor no encontrado"}, status=400)

            # Validar que hora_inicio < hora_fin
            hora_inicio = d.get("hora_inicio")
            hora_fin = d.get("hora_fin")
            
            if hora_inicio >= hora_fin:
                return JsonResponse({"message": "La hora de inicio debe ser menor que la hora de fin"}, status=400)

            # Validar superposición de horarios
            dia_semana = d.get("dia_semana")
            horarios_existentes = HorarioDoctor.objects.filter(
                id_doctor=doctor_id,
                dia_semana=dia_semana
            )

            # Si estamos editando, excluir el horario actual
            if _id:
                horarios_existentes = horarios_existentes.exclude(id_horario=_id)

            for horario in horarios_existentes:
                # Convertir a objetos time para comparación
                from datetime import datetime
                nuevo_inicio = datetime.strptime(hora_inicio, '%H:%M').time()
                nuevo_fin = datetime.strptime(hora_fin, '%H:%M').time()
                
                if (nuevo_inicio < horario.hora_fin and nuevo_fin > horario.hora_inicio):
                    return JsonResponse({
                        "message": f"El horario se superpone con uno existente: {horario.hora_inicio} - {horario.hora_fin}"
                    }, status=400)

            datos = {
                "id_doctor": doctor,
                "dia_semana": dia_semana,
                "hora_inicio": hora_inicio,
                "hora_fin": hora_fin,
            }

            if _id:
                # Editar horario existente
                horario = HorarioDoctor.objects.filter(id_horario=_id).first()
                if horario:
                    for key, value in datos.items():
                        if hasattr(horario, key):
                            setattr(horario, key, value)
                    horario.save()
                else:
                    return JsonResponse({"message": "Horario no encontrado"}, status=404)
            else:
                # Crear nuevo horario
                horario = HorarioDoctor.objects.create(**datos)
                _id = horario.id_horario
                
            return JsonResponse({"id": _id, "message": "Guardado"})
            
        except Exception as e:
            return JsonResponse({"message": f"No se pudo guardar: {str(e)}"}, status=400)
    
    return JsonResponse({"message": "Método no permitido"}, status=405)

@login_required
@csrf_exempt
def horario_eliminar(request):
    if request.method == "POST":
        _id = request.POST.get("id")
        try:
            horario = HorarioDoctor.objects.filter(id_horario=_id).first()
            if horario:
                horario.delete()
                return JsonResponse({"message": "Eliminado"})
            else:
                return JsonResponse({"message": "Horario no encontrado"}, status=404)
        except Exception as e:
            return JsonResponse({"message": f"No se pudo eliminar: {str(e)}"}, status=400)
    return JsonResponse({"message": "Método no permitido"}, status=405)

@login_required
def horario_calendario(request):
    """Vista para el calendario semanal con FullCalendar"""
    is_admin = request.user.groups.filter(name="Administrador").exists()
    is_doctor = request.user.groups.filter(name="Doctor").exists()
    
    # Obtener doctores para el filtro
    doctores = User.objects.filter(groups__name='Doctor')
    
    is_paciente = request.user.groups.filter(name="Paciente").exists()
    return render(request, "horario/calendario.html", {
        'is_admin': is_admin,
        'is_doctor': is_doctor,
        'is_paciente': is_paciente,
        'user_id': request.user.id,
        'doctores': doctores
    })

@login_required
def horario_eventos(request):
    """Endpoint para obtener horarios en formato FullCalendar"""
    doctor_id = request.GET.get("doctor_id")
    qs = HorarioDoctor.objects.all().select_related('id_doctor')
    
    if doctor_id:
        qs = qs.filter(id_doctor_id=doctor_id)
    
    eventos = []
    
    for horario in qs:
        color = get_color_for_doctor(horario.id_doctor.id)
        
        # Convertir a eventos semanales para FullCalendar
        evento = {
            'id': f"horario_{horario.id_horario}",
            'title': f"Dr. {horario.id_doctor.first_name} {horario.id_doctor.last_name}",
            'daysOfWeek': [get_day_number(horario.dia_semana)],
            'startTime': horario.hora_inicio.strftime("%H:%M:%S"),
            'endTime': horario.hora_fin.strftime("%H:%M:%S"),
            'color': color,
            'extendedProps': {
                'id_horario': horario.id_horario,
                'doctor': f"{horario.id_doctor.first_name} {horario.id_doctor.last_name}",
                'dia_semana': horario.dia_semana,
                'tipo': 'horario'
            }
        }
        eventos.append(evento)
    
    return JsonResponse(eventos, safe=False)


@login_required
def horario_disponibilidad(request):
    """Devuelve franjas horarias disponibles (eventos individuales) para un doctor
    Parameters esperados (GET): doctor_id, start, end, slot_minutes (opcional, default 30)
    Retorna lista de eventos con 'tipo': 'disponible' en extendedProps
    """
    from datetime import datetime, timedelta, time
    from django.utils import timezone

    doctor_id = request.GET.get('doctor_id')
    start = request.GET.get('start')
    end = request.GET.get('end')
    slot_minutes = int(request.GET.get('slot_minutes') or 30)

    if not doctor_id or not start or not end:
        return JsonResponse([], safe=False)

    # usar parse_datetime de Django y normalizar a timezone-aware
    start_dt = parse_datetime(start)
    end_dt = parse_datetime(end)
    if start_dt is None or end_dt is None:
        return JsonResponse([], safe=False)

    if timezone.is_naive(start_dt):
        start_dt = timezone.make_aware(start_dt, timezone.get_default_timezone())
    else:
        start_dt = timezone.localtime(start_dt, timezone.get_default_timezone())

    if timezone.is_naive(end_dt):
        end_dt = timezone.make_aware(end_dt, timezone.get_default_timezone())
    else:
        end_dt = timezone.localtime(end_dt, timezone.get_default_timezone())

    # obtener horarios del doctor
    qs = HorarioDoctor.objects.filter(id_doctor_id=doctor_id)

    # obtener citas existentes del doctor en el rango
    citas_qs = Cita.objects.filter(id_doctor_id=doctor_id, fecha_hora__gte=start_dt, fecha_hora__lt=end_dt)
    occupied = set()
    for c in citas_qs:
        # normalize to minute precision
        occupied.add(c.fecha_hora.replace(second=0, microsecond=0))

    eventos = []
    cur = start_dt
    # iterar día por día para generar slots según horarios
    while cur.date() <= end_dt.date():
        weekday = cur.strftime('%A')  # e.g., 'Monday'
        # map to Spanish week names used in HorarioDoctor
        mapping = {
            'Monday': 'Lunes', 'Tuesday': 'Martes', 'Wednesday': 'Miercoles',
            'Thursday': 'Jueves', 'Friday': 'Viernes', 'Saturday': 'Sabado', 'Sunday': 'Domingo'
        }
        dia_es = mapping.get(weekday)

        if dia_es:
            horarios_dia = qs.filter(dia_semana=dia_es)
            for h in horarios_dia:
                # build day's start/end datetimes (make them timezone-aware)
                fecha_base = cur.date()
                start_time_naive = datetime.combine(fecha_base, h.hora_inicio)
                end_time_naive = datetime.combine(fecha_base, h.hora_fin)

                # Hacer aware con la zona por defecto
                if timezone.is_naive(start_time_naive):
                    start_time = timezone.make_aware(start_time_naive, timezone.get_default_timezone())
                else:
                    start_time = timezone.localtime(start_time_naive, timezone.get_default_timezone())

                if timezone.is_naive(end_time_naive):
                    end_time = timezone.make_aware(end_time_naive, timezone.get_default_timezone())
                else:
                    end_time = timezone.localtime(end_time_naive, timezone.get_default_timezone())

                slot_start = start_time
                while slot_start + timedelta(minutes=slot_minutes) <= end_time:
                    # comparar con start_dt/end_dt (ambos aware)
                    if slot_start >= start_dt and slot_start < end_dt:
                        # if not occupied at this exact datetime (normalize seconds)
                        slot_norm = slot_start.replace(second=0, microsecond=0)
                        if slot_norm not in occupied:
                            slot_end = slot_start + timedelta(minutes=slot_minutes)
                            evento = {
                                'id': f"disp_{h.id_horario}_{slot_start.isoformat()}",
                                'title': 'Disponible',
                                'start': slot_start.isoformat(),
                                'end': slot_end.isoformat(),
                                'color': '#2ecc71',
                                'display': 'block',
                                'extendedProps': {
                                    'id_horario': h.id_horario,
                                    'doctor_id': h.id_doctor.id,
                                    'tipo': 'disponible'
                                }
                            }
                            eventos.append(evento)
                    slot_start = slot_start + timedelta(minutes=slot_minutes)
        cur = cur + timedelta(days=1)

    return JsonResponse(eventos, safe=False)

def get_day_number(dia_semana):
    """Convertir día de la semana a número (0=Dom, 1=Lun, ..., 6=Sab)"""
    dias = {
        'Domingo': 0,
        'Lunes': 1,
        'Martes': 2,
        'Miercoles': 3,
        'Jueves': 4,
        'Viernes': 5,
        'Sabado': 6
    }
    return dias.get(dia_semana, 0)

def get_color_for_doctor(doctor_id):
    """Generar color consistente para cada doctor"""
    colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c', '#34495e']
    return colors[doctor_id % len(colors)]

# ========== 13) Archivo de atención ==========
@login_required
def archivo_atencion_index(request):
    return render(request, "archivo_atencion/index.html")

@login_required
def archivo_atencion_listar(request):
    id_atencion = request.GET.get("id_atencion")
    if not id_atencion: return ok({"rows":[]})
    qs = ArchivoAtencion.objects.filter(atencion_id=id_atencion).order_by("-fecha_subida")
    data = [{
        "id_archivo": a.id_archivo,
        "id_atencion": a.atencion_id,
        "nombre_archivo": a.nombre_archivo,
        "ruta_archivo": a.ruta_archivo,
        "tipo_archivo": a.tipo_archivo,
        "peso_bytes": a.peso_bytes,
        "subido_por": a.subido_por_id,
        "fecha_subida": a.fecha_subida.strftime("%Y-%m-%d %H:%M")
    } for a in qs]
    return ok({"rows": data})

@login_required
def archivo_atencion_formulario(request):
    return render(request, "archivo_atencion/form.html", {
        "id_atencion": request.GET.get("id_atencion")
    })

@login_required
@csrf_exempt
def archivo_atencion_guardar(request):
    if (err := require("POST", request)): return err
    d = request.POST
    campos = ["id_atencion","nombre_archivo","ruta_archivo","tipo_archivo","peso_bytes","subido_por"]
    vals = [d.get(k) or None for k in campos]
    try:
        with connection.cursor() as cur:
            cur.execute("""INSERT INTO archivo_atencion
                           (id_atencion,nombre_archivo,ruta_archivo,tipo_archivo,peso_bytes,subido_por,fecha_subida)
                           VALUES (%s,%s,%s,%s,%s,%s,NOW())""", vals)
    except Exception as e:
        return bad(f"No se pudo guardar: {e}")
    return ok(message="Guardado")

@login_required
@csrf_exempt
def archivo_atencion_eliminar(request):
    if (err := require("POST", request)): return err
    _id = request.POST.get("id")
    try:
        with connection.cursor() as cur:
            cur.execute("DELETE FROM archivo_atencion WHERE id_archivo=%s", [_id])
    except Exception as e:
        return bad(f"No se pudo eliminar: {e}")
    return ok(message="Eliminado")
